import queue as queue_module

import pytest
import requests
from unittest.mock import MagicMock, patch
from bs4 import BeautifulSoup

from scanner import WebCrawler


BASE_URL = 'http://example.com'


def drain(q):
    """Pull every item currently sitting in a queue.Queue into a list."""
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue_module.Empty:
            break
    return items


@pytest.fixture
def crawler():
    c = WebCrawler(BASE_URL)
    drain(c.queue)  # tests only care about links queued during the test itself
    return c


def make_soup(html):
    return BeautifulSoup(html, 'html.parser')


class TestGetFormDetails:
    def test_parses_action_and_method(self, crawler):
        soup = make_soup('<form action="/search" method="post"><input type="text" name="q"></form>')
        form = soup.find('form')
        details = crawler.get_form_details(form)
        assert details['action'] == '/search'
        assert details['method'] == 'post'

    def test_defaults_method_to_get(self, crawler):
        soup = make_soup('<form action="/go"><input type="text" name="q"></form>')
        form = soup.find('form')
        details = crawler.get_form_details(form)
        assert details['method'] == 'get'

    def test_collects_input_fields(self, crawler):
        soup = make_soup(
            '<form action="/" method="get">'
            '<input type="text" name="user">'
            '<input type="password" name="pass">'
            '</form>'
        )
        form = soup.find('form')
        details = crawler.get_form_details(form)
        names = [i['name'] for i in details['inputs']]
        assert 'user' in names
        assert 'pass' in names


class TestExtractLinks:
    def test_stays_on_same_domain(self, crawler):
        soup = make_soup(
            '<a href="/page1">local</a>'
            '<a href="http://evil.com/x">external</a>'
        )
        crawler.extract_links(soup, BASE_URL)
        queued = drain(crawler.queue)
        assert any('example.com' in u for u in queued)
        assert not any('evil.com' in u for u in queued)

    def test_resolves_relative_links(self, crawler):
        soup = make_soup('<a href="/about">about</a>')
        crawler.extract_links(soup, BASE_URL)
        assert 'http://example.com/about' in drain(crawler.queue)

    def test_strips_fragment_from_links(self, crawler):
        soup = make_soup('<a href="/page#section">jump</a>')
        crawler.extract_links(soup, BASE_URL)
        queued = drain(crawler.queue)
        assert 'http://example.com/page' in queued
        assert 'http://example.com/page#section' not in queued

    def test_skips_non_http_schemes(self, crawler):
        soup = make_soup(
            '<a href="mailto:someone@example.com">mail</a>'
            '<a href="javascript:void(0)">js</a>'
        )
        crawler.extract_links(soup, BASE_URL)
        assert drain(crawler.queue) == []

    def test_does_not_queue_duplicate_links(self, crawler):
        soup = make_soup('<a href="/dup">a</a><a href="/dup">b</a>')
        crawler.extract_links(soup, BASE_URL)
        assert drain(crawler.queue).count('http://example.com/dup') == 1

    def test_respects_max_depth(self):
        c = WebCrawler(BASE_URL, max_depth=1)
        drain(c.queue)
        c.url_depth[BASE_URL] = 1  # pretend we're already at the depth limit
        soup = make_soup('<a href="/too-deep">nope</a>')
        c.extract_links(soup, BASE_URL)
        assert drain(c.queue) == []

    def test_respects_max_pages(self):
        c = WebCrawler(BASE_URL, max_pages=1)
        drain(c.queue)  # the seed url alone already counts toward max_pages
        soup = make_soup('<a href="/one">a</a><a href="/two">b</a>')
        c.extract_links(soup, BASE_URL)
        assert drain(c.queue) == []


class TestWorker:
    def test_worker_drains_queue_without_crashing(self, crawler):
        crawler.queue.put('http://example.com/a')
        crawler.queue.put('http://example.com/b')
        crawler.queue.put(None)
        with patch.object(crawler, 'visit_url') as mock_visit:
            crawler.worker()
