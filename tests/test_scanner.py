import pytest
from unittest.mock import MagicMock, patch
from bs4 import BeautifulSoup

from scanner import WebCrawler


BASE_URL = 'http://example.com'


@pytest.fixture
def crawler():
    return WebCrawler(BASE_URL)


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
        assert any('example.com' in u for u in crawler.urls_to_visit)
        assert not any('evil.com' in u for u in crawler.urls_to_visit)

    def test_resolves_relative_links(self, crawler):
