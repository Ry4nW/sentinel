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
        assert mock_visit.call_count == 2

    def test_worker_skips_already_visited_url(self, crawler):
        crawler.visited_urls.add('http://example.com/a')
        crawler.queue.put('http://example.com/a')
        crawler.queue.put(None)
        with patch.object(crawler, 'visit_url') as mock_visit:
            crawler.worker()
        mock_visit.assert_not_called()


class TestScanQueryParams:
    def test_fuzzes_existing_query_params(self, crawler):
        with patch.object(crawler, 'test_vulnerabilities') as mock_test:
            crawler.scan_query_params('http://example.com/search?id=1&Submit=Submit')
        mock_test.assert_called_once()
        form_details, url = mock_test.call_args[0]
        assert form_details['method'] == 'get'
        assert form_details['action'] == 'http://example.com/search'
        names = [i['name'] for i in form_details['inputs']]
        assert 'id' in names and 'Submit' in names

    def test_skips_urls_without_query_string(self, crawler):
        with patch.object(crawler, 'test_vulnerabilities') as mock_test:
            crawler.scan_query_params('http://example.com/about')
        mock_test.assert_not_called()


class TestAuthAndThrottling:
    def test_cookie_is_attached_to_session(self):
        c = WebCrawler(BASE_URL, cookie='PHPSESSID=abc123; security=low')
        assert c.session.headers['Cookie'] == 'PHPSESSID=abc123; security=low'

    def test_throttle_sleeps_when_delay_set(self):
        c = WebCrawler(BASE_URL, delay=0.5)
        with patch('scanner.time.sleep') as mock_sleep:
            c._throttle()
        mock_sleep.assert_called_once_with(0.5)

    def test_throttle_does_nothing_by_default(self, crawler):
        with patch('scanner.time.sleep') as mock_sleep:
            crawler._throttle()
        mock_sleep.assert_not_called()


class TestVulnerabilityDetection:
    @patch('scanner.WebCrawler.send_request')
    def test_sql_injection_detected_on_error_pattern(self, mock_send, crawler):
        mock_resp = MagicMock()
        mock_resp.text = "You have an error in your SQL syntax"
        mock_send.return_value = mock_resp
        form = {'action': '/search', 'method': 'get', 'inputs': [{'type': 'text', 'name': 'q'}]}
        with patch('scanner.logging') as mock_log:
            crawler.test_sql_injection(form, BASE_URL)
            assert mock_log.info.called

    @patch('scanner.WebCrawler.send_request')
    def test_xss_detected_when_payload_reflected(self, mock_send, crawler):
        payload = "<script>alert('XSS')</script>"
        mock_resp = MagicMock()
        mock_resp.text = f'<html>{payload}</html>'
        mock_send.return_value = mock_resp
        form = {'action': '/', 'method': 'get', 'inputs': [{'type': 'text', 'name': 'q'}]}
        with patch('scanner.logging') as mock_log:
            crawler.test_xss(form, BASE_URL)
            assert mock_log.info.called

    @patch('requests.Session.get')
    def test_clickjacking_detected_without_header(self, mock_get, crawler):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_get.return_value = mock_resp
        with patch('scanner.logging') as mock_log:
            crawler.test_clickjacking(BASE_URL)
            assert mock_log.info.called

    @patch('requests.Session.get')
    def test_clickjacking_not_flagged_with_header(self, mock_get, crawler):
        mock_resp = MagicMock()
        mock_resp.headers = {'X-Frame-Options': 'DENY'}
        mock_get.return_value = mock_resp
        with patch('scanner.logging') as mock_log:
            crawler.test_clickjacking(BASE_URL)
            mock_log.info.assert_not_called()


class TestBlindSqlInjection:
    @patch('scanner.WebCrawler.send_request')
    def test_flags_boolean_based_blind_sqli(self, mock_send, crawler):
        baseline = MagicMock(text='5 results')
        true_resp = MagicMock(text='5 results')
        false_resp = MagicMock(text='0 results')
        mock_send.side_effect = [baseline, true_resp, false_resp]
        form = {'action': '/', 'method': 'get', 'inputs': [{'type': 'text', 'name': 'id'}]}
        with patch('scanner.logging'):
            crawler.test_blind_sql_injection(form, BASE_URL)
        assert any(f['type'] == 'Blind SQL Injection' for f in crawler.findings)

    @patch('scanner.WebCrawler.send_request')
    def test_does_not_flag_when_responses_identical(self, mock_send, crawler):
        same = MagicMock(text='same page')
        mock_send.side_effect = [same, same, same]
        form = {'action': '/', 'method': 'get', 'inputs': [{'type': 'text', 'name': 'id'}]}
        with patch('scanner.logging'):
            crawler.test_blind_sql_injection(form, BASE_URL)
        assert crawler.findings == []


class TestVulnerabilityDispatch:
    def test_runs_every_check_and_clickjacking(self, crawler):
        form = {'action': '/', 'method': 'get', 'inputs': []}
        check_names = [
            'test_sql_injection', 'test_blind_sql_injection', 'test_xss',
            'test_command_injection', 'test_file_inclusion', 'test_directory_traversal',
            'test_html_injection', 'test_csrf', 'test_rfi', 'test_ldap_injection',
            'test_xxe', 'test_ssrf', 'test_unvalidated_redirects', 'test_clickjacking',
        ]
        patchers = [patch.object(crawler, name) for name in check_names]
        mocks = [p.start() for p in patchers]
        try:
            crawler.test_vulnerabilities(form, BASE_URL)
        finally:
            for p in patchers:
                p.stop()
        for name, mock in zip(check_names, mocks):
            assert mock.called, f'{name} was not called'


class TestSendRequest:
    @patch('requests.Session.get')
    def test_handles_form_with_no_action(self, mock_get, crawler):
        mock_get.return_value = MagicMock(text='')
        form = {'action': None, 'method': 'get', 'inputs': [{'type': 'text', 'name': 'q'}]}
        crawler.send_request(form, BASE_URL, 'payload')
        called_url = mock_get.call_args[0][0]
        assert called_url == BASE_URL

    @patch('requests.Session.get')
    def test_skips_inputs_with_no_name(self, mock_get, crawler):
        mock_get.return_value = MagicMock(text='')
        form = {
            'action': '/search', 'method': 'get',
            'inputs': [{'type': 'text', 'name': 'q'}, {'type': 'submit', 'name': None}],
        }
        crawler.send_request(form, BASE_URL, 'payload')
        sent_params = mock_get.call_args[1]['params']
        assert None not in sent_params

    @patch('requests.Session.get', side_effect=requests.exceptions.ConnectionError('refused'))
    def test_returns_empty_response_on_connection_error(self, mock_get, crawler):
        form = {'action': '/search', 'method': 'get', 'inputs': [{'type': 'text', 'name': 'q'}]}
        response = crawler.send_request(form, BASE_URL, 'payload')
        assert response.text == ''
