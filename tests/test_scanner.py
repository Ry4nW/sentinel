import pytest
import requests
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
        soup = make_soup('<a href="/about">about</a>')
        crawler.extract_links(soup, BASE_URL)
        assert 'http://example.com/about' in crawler.urls_to_visit

    def test_strips_fragment_from_links(self, crawler):
        soup = make_soup('<a href="/page#section">jump</a>')
        crawler.extract_links(soup, BASE_URL)
        assert 'http://example.com/page' in crawler.urls_to_visit
        assert 'http://example.com/page#section' not in crawler.urls_to_visit

    def test_skips_non_http_schemes(self, crawler):
        soup = make_soup(
            '<a href="mailto:someone@example.com">mail</a>'
            '<a href="javascript:void(0)">js</a>'
        )
        crawler.extract_links(soup, BASE_URL)
        assert crawler.urls_to_visit == [BASE_URL]

    def test_does_not_queue_duplicate_links(self, crawler):
        soup = make_soup('<a href="/dup">a</a><a href="/dup">b</a>')
        crawler.extract_links(soup, BASE_URL)
        assert crawler.urls_to_visit.count('http://example.com/dup') == 1


class TestWorker:
    def test_worker_drains_queue_without_crashing(self, crawler):
        crawler.urls_to_visit = ['http://example.com/a', 'http://example.com/b']
        with patch.object(crawler, 'visit_url') as mock_visit:
            crawler.worker()
        assert mock_visit.call_count == 2
        assert crawler.urls_to_visit == []


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

    @patch('requests.get')
    def test_clickjacking_detected_without_header(self, mock_get, crawler):
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_get.return_value = mock_resp
        with patch('scanner.logging') as mock_log:
            crawler.test_clickjacking(BASE_URL)
            assert mock_log.info.called

    @patch('requests.get')
    def test_clickjacking_not_flagged_with_header(self, mock_get, crawler):
        mock_resp = MagicMock()
        mock_resp.headers = {'X-Frame-Options': 'DENY'}
        mock_get.return_value = mock_resp
        with patch('scanner.logging') as mock_log:
            crawler.test_clickjacking(BASE_URL)
            mock_log.info.assert_not_called()


class TestSendRequest:
    @patch('requests.get')
    def test_handles_form_with_no_action(self, mock_get, crawler):
        mock_get.return_value = MagicMock(text='')
        form = {'action': None, 'method': 'get', 'inputs': [{'type': 'text', 'name': 'q'}]}
        crawler.send_request(form, BASE_URL, 'payload')
        called_url = mock_get.call_args[0][0]
        assert called_url == BASE_URL

    @patch('requests.get')
    def test_skips_inputs_with_no_name(self, mock_get, crawler):
        mock_get.return_value = MagicMock(text='')
        form = {
            'action': '/search', 'method': 'get',
            'inputs': [{'type': 'text', 'name': 'q'}, {'type': 'submit', 'name': None}],
        }
        crawler.send_request(form, BASE_URL, 'payload')
        sent_params = mock_get.call_args[1]['params']
        assert None not in sent_params

    @patch('requests.get', side_effect=requests.exceptions.ConnectionError('refused'))
    def test_returns_empty_response_on_connection_error(self, mock_get, crawler):
        form = {'action': '/search', 'method': 'get', 'inputs': [{'type': 'text', 'name': 'q'}]}
        response = crawler.send_request(form, BASE_URL, 'payload')
        assert response.text == ''
