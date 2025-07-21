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
        soup = make_soup('<a href="/about">about</a>')
        crawler.extract_links(soup, BASE_URL)
        assert 'http://example.com/about' in crawler.urls_to_visit


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
