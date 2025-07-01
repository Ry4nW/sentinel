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
