import pytest
from unittest.mock import MagicMock, patch
from bs4 import BeautifulSoup

from scanner import WebCrawler


BASE_URL = 'http://example.com'


@pytest.fixture
def crawler():
    return WebCrawler(BASE_URL)


def make_soup(html):
