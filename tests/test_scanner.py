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
