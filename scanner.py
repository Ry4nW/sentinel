import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import threading
import logging
import re

import config
from payloads import (
    SQL_PAYLOADS, SQL_ERROR_PATTERNS,
    XSS_PAYLOADS, CMD_PAYLOADS, LFI_PAYLOADS,
    HTML_PAYLOADS, CSRF_PAYLOADS, RFI_PAYLOADS,
    LDAP_PAYLOADS, XXE_PAYLOADS, SSRF_PAYLOADS,
    REDIRECT_PAYLOADS,
)

logging.basicConfig(
    filename=config.LOG_FILE,
    level=getattr(logging, config.LOG_LEVEL),
    format='%(asctime)s - %(levelname)s - %(message)s',
)


class _EmptyResponse:
    """Stand-in for a requests.Response when a request fails, so a single
    dropped connection doesn't take down the worker thread that hit it."""
    text = ''
    headers = {}


class WebCrawler:
    def __init__(self, base_url, threads=None, timeout=None):
        self.base_url = base_url
        self.visited_urls = set()
        self.urls_to_visit = [base_url]
        self.threads = threads or config.THREADS
        self.timeout = timeout or config.TIMEOUT
        self.headers = {'User-Agent': config.USER_AGENT}
        self.findings = []
        self.lock = threading.Lock()

    def crawl(self):
        threads = []
        for _ in range(self.threads):
            thread = threading.Thread(target=self.worker)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()

    def worker(self):
        while True:
            with self.lock:
                if not self.urls_to_visit:
                    break
                url = self.urls_to_visit.pop(0)
            if url not in self.visited_urls:
                self.visit_url(url)
