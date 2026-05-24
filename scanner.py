import logging
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

import config
from payloads import (
    SQL_PAYLOADS, SQL_ERROR_PATTERNS,
    BLIND_SQL_TRUE_PAYLOAD, BLIND_SQL_FALSE_PAYLOAD,
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
    def __init__(self, base_url, threads=None, timeout=None, delay=None,
                 cookie=None, max_depth=None, max_pages=None):
        self.base_url = base_url
        self.threads = threads or config.THREADS
        self.timeout = timeout or config.TIMEOUT
        self.delay = config.DELAY if delay is None else delay
        self.max_depth = max_depth
        self.max_pages = max_pages

        # crawl queue: a real queue instead of a hand-rolled list+lock, so a
        # worker that finds it empty just blocks on get() instead of exiting
        # early while other workers are still about to feed it more urls
        self.visited_urls = set()
        self.queued_urls = {base_url}
        self.url_depth = {base_url: 0}
        self.queue = queue.Queue()
        self.queue.put(base_url)

        self.headers = {'User-Agent': config.USER_AGENT}
        if cookie:
            self.headers['Cookie'] = cookie
        self.session = requests.Session()
        self.session.headers.update(self.headers)

        self.findings = []
        self.lock = threading.Lock()
        # each form's dozen-odd vulnerability checks run concurrently here,
        # not just the page-level crawl
        self.vuln_pool = ThreadPoolExecutor(max_workers=self.threads)

    def crawl(self):
        workers = [threading.Thread(target=self.worker) for _ in range(self.threads)]
        for w in workers:
            w.start()
        self.queue.join()
        for _ in workers:
            self.queue.put(None)  # sentinel: tells each worker to stop
        for w in workers:
            w.join()
        self.vuln_pool.shutdown(wait=True)

    def worker(self):
        while True:
            url = self.queue.get()
            try:
                if url is None:
                    return
                with self.lock:
                    if url in self.visited_urls:
                        continue
                    self.visited_urls.add(url)
                self.visit_url(url)
            finally:
                self.queue.task_done()

    def _throttle(self):
        if self.delay:
            time.sleep(self.delay)

    def visit_url(self, url):
        self._throttle()
        try:
            response = self.session.get(url, timeout=self.timeout)
            self.scan_query_params(url)
            if response.status_code == 200:
                response.encoding = response.apparent_encoding
                soup = BeautifulSoup(response.text, 'html.parser')
                self.extract_links(soup, url)
                self.scan_forms(soup, url)
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {e}")

    def extract_links(self, soup, current_url):
        current_depth = self.url_depth.get(current_url, 0)
        if self.max_depth is not None and current_depth >= self.max_depth:
            return
        for link in soup.find_all('a', href=True):
