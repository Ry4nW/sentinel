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
        while self.urls_to_visit:
            with self.lock:
                if self.urls_to_visit:
                    url = self.urls_to_visit.pop(0)
            if url and url not in self.visited_urls:
                self.visit_url(url)

    def visit_url(self, url):
        self.visited_urls.add(url)
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            if response.status_code == 200:
                response.encoding = response.apparent_encoding
                soup = BeautifulSoup(response.text, 'html.parser')
                self.extract_links(soup, url)
                self.scan_forms(soup, url)
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {e}")

    def extract_links(self, soup, current_url):
        for link in soup.find_all('a', href=True):
            href = link['href']
            if not href.startswith('http'):
                href = urljoin(current_url, href)
            parsed_href = urlparse(href)
            if parsed_href.netloc == urlparse(self.base_url).netloc:
                with self.lock:
                    if href not in self.visited_urls:
                        self.urls_to_visit.append(href)

    def scan_forms(self, soup, url):
        for form in soup.find_all('form'):
            form_details = self.get_form_details(form)
            self.test_vulnerabilities(form_details, url)

    def get_form_details(self, form):
        details = {}
        try:
            action = form.attrs.get('action')
            method = form.attrs.get('method', 'get').lower()
            inputs = []
            for input_tag in form.find_all('input'):
                input_type = input_tag.attrs.get('type', 'text')
                input_name = input_tag.attrs.get('name')
                inputs.append({'type': input_type, 'name': input_name})
            details['action'] = action
            details['method'] = method
            details['inputs'] = inputs
        except Exception as e:
            logging.error(f"Error getting form details: {e}")
        return details

