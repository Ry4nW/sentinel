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
            href = link['href']
            if not href.startswith('http'):
                href = urljoin(current_url, href)
            parsed_href = urlparse(href)
            if parsed_href.scheme not in ('http', 'https'):
                continue
            href = parsed_href._replace(fragment='').geturl()
            if parsed_href.netloc != urlparse(self.base_url).netloc:
                continue
            with self.lock:
                if href in self.visited_urls or href in self.queued_urls:
                    continue
                if self.max_pages is not None and len(self.visited_urls) + len(self.queued_urls) >= self.max_pages:
                    continue
                self.queued_urls.add(href)
                self.url_depth[href] = current_depth + 1
            self.queue.put(href)

    def scan_query_params(self, url):
        """Fuzz params already sitting in a crawled url's query string
        (?id=1&Submit=Submit), not just <form> submissions."""
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return
        form_details = {
            'action': parsed._replace(query='', fragment='').geturl(),
            'method': 'get',
            'inputs': [{'type': 'text', 'name': name} for name in params],
        }
        self.test_vulnerabilities(form_details, url)

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

    def send_request(self, form_details, url, payload):
        data = {}
        for input in form_details['inputs']:
            if not input['name']:
                continue
            if input['type'] in ('text', 'search'):
                data[input['name']] = payload
            else:
                data[input['name']] = 'test'
        target_url = urljoin(url, form_details['action'] or '')
        self._throttle()
        try:
            if form_details['method'] == 'post':
                return self.session.post(
                    target_url, data=data, timeout=self.timeout,
                )
            return self.session.get(
                target_url, params=data, timeout=self.timeout,
            )
        except requests.RequestException as e:
            logging.error(f"Request failed for {target_url}: {e}")
            return _EmptyResponse()

    def _record(self, vuln_type, url, payload, severity='high'):
        msg = f"{vuln_type} vulnerability found at {url}"
        logging.info(msg)
        print(msg)
        with self.lock:
            self.findings.append({'type': vuln_type, 'url': url, 'payload': payload, 'severity': severity})

    def test_vulnerabilities(self, form_details, url):
        # every check below is independent of the others, so they run
        # concurrently against the pool instead of one after another
        checks = [
            self.test_sql_injection,
            self.test_blind_sql_injection,
            self.test_xss,
            self.test_command_injection,
            self.test_file_inclusion,
            self.test_directory_traversal,
            self.test_html_injection,
            self.test_csrf,
            self.test_rfi,
            self.test_ldap_injection,
            self.test_xxe,
            self.test_ssrf,
            self.test_unvalidated_redirects,
        ]
        futures = [self.vuln_pool.submit(check, form_details, url) for check in checks]
        for future in futures:
            future.result()
        self.test_clickjacking(url)

    def test_sql_injection(self, form_details, url):
        for payload in SQL_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self._record('SQL Injection', url, payload, 'critical')
                    return

    def test_blind_sql_injection(self, form_details, url):
        # boolean-based blind sqli: an always-true condition should read like
        # a normal response, an always-false one should read differently.
        # catches injections that don't throw a db error or reflect anything.
        baseline = self.send_request(form_details, url, 'test')
        true_resp = self.send_request(form_details, url, BLIND_SQL_TRUE_PAYLOAD)
        false_resp = self.send_request(form_details, url, BLIND_SQL_FALSE_PAYLOAD)
        if true_resp.text == baseline.text and true_resp.text != false_resp.text:
            self._record('Blind SQL Injection', url, BLIND_SQL_TRUE_PAYLOAD, 'critical')

    def test_xss(self, form_details, url):
        for payload in XSS_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if payload in response.text:
                self._record('XSS', url, payload, 'high')
                return

    def test_command_injection(self, form_details, url):
        for payload in CMD_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if "PING" in response.text:
                self._record('Command Injection', url, payload, 'critical')
                return

    def test_file_inclusion(self, form_details, url):
        for payload in LFI_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if "root:" in response.text:
                self._record('Local File Inclusion', url, payload, 'critical')
                return

    def test_directory_traversal(self, form_details, url):
        for payload in LFI_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if "root:" in response.text:
                self._record('Directory Traversal', url, payload, 'high')
                return

    def test_html_injection(self, form_details, url):
        for payload in HTML_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if payload in response.text:
                self._record('HTML Injection', url, payload, 'medium')
                return

    def test_csrf(self, form_details, url):
        for payload in CSRF_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if payload in response.text:
                self._record('CSRF', url, payload, 'medium')
                return

    def test_rfi(self, form_details, url):
        for payload in RFI_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if "malicious" in response.text:
                self._record('Remote File Inclusion', url, payload, 'critical')
                return

    def test_ldap_injection(self, form_details, url):
        for payload in LDAP_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if "ldap" in response.text:
                self._record('LDAP Injection', url, payload, 'high')
                return

    def test_xxe(self, form_details, url):
        for payload in XXE_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if "root:" in response.text:
                self._record('XXE', url, payload, 'critical')
                return

    def test_ssrf(self, form_details, url):
        for payload in SSRF_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if "localhost" in response.text:
                self._record('SSRF', url, payload, 'high')
                return

    def test_unvalidated_redirects(self, form_details, url):
        for payload in REDIRECT_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if payload in response.text:
                self._record('Unvalidated Redirect', url, payload, 'medium')
                return

    def test_clickjacking(self, url):
        self._throttle()
        try:
            response = self.session.get(url, timeout=self.timeout)
            if 'X-Frame-Options' not in response.headers:
                self._record('Clickjacking', url, None, 'medium')
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {e}")


if __name__ == '__main__':
    base_url = 'http://localhost:4280/vulnerabilities/sqli/'
    crawler = WebCrawler(base_url)
    crawler.crawl()
    print(f"Visited URLs: {crawler.visited_urls}")

'''
docker run --rm -it -p 4280:80 vulnerables/web-dvwa
https://github.com/digininja/DVWA
'''
