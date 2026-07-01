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

    def send_request(self, form_details, url, payload):
        data = {}
        for input in form_details['inputs']:
            if input['type'] in ('text', 'search'):
                data[input['name']] = payload
            else:
                data[input['name']] = 'test'
        if form_details['method'] == 'post':
            return requests.post(
                urljoin(url, form_details['action']),
                data=data, headers=self.headers, timeout=self.timeout,
            )
        return requests.get(
            urljoin(url, form_details['action']),
            params=data, headers=self.headers, timeout=self.timeout,
        )

    def _record(self, vuln_type, url, payload, severity='high'):
        msg = f"{vuln_type} vulnerability found at {url}"
        logging.info(msg)
        print(msg)
        self.findings.append({'type': vuln_type, 'url': url, 'payload': payload, 'severity': severity})

    def test_vulnerabilities(self, form_details, url):
        self.test_sql_injection(form_details, url)
        self.test_xss(form_details, url)
        self.test_command_injection(form_details, url)
        self.test_file_inclusion(form_details, url)
        self.test_directory_traversal(form_details, url)
        self.test_html_injection(form_details, url)
        self.test_csrf(form_details, url)
        self.test_lfi(form_details, url)
        self.test_rfi(form_details, url)
        self.test_ldap_injection(form_details, url)
        self.test_xxe(form_details, url)
        self.test_ssrf(form_details, url)
        self.test_unvalidated_redirects(form_details, url)
        self.test_clickjacking(url)

    def test_sql_injection(self, form_details, url):
        for payload in SQL_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self._record('SQL Injection', url, payload, 'critical')
                    return

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

    def test_lfi(self, form_details, url):
        for payload in LFI_PAYLOADS:
            response = self.send_request(form_details, url, payload)
            if "root:" in response.text:
                self._record('Local File Inclusion', url, payload, 'critical')
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
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
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
