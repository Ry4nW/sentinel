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
