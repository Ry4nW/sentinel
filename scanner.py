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
