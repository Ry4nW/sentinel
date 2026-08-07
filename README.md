# Sentinel

A concurrent web vulnerability scanner. It crawls a target, finds forms and URL parameters, and tests them for SQL injection (including blind), XSS, command injection, LFI/RFI, XXE, SSRF, LDAP injection, CSRF, and open redirects. It also flags missing clickjacking headers.

Only scan targets you own or have permission to test.

## Setup

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

