# Sentinel

A concurrent web vulnerability scanner. It crawls a target, finds forms and URL parameters, and tests them for SQL injection (including blind), XSS, command injection, LFI/RFI, XXE, SSRF, LDAP injection, CSRF, and open redirects. It also flags missing clickjacking headers.

Only scan targets you own or have permission to test.

## Setup

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```
docker run --rm -it -p 4280:80 vulnerables/web-dvwa
python cli.py --url http://localhost:4280/vulnerabilities/sqli/
```

Flags:
- `--threads` crawler thread count (default 10)
- `--timeout` request timeout in seconds (default 10)
- `--delay` delay between requests, per thread (default 0)
- `--cookie` cookie header, for scanning behind a login
- `--max-depth`, `--max-pages` limit crawl scope
- `--fail-on` exit non-zero on findings at or above a severity, for CI
- `--output` report directory (default `reports/`)

Each run writes `scan_report.json` and `scan_report.html`.

## How it works

Crawling and vulnerability testing both run concurrently: one thread pool crawls pages, another runs each form's checks in parallel rather than sequentially. Detection is mostly pattern matching, error strings, reflected payloads, or response differences for blind SQLi, so treat findings as leads to verify, not confirmed results.

## Known limitations

- Command injection detection only recognizes Linux `ping` output.
- No `robots.txt` or exclude-pattern support.
- `--max-pages` is a soft limit, not a hard stop mid-crawl.

## Tests

```
pytest tests/ -q
```
