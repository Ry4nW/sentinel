# sentinel

small web vuln scanner i built to poke at DVWA and learn how this stuff works under the hood. crawls a site, finds forms, throws a pile of payloads at them (sqli, xss, cmd injection, lfi/rfi, xxe, ssrf, ldap, csrf, open redirects) and checks the response for anything that looks broken. also flags missing clickjacking headers.

**only point this at stuff you own or have permission to test.** it's not smart, it's not stealthy, it just fires requests as fast as it can with a bunch of threads.

## setup

```
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## running it

spin up DVWA if you want a real target to test against:

```
docker run --rm -it -p 4280:80 vulnerables/web-dvwa
```

then

```
python cli.py --url http://localhost:4280/vulnerabilities/sqli/
```

flags:
- `--threads` how many crawler threads (default 10)
- `--timeout` per request timeout in seconds (default 10)
- `--output` where the json report goes (default `reports/`)

report lands in `reports/scan_report.json`, looks like `reports/sample_report.json`. list of urls visited plus a list of findings with type/url/payload/severity.

## how detection works

it's all string matching, nothing fancy. sql injection = payload triggers a known db error string in the response. xss/html injection/csrf = payload gets reflected back verbatim. command injection = "PING" shows up (linux ping output). lfi/xxe = "root:" shows up (assumes /etc/passwd read). so yeah, heuristic and prone to false positives/negatives depending on the app. good enough for DVWA-style targets, wouldn't trust it against something with actual output sanitization quirks without checking findings by hand.

## bugs i ran into building/fixing this

- **worker() could crash on startup.** the loop checked `while self.urls_to_visit` outside the lock, then popped inside the lock. if two threads both saw a non-empty queue but only one item was left, the second thread would skip the pop and then reference `url` from a previous loop iteration, or blow up with `UnboundLocalError` if it was the very first iteration. fixed by doing the empty check and the pop as one atomic step under the lock.

- **crash on forms with no action attribute.** `<form>` with no `action=""` gives `None`, and `urljoin(url, None)` throws. real sites do this all the time (form just posts back to the current page). now it falls back to `''` so it resolves to the current url.

- **inputs with no name attribute.** buttons/inputs without a `name` were getting shoved into the payload dict as a `None` key, which is just noise at best and breaks the request at worst. now those get skipped since they wouldn't be submitted by a real browser anyway.

- **one flaky request could permanently kill a worker thread.** `send_request` didn't catch `requests.RequestException`, so a timeout or connection refused mid-scan would raise, kill that thread (python threads just die silently on an unhandled exception, they don't crash the whole process), and you'd quietly lose one of your scan threads for the rest of the run. now it catches the exception, logs it, and hands back an empty stand-in response so the vuln checks just see no match and move on.

- **duplicate crawling from url fragments.** links like `/page#section` and `/page#other` were treated as different pages even though the fragment never even gets sent to the server. same page, scanned twice (or ten times on a page with a lot of anchor links). now fragments get stripped before the url goes in the queue. also added a check so the same url doesn't get queued twice from two different pages linking to it, and non-http(s) links (`mailto:`, `javascript:`, etc) get skipped instead of silently failing the domain check.

- **test_lfi and test_file_inclusion were the exact same check.** copy-paste leftover, same payloads, same detection string, same finding type. was quietly doubling requests and writing duplicate findings into the report for local file inclusion. removed the duplicate.

## known limitations, didn't fix these

- crawler queue is a plain list with `pop(0)`, fine for DVWA-sized targets, would get slow on a big site.
- worker threads exit as soon as they see an empty queue even if another thread is about to add more urls to it. mostly a non-issue in practice since forms/links usually get discovered early, but on a weird crawl order you could in theory stop a bit short of a full crawl.
- command injection check only looks for "PING" (linux ping output), won't catch it on a windows backend.
- no rate limiting, so don't run this against anything that isn't yours or expecting a burst of traffic.

## tests

```
pytest tests/ -q
```
