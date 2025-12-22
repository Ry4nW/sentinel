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
