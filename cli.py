import argparse
import json
import os

import config
from report import write_html_report
from scanner import WebCrawler

SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']


def parse_args():
    parser = argparse.ArgumentParser(
        prog='sentinel',
        description='Sentinel — web vulnerability scanner',
    )
    parser.add_argument('--url', required=True, help='Target base URL to scan')
    parser.add_argument(
        '--threads', type=int, default=config.THREADS,
        help=f'Crawler thread count (default: {config.THREADS})',
    )
    parser.add_argument(
        '--output', default=config.OUTPUT_DIR,
        help=f'Directory to write reports to (default: {config.OUTPUT_DIR})',
    )
    parser.add_argument(
        '--timeout', type=int, default=config.TIMEOUT,
        help=f'Per-request timeout in seconds (default: {config.TIMEOUT})',
    )
    parser.add_argument(
        '--delay', type=float, default=config.DELAY,
        help=f'Delay between requests in seconds, per thread (default: {config.DELAY})',
    )
    parser.add_argument(
        '--cookie', default=None,
        help='Raw Cookie header sent with every request, e.g. "PHPSESSID=abc; security=low". '
             'Grab it from your browser after logging in, for scanning pages behind auth.',
    )
    parser.add_argument(
        '--max-depth', type=int, default=None,
        help='Max link-following depth from the start URL (default: unlimited)',
    )
    parser.add_argument(
        '--max-pages', type=int, default=None,
        help='Stop crawling after visiting this many pages (default: unlimited)',
    )
    parser.add_argument(
        '--fail-on', choices=['none'] + SEVERITY_ORDER, default='none',
        help='Exit non-zero if a finding at or above this severity turns up, for CI (default: none)',
    )
    return parser.parse_args()


def should_fail(findings, fail_on):
    if fail_on == 'none':
        return False
    threshold = SEVERITY_ORDER.index(fail_on)
    return any(
        f['severity'] in SEVERITY_ORDER and SEVERITY_ORDER.index(f['severity']) <= threshold
        for f in findings
    )


def main():
    args = parse_args()

    print(f'[*] Target : {args.url}')
    print(f'[*] Threads: {args.threads}')
    print(f'[*] Output : {args.output}')
    print()

    crawler = WebCrawler(
        args.url,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        cookie=args.cookie,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
    )
    crawler.crawl()

    os.makedirs(args.output, exist_ok=True)
    report = {
        'target': args.url,
        'visited': list(crawler.visited_urls),
        'findings': crawler.findings,
    }

    report_path = os.path.join(args.output, 'scan_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    html_path = os.path.join(args.output, 'scan_report.html')
    write_html_report(report, html_path)

    print(f'\n[+] Visited {len(crawler.visited_urls)} URL(s)')
    print(f'[+] Found   {len(crawler.findings)} finding(s)')
    print(f'[+] Report  {report_path}')
    print(f'[+] Report  {html_path}')

    if should_fail(crawler.findings, args.fail_on):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
