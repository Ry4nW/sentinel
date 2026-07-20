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
