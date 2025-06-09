import argparse
import json
import os

import config
from scanner import WebCrawler


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
        help=f'Directory to write JSON report (default: {config.OUTPUT_DIR})',
    )
    parser.add_argument(
        '--timeout', type=int, default=config.TIMEOUT,
        help=f'Per-request timeout in seconds (default: {config.TIMEOUT})',
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print(f'[*] Target : {args.url}')
    print(f'[*] Threads: {args.threads}')
