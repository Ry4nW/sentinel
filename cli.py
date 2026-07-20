import argparse
import json
import os

import config
from report import write_html_report
from scanner import WebCrawler

SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']
