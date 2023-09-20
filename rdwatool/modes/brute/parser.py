#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : parser.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023

import argparse


def generate_brute_parser_options():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("-tu", "--target-url", dest="target_urls", default=None, type=str, help="Target URL of the RDWA login page.")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("--no-colors", default=False, action="store_true", help="Disable colored output. (default: False)")
    parser.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")
    parser.add_argument("-T", "--threads", default=8, type=int, help="Number of threads (default: 8)")

    group_configuration = parser.add_argument_group("Advanced configuration")
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help="Proxy IP.")
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help="Proxy port")
    group_configuration.add_argument("-rt", "--request-timeout", default=5, type=int, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("-k", "--insecure", dest="request_verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    group_configuration.add_argument("-L", "--location", dest="request_redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")

    group_export = parser.add_argument_group("Export results")
    group_export.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    group_export.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    group_export.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    return parser