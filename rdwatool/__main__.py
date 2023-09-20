#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023


import argparse
import os
import socket
import sys
import urllib.parse
import requests
import urllib3
from bs4 import BeautifulSoup
import hashlib


VERSION = "1.3"


def banner():
    print(r"""        ____  ____ _       _____                             
       / __ \/ __ \ |     / /   |  ________  _________  ____ 
      / /_/ / / / / | /| / / /| | / ___/ _ \/ ___/ __ \/ __ \   @podalirius_
     / _, _/ /_/ /| |/ |/ / ___ |/ /  /  __/ /__/ /_/ / / / /   
    /_/ |_/_____/ |__/|__/_/  |_/_/   \___/\___/\____/_/ /_/    v%s

    """ % VERSION)


def parseArgs():
    parser = argparse.ArgumentParser(description="Extract information about the server and the domain from external RDWeb pages.")

    parser.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")

    group_targets_source = parser.add_argument_group("Targets")
    group_targets_source.add_argument("-tf", "--targets-file", dest="targets_file", default=None, type=str, help="Path to file containing a line by line list of targets.")
    group_targets_source.add_argument("-tu", "--target-url", dest="target_urls", default=[], type=str, action='append', help="Target URL to the tomcat manager.")

    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("-k", "--insecure", dest="verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    parser.add_argument("-L", "--location", dest="redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    parser.add_argument("--no-colors", dest="nocolors", action="store_true", default=False, required=False, help="Disable colored output (default: False)")



    args = parser.parse_args()

    if (args.targets_file is None) and (len(args.target_urls) == 0):
        parser.print_help()
        print("\n[!] No targets specified.")
        sys.exit(0)

    return args


def main():
    banner()
    options = parseArgs()

    targets = []
    # Loading targets from a single --target option
    if len(options.target_urls) != 0:
        if options.debug:
            print("[debug] Loading targets from --target options")
        for target in options.target_urls:
            targets.append(target)

    # Loading targets line by line from a targets file
    if options.targets_file is not None:
        if os.path.exists(options.targets_file):
            if options.debug:
                print("[debug] Loading targets line by line from targets file '%s'" % options.targets_file)
            f = open(options.targets_file, "r")
            for line in f.readlines():
                targets.append(line.strip())
            f.close()
        else:
            print("[!] Could not open targets file '%s'" % options.targets_file)

    # Scanning targets
    for url in targets:
        scan_target(url, options)


if __name__ == '__main__':
    main()