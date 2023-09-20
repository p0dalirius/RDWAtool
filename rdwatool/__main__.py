#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023


import argparse
import os
import sys
from rdwatool.scan import scan_target_worker


VERSION = "2.0"


def banner():
    print(r"""                ____  ____ _       _____   __              __
               / __ \/ __ \ |     / /   | / /_____  ____  / /
              / /_/ / / / / | /| / / /| |/ __/ __ \/ __ \/ /    @podalirius_
             / _, _/ /_/ /| |/ |/ / ___ / /_/ /_/ / /_/ / /  
            /_/ |_/_____/ |__/|__/_/  |_\__/\____/\____/_/      v%s
    """ % VERSION)


def parseArgs():
    parser = argparse.ArgumentParser(description="Extract information about the server and the domain from external RDWeb pages.")
    parser.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")

    mode_recon = argparse.ArgumentParser(add_help=False)
    group_targets_source = mode_recon.add_argument_group("Targets")
    group_targets_source.add_argument("-tf", "--targets-file", dest="targets_file", default=None, type=str, help="Path to file containing a line by line list of targets.")
    group_targets_source.add_argument("-tu", "--target-url", dest="target_urls", default=[], type=str, action="append", help="Target URL of the RDWA login page.")
    mode_recon.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    mode_recon.add_argument("-k", "--insecure", dest="verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    mode_recon.add_argument("-L", "--location", dest="redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    mode_recon.add_argument("--no-colors", dest="nocolors", action="store_true", default=False, required=False, help="Disable colored output (default: False)")
    mode_recon.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")

    mode_spray = argparse.ArgumentParser(add_help=False)
    mode_spray.add_argument("-tu", "--target-url", dest="target_urls", default=None, type=str, help="Target URL of the RDWA login page.")
    mode_spray.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    mode_spray.add_argument("-k", "--insecure", dest="verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    mode_spray.add_argument("-L", "--location", dest="redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    mode_spray.add_argument("--no-colors", dest="nocolors", action="store_true", default=False, required=False, help="Disable colored output (default: False)")
    mode_spray.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")

    mode_brute = argparse.ArgumentParser(add_help=False)
    mode_brute.add_argument("-tu", "--target-url", dest="target_urls", default=None, type=str, help="Target URL of the RDWA login page.")
    mode_brute.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    mode_brute.add_argument("-k", "--insecure", dest="verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    mode_brute.add_argument("-L", "--location", dest="redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    mode_brute.add_argument("--no-colors", dest="nocolors", action="store_true", default=False, required=False, help="Disable colored output (default: False)")
    mode_brute.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")

    # Adding the subparsers to the base parser
    subparsers = parser.add_subparsers(help="Mode", dest="mode", required=True)
    mode_recon_parser = subparsers.add_parser("recon", parents=[mode_recon], help="Search for Remote Desktop Web Access login pages on the target(s).")
    mode_spray_parser = subparsers.add_parser("spray", parents=[mode_spray], help="Spray a password on a list of users through the RDWA login page.")
    mode_brute_parser = subparsers.add_parser("brute", parents=[mode_brute], help="Bruteforces passwords on one or more users through the RDWA login page.")
    args = parser.parse_args()

    if (args.targets_file is None) and (len(args.target_urls) == 0):
        parser.print_help()
        print("\n[!] No targets specified.")
        sys.exit(0)

    return args


def main():
    banner()
    options = parseArgs()

    if options.mode == "recon":
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
            print(scan_target_worker(url, options))

    elif options.mode == "spray":
        pass

    elif options.mode == "brute":
        pass

if __name__ == '__main__':
    main()