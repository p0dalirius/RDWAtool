#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023

from concurrent.futures import ThreadPoolExecutor
import argparse
import os
from rdwatool.modes.recon.recon import recon_worker, recon_monitor_thread
from rdwatool.Config import Config
from rdwatool.modes.recon.ReconReporter import ReconReporter
import requests
import sys
import threading


VERSION = "2.0"


def banner():
    print(r"""           ____  ____ _       _____   __              __
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
    mode_recon.add_argument("--no-colors", default=False, action="store_true", help="Disable colored output. (default: False)")
    mode_recon.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")
    mode_recon.add_argument("-T", "--threads", default=250, type=int, help="Number of threads (default: 250)")
    group_configuration = mode_recon.add_argument_group("Advanced configuration")
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help="Proxy IP.")
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help="Proxy port")
    group_configuration.add_argument("-rt", "--request-timeout", default=5, type=int, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("-k", "--insecure", dest="request_verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    group_configuration.add_argument("-L", "--location", dest="request_redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    group_export = mode_recon.add_argument_group("Export results")
    group_export.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    group_export.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    group_export.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    mode_spray = argparse.ArgumentParser(add_help=False)
    mode_spray.add_argument("-tu", "--target-url", dest="target_urls", default=None, type=str, help="Target URL of the RDWA login page.")
    mode_spray.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    mode_spray.add_argument("--no-colors", default=False, action="store_true", help="Disable colored output. (default: False)")
    mode_spray.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")
    mode_spray.add_argument("-T", "--threads", default=8, type=int, help="Number of threads (default: 8)")
    group_configuration = mode_spray.add_argument_group("Advanced configuration")
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help="Proxy IP.")
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help="Proxy port")
    group_configuration.add_argument("-rt", "--request-timeout", default=5, type=int, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("-k", "--insecure", dest="request_verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    group_configuration.add_argument("-L", "--location", dest="request_redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    group_export = mode_spray.add_argument_group("Export results")
    group_export.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    group_export.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    group_export.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    mode_brute = argparse.ArgumentParser(add_help=False)
    mode_brute.add_argument("-tu", "--target-url", dest="target_urls", default=None, type=str, help="Target URL of the RDWA login page.")
    mode_brute.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    mode_brute.add_argument("--no-colors", default=False, action="store_true", help="Disable colored output. (default: False)")
    mode_brute.add_argument("--debug", default=False, action="store_true", help="Debug mode, for huge verbosity. (default: False)")
    mode_brute.add_argument("-T", "--threads", default=8, type=int, help="Number of threads (default: 8)")
    group_configuration = mode_brute.add_argument_group("Advanced configuration")
    group_configuration.add_argument("-PI", "--proxy-ip", default=None, type=str, help="Proxy IP.")
    group_configuration.add_argument("-PP", "--proxy-port", default=None, type=int, help="Proxy port")
    group_configuration.add_argument("-rt", "--request-timeout", default=5, type=int, help="Set the timeout of HTTP requests.")
    group_configuration.add_argument("-k", "--insecure", dest="request_verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    group_configuration.add_argument("-L", "--location", dest="request_redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    group_export = mode_brute.add_argument_group("Export results")
    group_export.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    group_export.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    group_export.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

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

    config = Config()
    config.set_debug_mode(options.debug)
    config.set_no_colors(options.no_colors)
    config.set_request_no_check_certificate(options.request_verify)
    # config.set_request_available_schemes(only_http=options.only_http, only_https=options.only_https)
    config.set_request_timeout(options.request_timeout)
    config.set_request_proxies(options.proxy_ip, options.proxy_port)

    # Disable SSL/TLS verification if needed
    if options.request_verify:
        # Disable warnings of insecure connection for invalid certificates
        requests.packages.urllib3.disable_warnings()
        # Allow use of deprecated and weak cipher methods
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        try:
            requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        except AttributeError:
            pass

    if options.mode == "recon":
        targets = []
        # Loading targets from a single --target option
        if len(options.target_urls) != 0:
            if options.debug:
                print("[debug] Loading targets from --target options")
            for target in options.target_urls:
                # Format target url if not formatted properly
                if not target.startswith("http://") and not target.startswith("https://"):
                    targets.append("https://" + target)
                    targets.append("http://" + target)
                else:
                    targets.append(target)

        # Loading targets line by line from a targets file
        if options.targets_file is not None:
            if os.path.exists(options.targets_file):
                if options.debug:
                    print("[debug] Loading targets line by line from targets file '%s'" % options.targets_file)
                f = open(options.targets_file, "r")
                for line in f.readlines():
                    target = line.strip()
                    # Format target url if not formatted properly
                    if not target.startswith("http://") and not target.startswith("https://"):
                        targets.append("https://" + target)
                        targets.append("http://" + target)
                    else:
                        targets.append(target)
                f.close()
            else:
                print("[!] Could not open targets file '%s'" % options.targets_file)
        targets = sorted(list(set(targets)))

        reporter = ScanReporter(config=config)

        print("[+] Searching for RDWA login pages on specified targets ...")
        monitor_data = {"actions_performed": 0, "total": len(targets), "lock": threading.Lock()}
        with ThreadPoolExecutor(max_workers=min(options.threads, 1 + monitor_data["total"])) as tp:
            tp.submit(scan_monitor_thread, reporter, config, monitor_data)
            for target_url in targets:
                tp.submit(scan_worker, target_url, options, reporter, config, monitor_data)

        if options.export_xlsx is not None:
            reporter.export_xlsx(options.export_xlsx)

        if options.export_json is not None:
            reporter.export_json(options.export_json)

        if options.export_sqlite is not None:
            reporter.export_sqlite(options.export_sqlite)

        print("[+] All done!")

    elif options.mode == "spray":
        pass

    elif options.mode == "brute":
        pass

if __name__ == '__main__':
    main()