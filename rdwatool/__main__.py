#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : __main__.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023

import argparse
from rdwatool.modes.recon.main import mode_recon
from rdwatool.modes.recon.parser import generate_recon_parser_options
from rdwatool.modes.spray.main import mode_spray
from rdwatool.modes.spray.parser import generate_spray_parser_options
from rdwatool.modes.brute.main import mode_brute
from rdwatool.modes.brute.parser import generate_brute_parser_options
from rdwatool.Config import Config
import requests


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

    # Adding the subparsers to the base parser
    subparsers = parser.add_subparsers(help="Mode", dest="mode", required=True)
    mode_recon_parser = subparsers.add_parser("recon", parents=[generate_recon_parser_options()], help="Search for Remote Desktop Web Access login pages on the target(s).")
    mode_spray_parser = subparsers.add_parser("spray", parents=[generate_spray_parser_options()], help="Spray a password on a list of users through the RDWA login page.")
    mode_brute_parser = subparsers.add_parser("brute", parents=[generate_brute_parser_options()], help="Bruteforces passwords on one or more users through the RDWA login page.")
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
        mode_recon(options, config)

    elif options.mode == "spray":
        mode_spray(options, config)

    elif options.mode == "brute":
        mode_brute(options, config)

if __name__ == '__main__':
    main()