#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RDWArecon.py
# Author             : Podalirius (@podalirius_)
# Date created       : 5 Feb 2022

import argparse
import urllib.parse
import requests
import urllib3
from bs4 import BeautifulSoup
import hashlib


def banner():
    print(r"""
        ____  ____ _       _____                             
       / __ \/ __ \ |     / /   |  ________  _________  ____ 
      / /_/ / / / / | /| / / /| | / ___/ _ \/ ___/ __ \/ __ \
     / _, _/ /_/ /| |/ |/ / ___ |/ /  /  __/ /__/ /_/ / / / /
    /_/ |_/_____/ |__/|__/_/  |_/_/   \___/\___/\____/_/ /_/ 
                                                             
    """)

def parseArgs():
    parser = argparse.ArgumentParser(description="Description message")
    parser.add_argument("-u", "--url", default=None, required=True, help="Target RDWeb url")
    parser.add_argument("-v", "--verbose", default=False, action="store_true", help="Verbose mode. (default: False)")
    parser.add_argument("-k", "--insecure", dest="verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    parser.add_argument("-L", "--location", dest="redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    parser.add_argument("--no-colors", dest="nocolors", action="store_true", default=False, required=False, help="Disable colored output (default: False)")
    return parser.parse_args()


def detect_version(base_url, allow_redirects=False, verify=True, verbose=False, nocolors=False):
    known_hashes = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty WS_h_c.png file",
        "9d7338e8b8bb104ae416f02eb6d586dda8bf37a5b71869e7d1c766e6b626d19e": "Blank WS_h_c.png file",
        "5a8a77dc7ffd463647987c0de6df2c870f42819ec03bbd02a3ea9601e2ed8a4b": "Windows Server 2008 R2",
        "ae66321b4a47868903c38cbfb3a7b426a7523943a6c3f9978f380b36aa79ee82": "Windows Server 2012",
        "4560591682d433c7fa190c6bf40827110e219929932dc6dc049697529c8a98bc": "Windows Server 2012 R2",
        "3d9b56811a5126a6d3b78a692c2278d588d495ee215173f752ce4cbf8102921c": "Windows Server 2012 R2",
        "3dbbeff5a0def7e0ba8ea383e5059eaa6acc37f7f8857218d44274fc029cfc4b": "Windows Server 2016",
        "fb1505aadeab42d82100c4d23d421f421c858feae98332c55a4b9595f4cea541": "Windows Server 2016",
        "2da4eb15fda2b7c80a94b9b2c5a3e104e2a9a2d9e9b3a222f5526c748fadf792": "Windows Server 2019",
        "256a6445e032875e611457374f08acb0565796c950eb9c254495d559600c0367": "Windows Server 2022"
    }
    image_link = base_url + '/RDWeb/Pages/images/WS_h_c.png'
    if verbose:
        print("[debug] [+] Detecting remote windows server version if possible")
        print("[debug]    [>] Requesting %s" % image_link)
    try:
        r = requests.get(image_link, allow_redirects=allow_redirects, verify=verify, timeout=10)
        if r.status_code == 200:
            if 'Content-Type' in r.headers:
                if r.headers['Content-Type'] == "image/png":
                    h = hashlib.sha256(r.content).hexdigest()
                    if h in known_hashes.keys():
                        if verbose:
                            print("[debug]    [+] Found 'WS_h_c.png' with sha256 hash '%s'" % h)
                            print("[debug]    [+] Remote server: %s" % known_hashes[h])
                        return known_hashes[h]
                    else:
                        if verbose:
                            print("[debug]    [!] Unknown 'WS_h_c.png' sha256 hash '%s' " % h)
                        return None
        else:
            if verbose:
                print("[debug]    [!] Unexpected HTTP response code %d" % r.status_code)
            return None
    except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.ReadTimeoutError, requests.exceptions.ConnectionError) as e:
        if verbose:
            if nocolors:
                print("[debug]    [error] %s" % e)
            else:
                print("[debug]    [\x1b[91merror\x1b[0m] \x1b[91m%s\x1b[0m" % e)
        else:
            if nocolors:
                print("[error] %s" % e)
            else:
                print("[\x1b[91merror\x1b[0m] \x1b[91m%s\x1b[0m" % e)
    return None


if __name__ == '__main__':
    banner()
    options = parseArgs()

    if not options.url.startswith("http://") and not options.url.startswith("https://"):
        options.url = "https://" + options.url
    options.url = options.url.rstrip('/')

    if not options.verify:
        # Disable warings of insecure connection for invalid certificates
        requests.packages.urllib3.disable_warnings()
        # Allow use of deprecated and weak cipher methods
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        try:
            requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        except AttributeError:
            pass

    # Detecting remote windows server version if possible
    remote_version = detect_version(options.url, allow_redirects=options.redirect, verify=options.verify, verbose=options.verbose)
    if remote_version is not None:
        if options.nocolors:
            print("[+] Remote server is running: %s" % remote_version)
        else:
            print("[+] Remote server is running: \x1b[95m%s\x1b[0m" % remote_version)

    langs = ["de-DE", "en-GB", "en-US", "es-ES", "fr-FR", "it-IT", "ja-JP", "mk-MK", "nl-NL", "pt-BR", "ru-RU", "tr-TR"]
    rdweb_data = {"WorkspaceFriendlyName": "", "WorkSpaceID": "", "RDPCertificates": "", "RedirectorName": "", "EventLogUploadAddress": ""}
    for lang in langs:
        url = "%s/RDWeb/Pages/%s/login.aspx" % (options.url, lang)

        if options.verbose:
            print("[debug] Trying %s" % url)
        try:
            r = requests.get(url, allow_redirects=options.redirect, verify=options.verify, timeout=10)
            if r.status_code == 200:
                print("[>] Found information on %s" % url)

                # HTTP headers
                print("  [>] Parsing interesting HTTP headers if any")
                for hname in ["Server", "X-FEServer", "X-Powered-By"]:
                    if hname in r.headers.keys():
                        if options.nocolors:
                            print("    | %s: %s" % (hname, r.headers[hname]))
                        else:
                            print("    | \x1b[94m%s\x1b[0m: \x1b[95m%s\x1b[0m" % (hname, r.headers[hname]))

                # Form data
                soup = BeautifulSoup(r.content, "lxml")
                form = soup.find('form', attrs={"id": "FrmLogin"})
                if form is not None:
                    print("  [>] Parsing login form data")
                    for _input in form.findAll('input'):
                        if "name" in _input.attrs.keys() and "value" in _input.attrs.keys():
                            if _input["name"] in rdweb_data.keys():
                                if _input['name'] == "WorkspaceFriendlyName":
                                    rdweb_data[_input["name"]] = urllib.parse.unquote(_input["value"])
                                else:
                                    rdweb_data[_input["name"]] = _input["value"]
                                if options.nocolors:
                                    print("    | %s: %s" % (_input["name"], rdweb_data[_input["name"]]))
                                else:
                                    print("    | \x1b[94m%s\x1b[0m: \x1b[95m%s\x1b[0m" % (_input["name"], rdweb_data[_input["name"]]))

                break
            else:
                if options.verbose:
                    print("[debug] Got unexpected HTTP response %d" % r.status_code)
        except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.ReadTimeoutError, requests.exceptions.ConnectionError) as e:
            if options.nocolors:
                print("[error] %s" % e)
            else:
                print("[\x1b[91merror\x1b[0m] \x1b[91m%s\x1b[0m" % e)
