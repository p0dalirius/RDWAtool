#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : scan.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023


import urllib.parse
import requests
import urllib3
import hashlib
from bs4 import BeautifulSoup
from rdwatool.network import is_port_open, is_http_accessible


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

    try:
        r = requests.get(image_link, allow_redirects=allow_redirects, verify=verify, timeout=10)
        if r.status_code == 200:
            if 'Content-Type' in r.headers:
                if r.headers['Content-Type'] == "image/png":
                    h = hashlib.sha256(r.content).hexdigest()
                    if h in known_hashes.keys():
                        return known_hashes[h]
                    else:
                        return None
        else:
            return None
    except (
        urllib3.exceptions.NewConnectionError,
        urllib3.exceptions.ConnectTimeoutError,
        urllib3.exceptions.ReadTimeoutError,
        requests.exceptions.ConnectionError
    ) as e:
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


def scan_target_worker(url, options):
    rdwa_login_page = {"found": False}
    # Format target url if not formatted properly
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    url = url.rstrip('/')
    rdwa_login_page["baseurl"] = url

    # Parsing target port
    port = 80
    target_data = urllib.parse.urlparse(url)
    if ":" in target_data.netloc:
        port = int(target_data.netloc.split(':', 1)[1])
    elif target_data.scheme == "https":
        port = 443
    elif target_data.scheme == "http":
        port = 80

    # Check if target port is open
    if not is_port_open(target=target_data.netloc, port=port, debug=options.verbose):
        if options.verbose:
            if options.nocolors:
                print("[error] TCP port is closed on %s://%s." % (target_data.scheme, target_data.netloc))
            else:
                print("[\x1b[91merror\x1b[0m] \x1b[91mTCP port is closed on %s://%s.\x1b[0m" % (target_data.scheme, target_data.netloc))
        return rdwa_login_page

    # Check if target HTTP protocol is responding
    if not is_http_accessible(target_url=url, verify=options.verify, debug=options.verbose):
        if options.verbose:
            if options.nocolors:
                print("[error] No HTTP protocol on %s://%s." % (target_data.scheme, target_data.netloc))
            else:
                print("[\x1b[91merror\x1b[0m] \x1b[91mNo HTTP protocol on %s://%s.\x1b[0m" % (target_data.scheme, target_data.netloc))
        return rdwa_login_page

    # Disable SSL/TLS verification if needed
    if not options.verify:
        # Disable warnings of insecure connection for invalid certificates
        requests.packages.urllib3.disable_warnings()
        # Allow use of deprecated and weak cipher methods
        requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        try:
            requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        except AttributeError:
            pass

    # Detecting remote windows server version if possible
    remote_version = detect_version(
        base_url=url,
        allow_redirects=options.redirect,
        verify=options.verify,
        verbose=options.verbose
    )
    if remote_version is not None:
        rdwa_login_page["found"] = True
        rdwa_login_page["version"] = remote_version

    # iterate on possible languages
    langs = [
        "de-DE", "en-GB", "en-US", "es-ES", "fr-FR", "it-IT",
        "ja-JP", "mk-MK", "nl-NL", "pt-BR", "ru-RU", "tr-TR"
    ]
    rdwa_login_page["form_data"] = {
        "WorkspaceFriendlyName": "",
        "WorkSpaceID": "",
        "RDPCertificates": "",
        "RedirectorName": "",
        "EventLogUploadAddress": ""
    }
    for lang in langs:
        login_url = "%s/RDWeb/Pages/%s/login.aspx" % (url, lang)

        try:
            r = requests.get(
                url=login_url,
                allow_redirects=options.redirect,
                verify=options.verify,
                timeout=10
            )
            if r.status_code == 200:
                rdwa_login_page["login_url"] = login_url

                # HTTP headers
                rdwa_login_page["http_headers"] = {}
                for header_name in ["Server", "X-FEServer", "X-Powered-By"]:
                    if header_name in r.headers.keys():
                        rdwa_login_page["http_headers"][header_name] = r.headers[header_name]

                # Form data
                soup = BeautifulSoup(markup=r.content, features="lxml-xml")
                form = soup.find('form', attrs={"id": "FrmLogin"})
                if form is not None:
                    for form_hidden_input_field in form.findAll('input'):
                        if "name" in form_hidden_input_field.attrs.keys() and "value" in form_hidden_input_field.attrs.keys():
                            if form_hidden_input_field["name"] in rdwa_login_page["form_data"].keys():
                                if form_hidden_input_field['name'] == "WorkspaceFriendlyName":
                                    rdwa_login_page["form_data"][form_hidden_input_field["name"]] = urllib.parse.unquote(form_hidden_input_field["value"])
                                else:
                                    rdwa_login_page["form_data"][form_hidden_input_field["name"]] = form_hidden_input_field["value"]

                # We found the page, not trying other languages
                break

        except (
                urllib3.exceptions.NewConnectionError,
                urllib3.exceptions.ConnectTimeoutError,
                urllib3.exceptions.ReadTimeoutError,
                requests.exceptions.ConnectionError
        ) as err:
            if options.debug:
                print("[error] Target '%s' ==> %s" % (login_url, err))

    return rdwa_login_page

