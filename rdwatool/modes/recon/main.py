#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : main.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023


from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from rdwatool.modes.recon.ReconReporter import ReconReporter
from rdwatool.network import is_port_open, is_http_accessible
import datetime
import hashlib
import os
import requests
import sys
import threading
import time
import traceback
import urllib3
import urllib.parse


def mode_recon(options, config):
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

    if len(targets) != 0:
        reporter = ReconReporter(config=config)
        print("[+] Searching for RDWA login pages on specified targets ...")
        monitor_data = {"actions_performed": 0, "total": len(targets), "lock": threading.Lock()}
        with ThreadPoolExecutor(max_workers=min(options.threads, 1 + monitor_data["total"])) as tp:
            tp.submit(recon_monitor_thread, reporter, config, monitor_data)
            for target_url in targets:
                tp.submit(recon_worker, target_url, config, reporter, monitor_data)

        if options.export_xlsx is not None:
            reporter.export_xlsx(options.export_xlsx)

        if options.export_json is not None:
            reporter.export_json(options.export_json)

        if options.export_sqlite is not None:
            reporter.export_sqlite(options.export_sqlite)
    else:
        print("[!] No targets loaded.")

    print("[+] All done!")


def detect_os_version(base_url, config):
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
        r = requests.get(
            url=image_link,
            allow_redirects=config.request_redirect,
            timeout=config.request_timeout,
            proxies=config.request_proxies,
            verify=(not (config.request_no_check_certificate))
        )
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


def recon_worker(url, config, reporter=None, monitor_data=None):
    rdwa_login_page = {"found": False, "baseurl": url}
    try:
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
        if is_port_open(target=target_data.netloc, port=port, config=config):
            if is_http_accessible(target_url=url, config=config):

                # Detecting remote windows server version if possible
                remote_version = detect_os_version(
                    base_url=url,
                    config=config
                )
                if remote_version is not None:
                    rdwa_login_page["found"] = True
                    rdwa_login_page["os_version"] = remote_version
                else:
                    rdwa_login_page["os_version"] = None

                # iterate on possible languages
                langs = ["de-DE", "en-GB", "en-US", "es-ES", "fr-FR", "it-IT", "ja-JP", "mk-MK", "nl-NL", "pt-BR", "ru-RU", "tr-TR"]
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
                            allow_redirects=config.request_redirect,
                            timeout=config.request_timeout,
                            proxies=config.request_proxies,
                            verify=(not (config.request_no_check_certificate))
                        )
                        if r.status_code == 200:
                            rdwa_login_page["machine"] = ""
                            rdwa_login_page["domain"] = ""
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

                            if rdwa_login_page["form_data"]["WorkSpaceID"].count('.') >= 2:
                                rdwa_login_page["machine"], rdwa_login_page["domain"] = rdwa_login_page["form_data"]["WorkSpaceID"].split('.', 1)
                                rdwa_login_page["machine"] = rdwa_login_page["machine"].upper()
                            elif rdwa_login_page["form_data"]["RedirectorName"].count('.') >= 2:
                                rdwa_login_page["machine"], rdwa_login_page["domain"] = rdwa_login_page["form_data"]["RedirectorName"].split('.', 1)
                                rdwa_login_page["machine"] = rdwa_login_page["machine"].upper()

                            if reporter is not None:
                                reporter.report_result(rdwa_login_page)

                            # We found the page, not trying other languages
                            break

                    except (urllib3.exceptions.NewConnectionError, urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.ReadTimeoutError, requests.exceptions.ConnectionError) as err:
                        config.debug("scan_worker targeting '%s' ==> %s" % (login_url, err))
    except Exception as err:
        config.debug("scan_worker('%s') ==> %s" % (url, err))
        traceback.print_exc()

    if monitor_data is not None:
        monitor_data["lock"].acquire()
        monitor_data["actions_performed"] = monitor_data["actions_performed"] + 1
        monitor_data["lock"].release()

    return rdwa_login_page


def recon_monitor_thread(reporter, config, monitor_data):
    time.sleep(1)
    last_check, monitoring = 0, True
    while monitoring:
        new_check = monitor_data["actions_performed"]
        rate = (new_check - last_check)
        if not config.debug_mode:
            print("\r", end="")
        reporter.print_new_results()
        print("[%s] Status (%d/%d) %5.2f %% | Rate %d tests/s        " % (
                datetime.datetime.now().strftime("%Y/%m/%d %Hh%Mm%Ss"),
                new_check, monitor_data["total"], (new_check/monitor_data["total"])*100,
                rate
            ),
            end=("" if not config.debug_mode else "\n")
        )
        last_check = new_check
        time.sleep(1)
        if rate == 0 and monitor_data["actions_performed"] == monitor_data["total"]:
            monitoring = False

    if len(reporter._new_results) != 0:
        reporter.print_new_results()

    print()