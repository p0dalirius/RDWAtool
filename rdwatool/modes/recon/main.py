#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : main.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023

from concurrent.futures import ThreadPoolExecutor
import os
from rdwatool.modes.recon.ReconReporter import ReconReporter
from rdwatool.modes.recon.recon import recon_worker, recon_monitor_thread
import sys
import threading


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
                tp.submit(recon_worker, target_url, options, reporter, config, monitor_data)

        if options.export_xlsx is not None:
            reporter.export_xlsx(options.export_xlsx)

        if options.export_json is not None:
            reporter.export_json(options.export_json)

        if options.export_sqlite is not None:
            reporter.export_sqlite(options.export_sqlite)
    else:
        print("[!] No targets loaded.")

    print("[+] All done!")