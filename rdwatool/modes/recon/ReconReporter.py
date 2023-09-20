#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ReconReporter.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2022


import json
import os.path
import sqlite3
import traceback
import xlsxwriter


class ReconReporter(object):
    """
    Documentation for class ReconReporter
    """

    data = {}

    def __init__(self, config):
        super(ReconReporter, self).__init__()
        self.config = config
        self._new_results = []

    def report_result(self, result):
        finding = result.copy()
        self.data[finding["baseurl"]] = finding
        self._new_results.append(finding)

    def print_new_results(self):
        try:
            for finding in self._new_results:
                if finding["os_version"] is not None:
                    if self.config.no_colors:
                        prompt = "[>] %s (domain:%s) (machine:%s)"
                    else:
                        prompt = "[>] \x1b[1;4;34m%s\x1b[0m (machine:\x1b[94m%s\x1b[0m) (domain:\x1b[95m%s\x1b[0m) (friendlyname:\x1b[93m%s\x1b[0m) (os:\x1b[96m%s\x1b[0m)"
                    print(prompt % (finding["login_url"], finding["machine"], finding["domain"], finding["form_data"]["WorkspaceFriendlyName"], finding["os_version"]))
                else:
                    if self.config.no_colors:
                        prompt = "[>] %s (domain:%s) (machine:%s)"
                    else:
                        prompt = "[>] \x1b[1;4;34m%s\x1b[0m (machine:\x1b[94m%s\x1b[0m) (domain:\x1b[95m%s\x1b[0m) (friendlyname:\x1b[93m%s\x1b[0m)"
                    print(prompt % (finding["login_url"], finding["machine"], finding["domain"], finding["form_data"]["WorkspaceFriendlyName"]))

                self._new_results.remove(finding)
        except Exception as e:
            if self.config.debug_mode:
                print("[Error in %s] %s" % (__name__, e))
                traceback.print_exc()

    def export_xlsx(self, path_to_file):
        path_to_file = os.path.abspath(path_to_file)
        basepath = os.path.dirname(path_to_file)
        filename = os.path.basename(path_to_file)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename

        workbook = xlsxwriter.Workbook(path_to_file)
        worksheet = workbook.add_worksheet()

        header_format = workbook.add_format({'bold': 1})
        header_fields = ["Computer IP", "Port", "Apache tomcat version", "Manager accessible", "Default credentials found", "CVEs on this version"]
        for k in range(len(header_fields)):
            worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
        worksheet.set_row(0, 20, header_format)
        worksheet.write_row(0, 0, header_fields)

        row_id = 1
        for computername in self.data.keys():
            computer = self.data[computername]
            for port in computer.keys():
                cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(computer[port]["tomcat_version"], colors=False, reverse=True)
                cve_str = ', '.join([cve["cve"]["id"] for cve in cve_list])

                data = [
                    computer[port]["computer_ip"],
                    computer[port]["computer_port"],
                    computer[port]["tomcat_version"],
                    str(computer[port]["manager_accessible"]).upper(),
                    computer[port]["default_credentials"],
                    cve_str
                ]
                worksheet.write_row(row_id, 0, data)
                row_id += 1
        worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
        workbook.close()

    def export_json(self, path_to_file):
        path_to_file = os.path.abspath(path_to_file)
        basepath = os.path.dirname(path_to_file)
        filename = os.path.basename(path_to_file)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename
        f = open(path_to_file, 'w')
        f.write(json.dumps(self.data, indent=4))
        f.close()

    def export_sqlite(self, path_to_file):
        path_to_file = os.path.abspath(path_to_file)
        basepath = os.path.dirname(path_to_file)
        filename = os.path.basename(path_to_file)
        if basepath not in [".", ""]:
            if not os.path.exists(basepath):
                os.makedirs(basepath)
            path_to_file = basepath + os.path.sep + filename
        else:
            path_to_file = filename

        conn = sqlite3.connect(path_to_file)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS results(computer_ip VARCHAR(255), computer_port INTEGER, tomcat_version VARCHAR(255), manager_accessible VARCHAR(255), default_credentials VARCHAR(255), cves INTEGER);")
        for computername in self.data.keys():
            computer = self.data[computername]
            for port in computer.keys():
                cve_list = self.vulns_db.get_vulnerabilities_of_version_sorted_by_criticity(computer[port]["tomcat_version"], colors=False, reverse=True)
                cve_str = ', '.join([cve["cve"]["id"] for cve in cve_list])

                cursor.execute("INSERT INTO results VALUES (?, ?, ?, ?, ?, ?)", (
                        computer[port]["computer_ip"],
                        computer[port]["computer_port"],
                        computer[port]["tomcat_version"],
                        str(computer[port]["manager_accessible"]).upper(),
                        computer[port]["default_credentials"],
                        cve_str
                    )
                )
        conn.commit()
        conn.close()