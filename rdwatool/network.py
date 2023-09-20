#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : network.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023


import requests
import socket


def is_port_open(target, port, debug=False) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        # Non-existant domains cause a lot of errors, added error handling
        try:
            return s.connect_ex((target, port)) == 0
        except Exception as err:
            if debug:
                print("[debug] is_port_open('%s', %d) ==> %s" % (target, port, err))
            return False


def is_http_accessible(target_url, verify=False, debug=False) -> bool:
    try:
        r = requests.get(url=target_url, verify=verify)
        return True
    except Exception as err:
        if debug:
            print("[debug] is_http_accessible('%s') ==> %s" % (target_url, err))
        return False