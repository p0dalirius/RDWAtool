#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : network.py
# Author             : Podalirius (@podalirius_)
# Date created       : 20 Sep 2023


import requests
import socket


def is_port_open(target, port, config) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        # Non-existant domains cause a lot of errors, added error handling
        try:
            return s.connect_ex((target, port)) == 0
        except Exception as err:
            config.debug("is_port_open('%s', %d) ==> %s" % (target, port, err))
            return False


def is_http_accessible(target_url, config) -> bool:
    try:
        r = requests.get(
            url=target_url,
            allow_redirects=config.request_redirect,
            timeout=config.request_timeout,
            proxies=config.request_proxies,
            verify=(not (config.request_no_check_certificate))
        )
        return True
    except Exception as err:
        config.debug("is_http_accessible('%s') ==> %s" % (target_url, err))
        return False