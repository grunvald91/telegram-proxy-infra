#!/usr/bin/env python3
"""Read-only gates shared by the baseline and post-cutover checks. No keys or PINs."""
import json
import re
import socket
import ssl
import subprocess
import sys


def targets(role):
    if role == 'RU':
        return [('10.66.77.1', 443, 'www.youtube.com'),
                ('10.66.77.1', 443, 'rr1---sn-gxuo03g-ig3s.googlevideo.com'),
                # Public DNS listens on the public address, not the tunnel IP.
                ('89.125.90.101', 853, 'dns.mnebyvpn.site')]
    if role == 'DE':
        return [('10.66.77.2', 8856, 'aaaaaaaaaaaa.dns.mnebyvpn.site')]
    raise ValueError('Unknown role')


def tls_probe(ip, port, hostname):
    with socket.create_connection((ip, port), timeout=5) as sock:
        sock.settimeout(5)
        with ssl.create_default_context().wrap_socket(sock, server_hostname=hostname) as tls:
            if not tls.getpeercert():
                raise ValueError('Missing verified certificate')


def check(role, probe=tls_probe):
    failed = False
    for ip, port, hostname in targets(role):
        try:
            probe(ip, port, hostname)
            result = {'role': role, 'port': port, 'tls_verified': True}
        except Exception as exc:
            result = {'role': role, 'port': port, 'error': type(exc).__name__}
            failed = True
        print('AWG_SERVICE_GATE=' + json.dumps(result), flush=True)
    return not failed


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('RU', 'DE'):
        sys.exit(2)
    sys.exit(0 if check(sys.argv[1]) else 1)
