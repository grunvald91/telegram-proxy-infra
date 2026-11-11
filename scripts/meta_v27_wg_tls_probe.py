#!/usr/bin/env python3
"""One-shot RU -> private WireGuard -> DE -> Meta TLS diagnostic.

No public listeners, production config edits, DNS changes, nft edits or VPN
route changes. A temporary DE Nginx stream listens on WG 10.66.77.1:15443.
RU uses standard Python TLS verification through the private path.
This is NOT a phone/ISP/TSPU test or client-SNI segmentation test.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time

WG_IP = "10.66.77.1"
WG_DEV = "tg-relay"
PORT = 15443
HOSTS = ("i.instagram.com", "iglite-z.instagram.com")


def run_server() -> None:
    import meta_v13_isolated_de as helper

    if os.geteuid() != 0:
        raise RuntimeError("DE isolated Nginx probe requires root")
    addr = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True,
                          text=True, timeout=7, check=True).stdout
    if not re.search(r"(?<![0-9])10[.]66[.]77[.]1/", addr):
        raise RuntimeError("DE WireGuard bind IP not present")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test:
        test.bind((WG_IP, PORT))
    renderer = helper.load_renderer()
    targets = {}
    for host in HOSTS:
        targets[host] = renderer.origin_ip(host)
        helper.verify_tls(targets[host], 443, host)

    with tempfile.TemporaryDirectory(prefix="mneby-v27-wg-") as directory:
        tmp = Path(directory)
        os.chmod(tmp, 0o700)
        conf = helper.isolated_nginx(tmp, PORT, targets)
        before = conf.read_text()
        marker = f"listen 127.0.0.1:{PORT};"
        if before.count(marker) != 1:
            raise RuntimeError("isolation bind rule ambiguous")
        conf.write_text(before.replace(marker, f"listen {WG_IP}:{PORT};"))
        conf.chmod(0o600)
        if not helper.checked_run(["nginx", "-t", "-c", str(conf)]):
            raise RuntimeError("isolated DE WG Nginx config invalid")
        proc = subprocess.Popen(
            ["nginx", "-c", str(conf), "-g",
             "daemon off; master_process off;"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, preexec_fn=helper.child_die_with_parent)
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError("isolated DE WG listener exited")
                try:
                    with socket.create_connection((WG_IP, PORT), timeout=0.25):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("DE WG listener did not bind")
            print("v27_de_origin_tls_verifications=2", flush=True)
            print("v27_de_listener_interface=wireguard_only", flush=True)
            print("v27_wg_tls_proxy=READY", flush=True)
            until = time.monotonic() + 38
            while time.monotonic() < until:
                if proc.poll() is not None:
                    raise RuntimeError("isolated DE WG Nginx exited")
                time.sleep(0.2)
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    print("v27_de_temporary_nginx_stopped=true", flush=True)
    print("v27_de_production_configs_untouched=true", flush=True)


def run_client() -> None:
    route = subprocess.run(["ip", "-j", "route", "get", WG_IP],
                           capture_output=True, text=True, timeout=7, check=True)
    routes = json.loads(route.stdout)
    if not routes or routes[0].get("dev") != WG_DEV:
        raise RuntimeError("RU route to DE is not via private WireGuard")
    print("v27_ru_route_via_tg_relay=PASS", flush=True)
    for host in HOSTS:
        raw = socket.create_connection((WG_IP, PORT), timeout=8)
        try:
            raw.settimeout(8)
            context = ssl.create_default_context()
            context.set_alpn_protocols(["http/1.1"])
            with context.wrap_socket(raw, server_hostname=host) as tls:
                if not tls.getpeercert():
                    raise RuntimeError("origin certificate absent for " + host)
                version = tls.version()
                tls.sendall(("GET / HTTP/1.1\r\nHost: " + host +
                             "\r\nConnection: close\r\nUser-Agent: MNEBY-test\r\n\r\n").encode("ascii"))
                response = tls.recv(1024)
                tag = host.replace(".", "_").replace("-", "_")
                print("v27_wg_" + tag + "_cert_valid=true", flush=True)
                print("v27_wg_" + tag + "_tls=" + str(version), flush=True)
                print("v27_wg_" + tag + "_http_bytes=" + str(len(response)), flush=True)
                if not response:
                    raise RuntimeError("no encrypted application response for " + host)
        finally:
            raw.close()
    print("v27_ru_wg_de_meta_tls_application=PASS", flush=True)
    print("v27_android_tspu_bypass=NOT_TESTED", flush=True)


def selftest() -> None:
    assert ipaddress.IPv4Address(WG_IP).is_private
    assert PORT > 1024
    assert len(HOSTS) == len(set(HOSTS)) == 2
    assert all(host.endswith(".instagram.com") for host in HOSTS)
    print("v27_scoped_wg_tls_probe_selftest=PASS")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: meta_v27_wg_tls_probe.py serve|client|selftest")
    command = sys.argv[1]
    if command == "serve":
        run_server()
    elif command == "client":
        run_client()
    elif command == "selftest":
        selftest()
    else:
        raise SystemExit("invalid mode")
