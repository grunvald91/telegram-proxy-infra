#!/usr/bin/env python3
"""Temporary test-only TCP acceptor for ClientHello transport measurements.

NOT a TLS proxy. Reads up to 16K per connection without logging payload.
"""
import argparse
import ipaddress
import os
import socket
import time


def serve(bind_ip, client_ip, port, ready_file, duration=120):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((bind_ip, port))  # no SO_REUSEPORT / takeover
        server.listen(8)
        server.settimeout(1)
        fd = os.open(ready_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        started = time.monotonic()
        while time.monotonic() - started < duration:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            with conn:
                if addr[0] != client_ip:
                    continue
                conn.settimeout(2)
                received = 0
                while received < 16384 and time.monotonic() - started < duration:
                    try:
                        data = conn.recv(min(4096, 16384 - received))
                    except socket.timeout:
                        break
                    if not data:
                        break
                    received += len(data)
                print(f"canary_connection_bytes={received}", flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bind", default="188.120.254.223")
    p.add_argument("--client", required=True)
    p.add_argument("--port", type=int, default=18443)
    p.add_argument("--ready-file", required=True)
    args = p.parse_args()
    for ip in (args.bind, args.client):
        if not ipaddress.ip_address(ip).is_global:
            p.error("Public IPv4 only")
    if args.port != 18443:
        p.error("Only port 18443 allowed")
    from mnebydns_nfq_failopen import arm_parent_death_signal
    arm_parent_death_signal()
    try:
        serve(args.bind, args.client, args.port, args.ready_file)
    finally:
        try:
            os.unlink(args.ready_file)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    main()
