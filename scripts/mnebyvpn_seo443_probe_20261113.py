#!/usr/bin/env python3
"""One-runner public HTTPS and control port probe. No server access."""
import socket
import ssl
import sys

stage = sys.argv[1]
assert stage in ("before", "during", "after")


def check(port):
    try:
        with socket.create_connection(("188.120.254.223", port), timeout=4) as conn:
            if port != 443:
                return "connected"
            with ssl.create_default_context().wrap_socket(
                    conn, server_hostname="mnebyvpn.site") as tls:
                tls.settimeout(4)
                tls.sendall(b"GET / HTTP/1.1\r\nHost: mnebyvpn.site\r\n"
                            b"Connection: close\r\n\r\n")
                line = tls.recv(150).split(b"\r\n", 1)[0]
                return "http200" if b" 200 " in line else "other_status"
    except Exception as exc:
        return type(exc).__name__


results = {p: check(p) for p in (80, 8443, 443)}
for port, status in results.items():
    print(stage.upper() + "_PORT" + str(port) + "=" + status, flush=True)

if stage == "before":
    assert results[80] == "connected" and results[8443] == "connected", \
        "Controls failed; canary is unsafe"
    assert results[443] != "http200", "HTTPS already works from this runner"
