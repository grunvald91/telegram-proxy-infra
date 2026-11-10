#!/usr/bin/env python3
"""Non-destructive TLS ClientHello SNI differential probe for owned VPS.
Two records differ by *exactly* the replacement SNI bytes, preserving
ClientHello bytes, length, fingerprint, packetization settings and destination.
Output contains no packet bytes, client identifiers, or secrets.
"""
import argparse
import socket
import ssl
import time

PAIRS = (
    ("wwwthreads", "www.threads.com", "www.example.com"),
    ("graphthreads", "graph.threads.com", "graph.example.com"),
    ("wwwthreadsnet", "www.threads.net", "www.example.net"),
)

def make_hello(host, compact):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if compact:
        ctx.set_ecdh_curve("prime256v1")
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    conn = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        conn.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    marker = host.encode("ascii")
    assert hello.count(marker) == 1, (host, len(hello))
    assert 150 < len(hello) < 4000
    return hello

def fixtures():
    for mode in ("compact", "standard"):
        for label, target, control in PAIRS:
            assert len(target) == len(control)
            a = make_hello(target, mode == "compact")
            b = a.replace(target.encode(), control.encode())
            assert len(a) == len(b), "different lengths"
            assert a.count(target.encode()) == 1
            assert b.count(control.encode()) == 1
            assert sum(x != y for x, y in zip(a, b)) == sum(
                x != y for x, y in zip(target.encode(), control.encode())
            )
            assert len(a) < 4000
            yield label, mode, a, b

def check():
    rows = list(fixtures())
    assert len(rows) == 6
    for label, mode, a, b in rows:
        print("fixture_" + label + "_" + mode + "_size=" + str(len(a)), flush=True)
        print("fixture_" + label + "_" + mode + "_byte_identical_except_sni=true", flush=True)
    print("equal_sni_tls_fixture_selftest=PASS", flush=True)

def send(host, port, repeat):
    check()
    for label, mode, a, b in fixtures():
        for trial in range(repeat):
            # Alternate sequence to limit time-order bias
            cases = [("meta", a), ("control", b)] if trial % 2 == 0 else [("control", b), ("meta", a)]
            for name, data in cases:
                connected = False
                sent = 0
                local_port = -1
                error = "none"
                try:
                    with socket.create_connection((host, port), timeout=3) as sock:
                        connected = True
                        sock.settimeout(3)
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        local_port = sock.getsockname()[1]
                        sock.sendall(data)
                        sent = len(data)
                        try:
                            sock.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        time.sleep(0.13)
                except OSError as exc:
                    error = type(exc).__name__ + "_" + str(exc.errno)
                ident = label + "_" + mode + "_" + str(trial) + "_" + name
                print("trial=" + ident + " local_port=" + str(local_port)
                      + " tcp=" + str(connected).lower()
                      + " sent=" + str(sent) + " error=" + error, flush=True)
                time.sleep(0.11)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=("self-test", "send"))
    p.add_argument("--host", default="89.125.90.101")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--repeat", type=int, default=3)
    args = p.parse_args()
    if args.command == "self-test":
        check()
    else:
        assert 1 <= args.repeat <= 5
        send(args.host, args.port, args.repeat)
