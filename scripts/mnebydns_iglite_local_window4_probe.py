#!/usr/bin/env python3
"""Proof-of-mechanism: does SYN-ACK TCP Window=4 actually split Instagram SNI?

A local TLS ClientHello (SNI=iglite-z.instagram.com) traverses DE public-IP
loopback. A temporary nft rule changes SYN-ACK window ONLY on the host's 'lo'
interface, for DE->DE:443. No client traffic, CoreDNS or Nginx is modified.
Rollback timer is armed BEFORE the change; only packet sizes are captured.
This DOES NOT test an Android phone or Russian TSPU.
"""
from __future__ import annotations
import os
import re
import signal
import socket
import ssl
import subprocess
import sys
import time

DE = "89.125.90.101"
HOST = "iglite-z.instagram.com"
TABLE = "mneby_ig_local_w4_20261111"
UNIT = "mneby-ig-localwin4-20261111"
RULES = (
    f"add table inet {TABLE}\n"
    f"add chain inet {TABLE} output {{ type filter hook output priority mangle; policy accept; }}\n"
    f"add rule inet {TABLE} output oifname \"lo\" ip saddr {DE} ip daddr {DE} "
    'tcp sport 443 tcp flags & (syn | ack) == (syn | ack) counter tcp window set 4 '
    'comment "MNEBY_IG_LOCAL_WINDOW4_ONLY"\n'
)
# tcpdump summary only; no -X, -A or full payload.
PKT = re.compile(
    r"\bIP (\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*"
    r"(\d{1,3}(?:\.\d{1,3}){3})\.(\d+):.*?"
    r"Flags \[([^\]]+)\].*?\blength (\d+)"
)

def run(args, *, input=None, check=True, timeout=15):
    p = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} returned {p.returncode}")
    return p

def exists():
    return run(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0

def cleanup():
    if exists():
        run(["nft", "delete", "table", "inet", TABLE])
    ok = not exists()
    print("localwin4_nft_cleaned=" + str(ok).lower(), flush=True)
    if not ok:
        raise RuntimeError("test nft table persists")

def parse(lines, client_port):
    out = dict(synack_windows=[], client_lengths=[], client_ranges=[], synack=0)
    for line in lines.splitlines():
        m = PKT.search(line)
        if not m:
            continue
        src, sp, dst, dp, flags, length = m.groups()
        winmatch = re.search(r"\bwin (\d+)\b", line)
        win = int(winmatch.group(1)) if winmatch else None
        if src == DE and sp == "443" and dst == DE and dp == str(client_port):
            if "S" in flags and "." in flags:
                out["synack"] += 1
                if win is not None:
                    out["synack_windows"].append(win)
        if (src == DE and sp == str(client_port) and dst == DE and dp == "443"
                and int(length) > 0):
            out["client_lengths"].append(int(length))
            match = re.search(r"\bseq (\d+):(\d+)", line)
            if match:
                out["client_ranges"].append(tuple(map(int, match.groups())))
    return out

def generate_clienthello():
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_side=False, server_hostname=HOST)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    data = outgoing.read()
    if len(data) < 100:
        raise RuntimeError("TLS ClientHello not generated")
    offsets = [m.start() for m in re.finditer(re.escape(HOST.encode()), data)]
    if len(offsets) != 1:
        raise RuntimeError("expected one known SNI in ClientHello")
    return data, offsets[0]

def client_probe():
    hello, sni_at = generate_clienthello()
    with socket.create_connection((DE, 443), timeout=4) as sock:
        port = sock.getsockname()[1]
        sock.settimeout(1.5)
        sock.sendall(hello)
        try:
            sock.recv(1)  # Allow ACK/window progression, ignore TLS response.
        except (OSError, TimeoutError):
            pass
        time.sleep(.4)
    return port, len(hello), sni_at

def sni_split(result, sni_at):
    # Sequence ranges are from tcpdump relative numbering. A TCP segment
    # boundary strictly within the known hostname bytes means SNI was split.
    segments = sorted(set(result["client_ranges"]))
    if not segments:
        return "UNVERIFIED_NO_TCP_SEQ"
    first = min(start for start, _ in segments)
    boundaries = {end - first for _, end in segments}
    middle = [x for x in boundaries if sni_at < x < sni_at + len(HOST)]
    return "YES" if middle else "NO_OBSERVED_BOUNDARY"

def capture(phase):
    p = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-n", "-nn", "-tt", "-s", "96", "-l",
         f"tcp and host {DE} and port 443"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    time.sleep(.4)
    if p.poll() is not None:
        raise RuntimeError("tcpdump did not initialize")
    try:
        client_port, size, sni_at = client_probe()
    finally:
        if p.poll() is None:
            p.send_signal(signal.SIGINT)
        try:
            output, stderr = p.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            output, stderr = p.communicate(timeout=2)
    info = parse(output, client_port)
    split = sni_split(info, sni_at)
    print(f"localwin4_{phase}_clienthello_bytes={size}", flush=True)
    print(f"localwin4_{phase}_sni_offset={sni_at}", flush=True)
    print(f"localwin4_{phase}_synack_count={info['synack']}", flush=True)
    print(f"localwin4_{phase}_synack_window=" +
          (",".join(map(str, info["synack_windows"])) or "NONE"), flush=True)
    print(f"localwin4_{phase}_client_segment_count={len(info['client_lengths'])}", flush=True)
    print(f"localwin4_{phase}_client_segment_lengths=" +
          (",".join(map(str, info["client_lengths"][:24])) or "NONE"), flush=True)
    print(f"localwin4_{phase}_sni_split={split}", flush=True)
    print(f"localwin4_{phase}_payload_saved=false", flush=True)
    return info, split

def selftest():
    sample = "\n".join((
        f"IP {DE}.443 > {DE}.47005: Flags [S.], seq 1, ack 1, win 4, options [mss 65495], length 0",
        f"IP {DE}.47005 > {DE}.443: Flags [P.], seq 1:5, ack 1, win 512, length 4",
        f"IP {DE}.47005 > {DE}.443: Flags [P.], seq 5:9, ack 1, win 512, length 4",
        f"IP {DE}.47006 > {DE}.443: Flags [P.], seq 1:130, ack 1, win 512, length 129"
    ))
    p = parse(sample, 47005)
    assert p["synack"] == 1 and p["synack_windows"] == [4]
    assert p["client_lengths"] == [4, 4] and p["client_ranges"] == [(1,5),(5,9)]
    assert parse(sample, 47006)["client_lengths"] == [129]
    assert sni_split(p, 5) == "YES" and sni_split(p, 60) == "NO_OBSERVED_BOUNDARY"
    hello, pos = generate_clienthello()
    assert hello[pos:pos+len(HOST)] == HOST.encode()
    assert 'oifname "lo"' in RULES and f"ip daddr {DE}" in RULES
    print("localwin4_selftest=PASS")

def main():
    if sys.argv[1:] == ["self-test"]:
        selftest()
        return
    if os.geteuid() != 0 or os.environ.get("MNEBY_LOCAL_W4_APPROVED") != "YES":
        raise RuntimeError("requires approved local-only root trial")
    if not re.search(r"\s" + re.escape(DE) + r"/",
                     run(["ip", "-4", "-o", "addr", "show"]).stdout):
        raise RuntimeError("unexpected DE host")
    for svc in ("nginx.service", "mnebydns-dot.service"):
        if run(["systemctl", "is-active", "--quiet", svc], check=False).returncode:
            raise RuntimeError("baseline service inactive")
    if exists():
        raise RuntimeError("test table exists")
    if not run(["systemctl", "is-active", "--quiet", UNIT + ".timer"], check=False).returncode:
        raise RuntimeError("rollback timer still active")
    local_route = run(["ip", "route", "get", DE]).stdout
    if not re.search(r"\blocal\b|\bdev lo\b", local_route):
        raise RuntimeError("destination not local")
    # Syntax gate must pass before any nft change.
    run(["nft", "--check", "-f", "-"], input=RULES)
    print("localwin4_nft_syntax=PASS", flush=True)
    capture("A")
    # Independent cleanup even if SSH, runner or script is killed.
    run(["systemd-run", "--quiet", "--collect", "--unit", UNIT, "--on-active=80s",
         "/usr/sbin/nft", "delete", "table", "inet", TABLE])
    if run(["systemctl", "is-active", "--quiet", UNIT + ".timer"], check=False).returncode:
        raise RuntimeError("rollback watchdog not armed")
    print("localwin4_independent_rollback_armed=true", flush=True)
    try:
        run(["nft", "-f", "-"], input=RULES)
        if not exists():
            raise RuntimeError("test table not installed")
        print("localwin4_only_loopback_modified=true", flush=True)
        b, split = capture("B")
        snapshot = run(["nft", "list", "table", "inet", TABLE]).stdout
        match = re.search(r"counter packets (\d+)", snapshot)
        print("localwin4_rule_synack_hits=" + (match.group(1) if match else "UNKNOWN"), flush=True)
        cleanup()
        capture("A2")
    finally:
        cleanup()
    for svc in ("nginx.service", "mnebydns-dot.service"):
        if run(["systemctl", "is-active", "--quiet", svc], check=False).returncode:
            raise RuntimeError("service interrupted")
    print("localwin4_post_services_active=true", flush=True)
    confirmed = (4 in b["synack_windows"] and split == "YES")
    print("localwin4_sni_fragmentation_proven=" + str(confirmed).lower(), flush=True)
    print("localwin4_android_tspu_path=NOT_TESTED", flush=True)

if __name__ == "__main__":
    main()
