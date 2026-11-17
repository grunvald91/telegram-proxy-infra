#!/usr/bin/env python3
"""Owner-approved, bounded Instagram Lite DE Smart DNS + native Window4 trial.

Only exact iglite-z.instagram.com is routed through DE while temporary
nftables SYN-ACK window=4 covers DE public IPv4 TCP/443. An independent
systemd timer reverts Corefile, nginx.conf and the test-owned nft table.
No TLS termination, wildcard Meta routes or permanent production changes.
"""
from __future__ import annotations
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time

ROOT = Path("/run/mneby-iglite-short-de-20261111-v5")
NGINX = Path("/etc/nginx/nginx.conf")
CORE = Path("/opt/mnebydns-dot/Corefile")
CHECKPOINT_CURRENT = Path("/opt/mnebydns-stable-checkpoints/current")
RENDERER = Path(__file__).resolve().parent / "mnebydns-owner-domain-render-20261110.py"
DE = "89.125.90.101"
HOST = "iglite-z.instagram.com"
TABLE = "mneby_ig_lite_w4_20261111_v5"
UNIT = "mneby-ig-lite-short-20261111-v5"
TRIAL_SECONDS = 35
WATCHDOG_SECONDS = 160

def command(argv, *, input=None, timeout=25, check=True):
    p = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode != 0:
        raise RuntimeError(argv[0] + " failed with status " + str(p.returncode))
    return p

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write_exclusive(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

def atomic_replace(path, data):
    target = path.with_name(path.name + ".mneby-iglite-temp")
    if target.exists() or target.is_symlink():
        raise RuntimeError("Prior staging file still present")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.copystat(path, target)
        os.replace(target, path)
    finally:
        if target.exists():
            target.unlink()

def baseline():
    if os.geteuid() != 0:
        raise RuntimeError("Root required")
    if os.environ.get("MNEBY_IGLITE_LIVE_APPROVED") != "YES":
        raise RuntimeError("Owner-approved one-shot flag required")
    for svc in ("nginx.service", "mnebydns-dot.service"):
        if command(["systemctl", "is-active", "--quiet", svc], check=False).returncode:
            raise RuntimeError("Baseline service inactive")
    addrs = command(["ip", "-4", "-o", "addr", "show"]).stdout
    if not re.search(r"\s89[.]125[.]90[.]101/", addrs):
        raise RuntimeError("Not the verified DE host")
    if command(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0:
        raise RuntimeError("Prior nft table exists")
    if command(["systemctl", "is-active", "--quiet", UNIT + ".timer"],
               check=False).returncode == 0:
        raise RuntimeError("Prior rollback timer active")
    # Independent earlier watchdog must not overwrite this trial's files.
    if command(["systemctl", "is-active", "--quiet",
                "mneby-ig-lite-short-20261111.timer"],
               check=False).returncode == 0:
        raise RuntimeError("Earlier run still has an active rollback timer")
    if command(["nft", "list", "table", "inet",
                "mneby_ig_lite_w4_20261111"],
               check=False).returncode == 0:
        raise RuntimeError("Earlier experiment still has active nft table")
    # Never terminate an older independent timer to force a new trial.
    # Wait until BOTH its timer and rollback service are no longer running.
    prior_units = ("mneby-ig-lite-short-20261111-v2",
                   "mneby-ig-lite-short-20261111-v3",
                   "mneby-ig-lite-short-20261111-v4")
    for tick in range(76):
        in_flight = any(
            command(["systemctl", "is-active", "--quiet", name + suffix],
                    check=False).returncode == 0
            for name in prior_units for suffix in (".timer", ".service")
        )
        if not in_flight:
            break
        if tick == 0:
            print("iglite_wait_previous_rollback=ACTIVE_WILL_WAIT", flush=True)
        time.sleep(2)
    else:
        raise RuntimeError("Earlier rollback watchdog did not finish; new test blocked")
    print("iglite_previous_rollback_watchdog_finished=true", flush=True)
    for old_table in ("mneby_ig_lite_w4_20261111_v2",
                      "mneby_ig_lite_w4_20261111_v3",
                      "mneby_ig_lite_w4_20261111_v4"):
        if command(["nft", "list", "table", "inet", old_table],
                   check=False).returncode == 0:
            raise RuntimeError("Earlier global Window4 table still active")
    if ROOT.exists():
        raise RuntimeError("Prior one-shot state exists; refuse duplicate")
    current = CHECKPOINT_CURRENT.read_text().strip()
    stable = Path(current)
    if not stable.is_dir():
        raise RuntimeError("Checkpoint dir absent")
    pairs = (("dns.stable", CORE), ("nginx.stable", NGINX))
    for name, path in pairs:
        original = stable / name
        if not original.is_file() or original.read_bytes() != path.read_bytes():
            raise RuntimeError("Live baseline diverged from stable checkpoint")
    if not RENDERER.is_file():
        raise RuntimeError("Exact route renderer not staged")
    return NGINX.read_bytes(), CORE.read_bytes()

def owner():
    spec = importlib.util.spec_from_file_location("exact", RENDERER)
    if not spec or not spec.loader:
        raise RuntimeError("Renderer import unavailable")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

def nft_rules():
    return (
        "add table inet " + TABLE + "\n"
        "add chain inet " + TABLE + " output { type filter hook output priority mangle; policy accept; }\n"
        "add rule inet " + TABLE + " output ip saddr " + DE
        + " tcp sport 443 tcp flags & (syn | ack) == (syn | ack)"
        " counter tcp window set 4 comment \"MNEBY_IGLITE_GLOBAL_WINDOW4\"\n"
    )

def rollback():
    """Standalone rollback; never depend on the renderer or any GitHub runner."""
    if not ROOT.is_dir():
        print("iglite_rollback=NO_STATE", flush=True)
        return
    nft_absent = command(["nft", "list", "table", "inet", TABLE], check=False).returncode != 0
    originals = ((ROOT / "nginx.original").is_file() and (ROOT / "core.original").is_file())
    if (nft_absent and originals and
        NGINX.read_bytes() == (ROOT / "nginx.original").read_bytes() and
        CORE.read_bytes() == (ROOT / "core.original").read_bytes()):
        print("iglite_rollback=ALREADY_RESTORED", flush=True)
        return
    failures = []
    # Remove the test table first, minimizing global window manipulation.
    if command(["nft", "list", "table", "inet", TABLE], check=False).returncode == 0:
        try: command(["nft", "delete", "table", "inet", TABLE])
        except Exception: failures.append("nft")
    for key, path in (("core", CORE), ("nginx", NGINX)):
        orig = ROOT / (key + ".original")
        candidate = ROOT / (key + ".candidate")
        if not orig.is_file() or not candidate.is_file():
            failures.append(key + "_backup_missing")
            continue
        now = path.read_bytes()
        good = orig.read_bytes()
        after = candidate.read_bytes()
        if now == good:
            continue
        if now != after:
            failures.append(key + "_drift")
            continue
        try: atomic_replace(path, good)
        except Exception: failures.append(key + "_restore")
    # Restart only if actual candidate was active. Using reload preserves Nginx sessions.
    try:
        command(["nginx", "-t"], timeout=20)
        command(["systemctl", "reload", "nginx.service"], timeout=20)
    except Exception: failures.append("nginx_health")
    try:
        command(["systemctl", "restart", "mnebydns-dot.service"], timeout=30)
    except Exception: failures.append("dns_health")
    good = (command(["nft", "list", "table", "inet", TABLE], check=False).returncode != 0
            and NGINX.read_bytes() == (ROOT / "nginx.original").read_bytes()
            and CORE.read_bytes() == (ROOT / "core.original").read_bytes())
    if not good or failures:
        print("iglite_rollback=FAILED_" + ",".join(failures), flush=True)
        raise RuntimeError("Rollback not verified")
    print("iglite_rollback=VERIFIED_ORIGINAL_BYTES_AND_SERVICES", flush=True)

def dot_query_a():
    qname = b"".join(bytes((len(part),))+part.encode("ascii")
                     for part in HOST.split(".")) + b"\x00"
    question = struct.pack("!HHHHHH", 0x7171, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    with socket.create_connection((DE, 853), timeout=5) as tcp:
        tcp.settimeout(5)
        with ssl.create_default_context().wrap_socket(tcp, server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(struct.pack("!H", len(question)) + question)
            def recv(n):
                data=b""
                while len(data)<n:
                    part=tls.recv(n-len(data))
                    if not part: raise RuntimeError("DoT EOF")
                    data+=part
                return data
            size=struct.unpack("!H",recv(2))[0]
            resp=recv(size)
    if len(resp)<12:
        raise RuntimeError("DoT response too short")
    tid, flags, qd, an, _ns, _ar=struct.unpack_from("!HHHHHH",resp)
    if tid!=0x7171 or not flags & 0x8000 or flags & 0xf:
        raise RuntimeError("DoT transaction or RCODE mismatch")
    def skip_name(at):
        for _ in range(128):
            if at>=len(resp): raise RuntimeError("Truncated DNS name")
            label=resp[at]
            if label&0xc0==0xc0:
                if at+1>=len(resp): raise RuntimeError("Truncated DNS pointer")
                return at+2
            if label&0xc0 or label>63: raise RuntimeError("Invalid DNS label")
            at+=1
            if label==0:return at
            at+=label
        raise RuntimeError("DNS name loop")
    at=12
    for _ in range(qd):
        at=skip_name(at)+4
        if at>len(resp):raise RuntimeError("Truncated DNS question")
    answers=[]
    for _ in range(an):
        at=skip_name(at)
        if at+10>len(resp):raise RuntimeError("Truncated DNS answer")
        kind, cls, _ttl, length=struct.unpack_from("!HHIH",resp,at)
        at+=10
        if at+length>len(resp): raise RuntimeError("Truncated DNS RDATA")
        if kind==1 and cls==1 and length==4:
            answers.append(socket.inet_ntoa(resp[at:at+4]))
        at+=length
    if answers != [DE]:
        raise RuntimeError("Wrong DoT IPv4 records for exact Lite hostname")
    return True


def live_tls():
    ctx = ssl.create_default_context()
    with socket.create_connection((DE, 443), timeout=7) as tcp:
        tcp.settimeout(7)
        with ctx.wrap_socket(tcp, server_hostname=HOST) as tls:
            if not tls.getpeercert():
                raise RuntimeError("Meta certificate not verified")
            return tls.version()

def live():
    originals = baseline()
    m = owner()
    origin = m.origin_ip(HOST)  # Resolved and certificate-validated FROM DE.
    ng = m.nginx_add(originals[0].decode(), HOST, origin)
    core = m.core_add(originals[1].decode(), HOST)
    if m.nginx_remove(ng, HOST).encode() != originals[0] or m.core_remove(core, HOST).encode() != originals[1]:
        raise RuntimeError("Candidate is not byte-reversible")
    rules = nft_rules()
    command(["nft", "--check", "-f", "-"], input=rules)
    print("iglite_approved_origin_tls_verified=true", flush=True)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=False)
    write_exclusive(ROOT / "nginx.original", originals[0])
    write_exclusive(ROOT / "core.original", originals[1])
    write_exclusive(ROOT / "nginx.candidate", ng.encode())
    write_exclusive(ROOT / "core.candidate", core.encode())
    # nginx syntax parser BEFORE changing any live file.
    command(["nginx", "-t", "-c", str(ROOT / "nginx.candidate")], timeout=25)
    print("iglite_nginx_candidate_syntax_verified=true", flush=True)
    # Independent rollback before touching either service or firewall.
    command(["systemd-run", "--quiet", "--collect", "--unit", UNIT,
             "--on-active=" + str(WATCHDOG_SECONDS) + "s",
             "/usr/bin/python3", str(Path(__file__).resolve()), "rollback"])
    if command(["systemctl", "is-active", "--quiet", UNIT + ".timer"],
               check=False).returncode:
        raise RuntimeError("Rollback timer not armed")
    print("iglite_independent_rollback_armed=true", flush=True)
    try:
        atomic_replace(NGINX, ng.encode())
        command(["nginx", "-t"], timeout=20)
        command(["systemctl", "reload", "nginx.service"], timeout=20)
        atomic_replace(CORE, core.encode())
        command(["systemctl", "restart", "mnebydns-dot.service"], timeout=30)
        # A systemctl restart can complete before the public-only DoT bind
        # is accepting connections; service-is-active alone is not readiness.
        # A complete route requires no alternate IPv6/CNAME/HTTPS/SVCB
        # reply that lets Android connect directly to Meta instead of DE.
        # Load this helper ONLY during live mode, never during rollback.
        from mnebydns_iglite_dns_wire_checks import check_exact_types
        for retry in range(21):
            try:
                dns_checks = check_exact_types()
                break
            except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
                if retry == 20:
                    raise
                time.sleep(.5)
        for qtype, verdict in dns_checks.items():
            print("iglite_live_dot_" + qtype + "=" + verdict, flush=True)
        print("iglite_live_dot_route_DE=PASS_NO_IPV6_OR_SVCB_ESCAPE", flush=True)
        print("iglite_live_meta_tls=" + live_tls(), flush=True)
        command(["nft", "-f", "-"], input=rules)
        print("iglite_live_global_window4=ACTIVE", flush=True)
        time.sleep(TRIAL_SECONDS)
        snapshot=command(["nft", "-a", "list", "table", "inet", TABLE]).stdout
        match=re.search(r"counter packets (\d+)", snapshot)
        print("iglite_live_window4_synacks=" + (match.group(1) if match else "UNKNOWN"), flush=True)
    finally:
        rollback()
    print("iglite_end_to_end_android=NOT_TESTED", flush=True)

if __name__ == "__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("live", "rollback"):
        raise SystemExit("Usage: canary.py live|rollback")
    if sys.argv[1]=="rollback":
        rollback()
    else:
        live()
