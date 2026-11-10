#!/usr/bin/env python3
"""Coordinated Android/Wi-Fi one-connection TCP443 test; no table rebuild.

Run only from a manually dispatched GitHub Actions job with a participant
at their phone. The HTTP/80 nonce proves only a fresh request from the
claimed public IPv4. It does NOT cryptographically identify an Android,
nor distinguish multiple users behind one NAT/CGNAT address.

Captures Ethernet headers and minimal HTTP challenge bytes only from the
specified IP; never prints payload, credentials, source port or nonce.
The single SYN's observed NAT source port scopes the NFT exception to ONE
TCP flow. A 75s independent systemd rollback is armed BEFORE nft insertion.
"""
from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time

RU = ipaddress.IPv4Address("188.120.254.223")
GEN = Path("/usr/local/sbin/telegram-nfqws-rules")
EXPECTED = "8beeffbe10e7da097e10bde4b1ef568219d52c2f1c04b189e71602069de9ec3f"
LOCK = Path("/run/lock/mnebydns-nfqws-guard-install.lock")
ROOT = Path("/run/mnebydns-phone-flow")
TABLE = ["inet", "telegram_nfqws", "post"]
TAG_PREFIX = "MNEBY_PHONE_TCP_"
CAPTURE_LIMIT = 150
LIVE_LIMIT = 30
WATCHDOG_SECONDS = 75

def sh(args, *, data=None, timeout=12, check=True):
    p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f"{args[0]} returned {p.returncode}: {p.stderr[:180]}")
    return p

def chain():
    return sh(["nft", "-a", "list", "chain", *TABLE]).stdout

def handles(src: str, tag: str):
    result = []
    for line in src.splitlines():
        if f'comment "{tag}"' not in line:
            continue
        h = re.search(r"# handle (\d+)\s*$", line)
        if h:
            result.append((int(h.group(1)), line))
    return result

def check_environment():
    if not GEN.is_file() or hashlib.sha256(GEN.read_bytes()).hexdigest() != EXPECTED:
        raise RuntimeError("Unexpected installed generator; abort")
    if Path("/etc/mnebydns/telegram-synack-canary-ipv4").exists():
        raise RuntimeError("Persistent opt-in must be disabled")
    status = sh(["systemctl", "is-active", "--quiet", "telegram-nfqws.service"], check=False)
    if status.returncode:
        raise RuntimeError("Telegram NFQUEUE handler is not active")
    current = chain()
    queued = [line for line in current.splitlines()
              if "tcp sport 443" in line and re.search(r"\bto\s+210\b", line)]
    if len(queued) != 1 or "bypass" not in queued[0] or "mark" not in queued[0]:
        raise RuntimeError("Unexpected live queue 210 rule")
    if TAG_PREFIX in current or "MNEBY_IG_SYNACK_AB_" in current or "MNEBYDNS_SYNACK_CANARY_PEER_V1" in current:
        raise RuntimeError("A previous test or persistent guard is active")
    return current

def packet(frame, peer):
    """Return minimal parsed IPv4 TCP fields, or None. Never store payload."""
    if len(frame) < 54 or frame[12:14] != b"\x08\x00":
        return None
    ip = frame[14:]
    if ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    n = (ip[0] & 0xf) * 4
    if n < 20 or len(ip) < n + 20:
        return None
    src, dst = ip[12:16], ip[16:20]
    allowed = ((src == peer and dst == RU.packed) or
               (src == RU.packed and dst == peer))
    if not allowed:
        return None
    tcp = ip[n:]
    sport, dport = struct.unpack_from("!HH", tcp)
    dataoffset = (tcp[12] >> 4) * 4
    if dataoffset < 20 or len(tcp) < dataoffset:
        return None
    return (src == peer, sport, dport, tcp[13], tcp[dataoffset:])

def match_challenge(parsed, nonce):
    if not parsed:
        return False
    inbound, _, dport, _, payload = parsed
    return (inbound and dport == 80 and
            payload.startswith(("GET /mneby-" + nonce + " ").encode("ascii")))

def pick_syn(parsed):
    if not parsed:
        return None
    inbound, sport, dport, flags, payload = parsed
    if inbound and dport == 443 and (flags & 0x12) == 0x02 and not payload:
        return sport
    return None

def nft_rule(peer, port, tag):
    if not (1 <= port <= 65535):
        raise ValueError("Invalid observed client port")
    return (
        f'insert rule inet telegram_nfqws post '
        f'oifname "ens3" ip saddr {RU} ip daddr {peer} '
        f'tcp sport 443 tcp dport {port} '
        'tcp flags & (syn | ack) == (syn | ack) '
        'ct reply packets 1-20 meta mark & 0x40000000 == 0 '
        f'counter return comment "{tag}"\n'
    )

def watchdog(path, tag):
    script = '''#!/usr/bin/env python3
import os,re,subprocess
tag=%r
root=%r
try:
    r=subprocess.run(["nft","-a","list","chain","inet","telegram_nfqws","post"],
                     capture_output=True,text=True,timeout=12)
    if r.returncode==0:
        for line in r.stdout.splitlines():
            if 'comment "'+tag+'"' not in line:continue
            match=re.search(r"# handle (\\d+)\\s*$",line)
            if match:
                subprocess.run(["nft","delete","rule","inet","telegram_nfqws","post",
                                "handle",match.group(1)],check=True,timeout=12)
                print("phone_watchdog_rule_removed=true",flush=True)
finally:
    for p in (root,):
        try:os.unlink(p)
        except FileNotFoundError:pass
''' % (tag, str(path))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, "w") as f:
        f.write(script); f.flush(); os.fsync(f.fileno())

def remove_own(tag):
    found = handles(chain(), tag)
    if len(found) > 1:
        raise RuntimeError("Ambiguous test rule; independent timer remains armed")
    for h, _ in found:
        sh(["nft", "delete", "rule", *TABLE, "handle", str(h)])
    return len(found)

def main():
    if os.geteuid() != 0 or len(sys.argv) != 4:
        raise SystemExit("Usage: python3 - PHONE_PUBLIC_IPV4 RUN_ID CHALLENGE_HEX")
    peer = ipaddress.IPv4Address(sys.argv[1])
    if not peer.is_global or peer == RU:
        raise ValueError("Phone peer must have public IPv4 distinct from RU")
    runid, nonce = sys.argv[2:]
    if not re.fullmatch(r"\d{8,18}", runid) or not re.fullmatch(r"[0-9a-f]{16,32}", nonce):
        raise ValueError("Invalid run id or challenge")
    tag = TAG_PREFIX + runid
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ROOT.is_symlink():
        raise RuntimeError("Unsafe runtime directory")
    path = ROOT / ("rollback-" + runid + ".py")
    unit = "mneby-phone-" + runid
    with LOCK.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_environment()
        if path.exists() or sh(["systemctl", "is-active", "--quiet", unit + ".timer"], check=False).returncode == 0:
            raise RuntimeError("Prior canary still active")
        # Bind before READY. A missing participant means no server rule change.
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        s.settimeout(0.35)
        try:
            print("phone_challenge_ready=true", flush=True)
            verified = False
            deadline = time.monotonic() + CAPTURE_LIMIT
            while time.monotonic() < deadline:
                try:
                    parsed = packet(s.recv(2048), peer.packed)
                except socket.timeout:
                    continue
                if match_challenge(parsed, nonce):
                    verified = True
                    break
            if not verified:
                print("phone_test=NO_CHALLENGE_NO_FIREWALL_CHANGE", flush=True)
                return
            print("phone_challenge_seen=true", flush=True)
            print("phone_waiting_for_https_syn=true", flush=True)
            port = None
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    port = pick_syn(packet(s.recv(2048), peer.packed))
                except socket.timeout:
                    continue
                if port is not None:
                    break
            if port is None:
                print("phone_test=NO_HTTPS_SYN_NO_FIREWALL_CHANGE", flush=True)
                return
            # Observe the matched 5-tuple *before* adding any exception.
            # If this path already receives a SYN-ACK, do not mutate nftables.
            baseline_synack=0
            baseline_ack=0
            deadline = time.monotonic() + 2.6
            while time.monotonic() < deadline:
                try:
                    parsed=packet(s.recv(2048),peer.packed)
                except socket.timeout:
                    continue
                if not parsed:continue
                inbound, sport, dport, flags, payload=parsed
                if not inbound and sport==443 and dport==port and (flags & 0x12)==0x12:
                    baseline_synack+=1
                if inbound and sport==port and dport==443 and (flags & 0x10) and not (flags & 0x02):
                    baseline_ack+=1
            print("phone_baseline_synack="+str(baseline_synack),flush=True)
            print("phone_baseline_ack="+str(baseline_ack),flush=True)
            if baseline_synack or baseline_ack:
                print("phone_test=ALREADY_REACHABLE_NO_FIREWALL_CHANGE",flush=True)
                return
            # The first SYN might have been lost; a later retransmission
            # from the same observed NAT source port can match this rule.
            rule = nft_rule(peer, port, tag)
            sh(["nft", "--check", "-f", "-"], data=rule)
            watchdog(path, tag)
            installed = False
            try:
                sh(["systemd-run", "--quiet", "--collect", "--unit", unit,
                    f"--on-active={WATCHDOG_SECONDS}s", "/usr/bin/python3", str(path)])
                if sh(["systemctl", "is-active", "--quiet", unit + ".timer"], check=False).returncode:
                    raise RuntimeError("Independent rollback not armed")
                print("phone_rollback_armed=true",flush=True)
                sh(["nft", "-f", "-"], data=rule)
                installed = True
                found = handles(chain(), tag)
                if len(found) != 1:
                    raise RuntimeError("Expected exactly one exception rule")
                print("phone_single_flow_rule_active=true",flush=True)
                print("phone_rule_scope=exact_ipv4_and_observed_tcp_source_port",flush=True)
                syns=synacks=acks=tls_records=0
                deadline = time.monotonic() + LIVE_LIMIT
                while time.monotonic() < deadline:
                    try:
                        parsed = packet(s.recv(2048), peer.packed)
                    except socket.timeout:
                        continue
                    if not parsed:
                        continue
                    inbound, sport, dport, flags, payload = parsed
                    if inbound and sport == port and dport == 443:
                        if (flags & 0x12) == 0x02:
                            syns+=1
                        elif (flags & 0x10) and not (flags & 0x02):
                            acks+=1
                        if payload[:1] == b"\x16":
                            tls_records+=1
                    elif not inbound and sport == 443 and dport == port and (flags & 0x12) == 0x12:
                        synacks+=1
                entries=handles(chain(),tag)
                counter=re.search(r"\bcounter packets (\d+)",entries[0][1]) if len(entries)==1 else None
                print("phone_observed_syn="+str(syns),flush=True)
                print("phone_observed_synack="+str(synacks),flush=True)
                print("phone_observed_ack="+str(acks),flush=True)
                print("phone_observed_tls_record_start="+str(tls_records),flush=True)
                print("phone_exception_counter="+(counter.group(1) if counter else "UNKNOWN"),flush=True)
            finally:
                # Always attempt scoped immediate rollback; independent timer
                # remains armed if SSH dies or direct nft cleanup fails.
                if installed or handles(chain(), tag):
                    print("phone_immediate_cleanup_rules="+str(remove_own(tag)),flush=True)
                if tag in chain():
                    raise RuntimeError("Phone test rule still present after cleanup")
        finally:
            s.close()
            # No table recreation or worker restart, even on failures.
            if not handles(chain(), tag):
                print("phone_test_rule_absent=true",flush=True)
            original=chain()
            good=any("tcp sport 443" in l and re.search(r"\bto\s+210\b",l) for l in original.splitlines())
            print("phone_original_queue_preserved="+str(good).lower(),flush=True)
            if not good:
                raise RuntimeError("Original NFQUEUE210 rule unexpectedly absent")

if __name__ == "__main__":
    main()
