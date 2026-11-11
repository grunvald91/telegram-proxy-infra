#!/usr/bin/env python3
"""MNEBYDNS stage 2: READ-ONLY RU/DE HTTPS differential on fixed origin IPv4.
A differential is evidence for investigation, NOT proof of geo-blocking and
NEVER permission to activate a DNS/SNI route automatically.
"""
import base64
import concurrent.futures
import datetime
import ipaddress
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
SELF = pathlib.Path(__file__).resolve()
HOSTS_FILE = ROOT / "data/mnebydns-geoblock-stage2-priority-20261111.txt"
CATALOG = ROOT / "data/mnebydns-geoblock-research-20261110.tsv"
KNOWN_HOSTS = ROOT / "ops/mnebydns-owner-ssh-known_hosts"
EDGE = "89.125.90.101"
RU = "188.120.254.223"
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
LIMIT = 40

def domain(s):
    if not isinstance(s, str) or len(s) > 253 or not DOMAIN_RE.fullmatch(s):
        raise ValueError("Invalid exact hostname")
    return s

def public_origin(ip):
    obj = ipaddress.IPv4Address(ip)
    if not obj.is_global or str(obj) in (EDGE, RU):
        raise ValueError("Origin must be a distinct public IPv4")
    return str(obj)

def priority():
    lines = [line.strip() for line in HOSTS_FILE.read_text().splitlines()
             if line.strip() and not line.startswith("#")]
    if len(lines) != len(set(lines)) or not 1 <= len(lines) <= LIMIT:
        raise ValueError("Priority list not unique/bounded")
    valid = {}
    for line in CATALOG.read_text().splitlines():
        if line.startswith("#") or line.startswith("domain\t") or not line:
            continue
        parts = line.split("\t")
        if len(parts) != 5:
            raise ValueError("Invalid research record")
        valid[parts[0]] = parts[-1]
    for name in lines:
        domain(name)
        if valid.get(name) != "PENDING_RESEARCH":
            raise ValueError("Priority must be a research candidate: " + name)
    return lines

def result(host, ip=None, state="NOT_TESTED", tls=False, status=None, note=None):
    return dict(host=host, origin_ipv4=ip, state=state,
                certificate_verified=tls, http_status=status, reason=note)

def remote_probe(item, mode):
    host = domain(item["host"])
    if mode == "DE":
        try:
            addresses = sorted({public_origin(info[4][0])
                 for info in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
        except (OSError, ValueError):
            return result(host, state="DNS_ERROR")
        addresses = addresses[:3]
    else:
        try:
            addresses = [public_origin(item["origin_ipv4"])]
        except (KeyError, ValueError):
            return result(host, state="REFERENCE_IP_NOT_VERIFIED")
    last = result(host, state="UNREACHABLE")
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["http/1.1"])
    for ip in addresses:
        stage = "TCP_ERROR"
        try:
            with socket.create_connection((ip, 443), timeout=4) as sock:
                sock.settimeout(4)
                stage = "TLS_ERROR"
                with ctx.wrap_socket(sock, server_hostname=host) as tls:
                    stage = "HTTP_ERROR"
                    tls.sendall(("GET / HTTP/1.1\r\nHost: " + host +
                        "\r\nUser-Agent: MNEBYDNS-ReadOnly-Research/1.0\r\n"
                        "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii"))
                    head = tls.recv(512)
                    match = re.match(rb"HTTP/1\.[01] (\d{3})\b", head)
                    if match:
                        return result(host, ip, "TLS_AND_HTTP", True, int(match.group(1)))
                    return result(host, ip, "TLS_VERIFIED_HTTP_UNPARSEABLE", True)
        except (OSError, ssl.SSLError, TimeoutError) as ex:
            last = result(host, ip, stage, False, note=type(ex).__name__)
    return last

def remote_main(mode, token):
    if mode not in ("DE", "RU"):
        raise ValueError("Invalid location")
    payload = json.loads(base64.b64decode(token, validate=True))
    if not isinstance(payload, list) or not 1 <= len(payload) <= LIMIT:
        raise ValueError("Invalid candidate batch")
    hosts = [domain(x["host"]) for x in payload]
    if len(set(hosts)) != len(hosts):
        raise ValueError("Duplicate host")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        items = list(pool.map(lambda x: remote_probe(x, mode), payload))
    for item in items:
        print(json.dumps(item, separators=(",", ":"), ensure_ascii=True), flush=True)

def via_ssh(role, targets):
    host = EDGE if role == "DE" else RU
    secret = "DE_PASS" if role == "DE" else "RU_PASS"
    if not os.environ.get(secret):
        raise RuntimeError("Missing authorized SSH connection")
    env = os.environ.copy()
    env["SSHPASS"] = env[secret]
    token = base64.b64encode(json.dumps(targets).encode()).decode("ascii")
    opts = ["-T", "-o", "ConnectTimeout=12", "-o", "BatchMode=no",
        "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
        "-o", "UserKnownHostsFile=" + str(KNOWN_HOSTS),
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
        "-o", "LogLevel=ERROR"]
    proc = subprocess.run(["sshpass", "-e", "ssh", *opts, "root@" + host,
         "python3", "-", "--remote", role, token], input=SELF.read_text(),
         capture_output=True, text=True, env=env, timeout=210)
    if proc.returncode:
        raise RuntimeError("Remote " + role + " probe failed, exit " + str(proc.returncode) +
                           " (" + proc.stderr[-180:] + ")")
    lines = [json.loads(line) for line in proc.stdout.splitlines()]
    expected = {x["host"] for x in targets}
    if len(lines) != len(expected) or {x.get("host") for x in lines} != expected:
        raise RuntimeError("Remote probe output incomplete or duplicated")
    return {x["host"]: x for x in lines}

def verdict(de, ru):
    if not de.get("certificate_verified"):
        return "NO_VALID_DE_BASELINE"
    if ru.get("certificate_verified") and ru.get("http_status") in (403, 451) and de.get("http_status") and 200 <= de["http_status"] < 400:
        return "POSSIBLE_SERVER_SIDE_ACCESS_DIFFERENCE"
    if not ru.get("certificate_verified"):
        return "RU_TRANSPORT_OR_TLS_DIFFERENCE"
    a, b = de.get("http_status"), ru.get("http_status")
    if a is not None and b is not None and a == b:
        return "SAME_HTTP_STATUS_NOT_PROOF_OF_ACCESS"
    if a is not None and b is not None:
        return "HTTP_RESPONSE_DIFF_INCONCLUSIVE"
    return "BOTH_TLS_OK_HTTP_INCONCLUSIVE"

def report(names, de, ru):
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    observations = []
    for host in names:
        a, b = de[host], ru[host]
        observations.append({"host": host, "de": a, "ru": b, "assessment": verdict(a, b)})
    counts = Counter(x["assessment"] for x in observations)
    out = ROOT / "stage2-results"
    out.mkdir(mode=0o700, exist_ok=True)
    payload = {"date_utc": ts, "methods": "Same DE-resolved origin IPv4, strict TLS/SNI and one GET /; no redirects or credentials", "observations": observations}
    (out / "differential.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    doc = ["# MNEBYDNS study: RU vs DE first screen", "",
        f"Run (UTC): {ts}. Hosts: {len(names)}.", "",
        "Read-only. No DNS, proxy, route, firewall or database mutation. A difference is NOT definitive proof of a national geoblock.",
        "The same origin IPv4 from the DE DNS lookup was used on both servers; only '/' was requested with no authentication or redirect following.",
        "Even valid TLS and HTTP responses do not demonstrate working application sessions or client compatibility.", "",
        "| Host | DE | RU | Assessment |", "|---|---|---|---|"]
    for x in observations:
        def view(v):
            return v["state"] + ("/HTTP " + str(v["http_status"]) if v.get("http_status") else "")
        doc.append("| " + x["host"] + " | " + view(x["de"]) +
                   " | " + view(x["ru"]) + " | " + x["assessment"] + " |")
    doc.extend(["", "## Counts", ""] +
        ["- " + k + ": " + str(v) for k, v in sorted(counts.items())] +
        ["", "**No activation decisions are made by this workflow.**"])
    (out / "report.md").write_text("\n".join(doc) + "\n")
    for k, v in sorted(counts.items()):
        print("stage2_" + k + "=" + str(v), flush=True)
    print("stage2_readonly_complete=" + str(len(observations)), flush=True)

def self_test():
    names = priority()
    assert len(names) >= 20
    assert verdict(result("test.org", "1.1.1.1", "TLS_AND_HTTP", True, 200),
                   result("test.org", "1.1.1.1", "TLS_AND_HTTP", True, 403)) == "POSSIBLE_SERVER_SIDE_ACCESS_DIFFERENCE"
    assert verdict(result("test.org", "1.1.1.1", "TLS_AND_HTTP", True, 200),
                   result("test.org", "1.1.1.1", "TCP_ERROR")) == "RU_TRANSPORT_OR_TLS_DIFFERENCE"
    assert verdict(result("test.org", "1.1.1.1", "TLS_ERROR"),
                   result("test.org", "1.1.1.1", "TLS_AND_HTTP", True, 200)) == "NO_VALID_DE_BASELINE"
    for forbidden in ("127.0.0.1", "10.0.0.1", EDGE, RU, "169.254.169.254"):
        try:
            public_origin(forbidden)
        except ValueError:
            pass
        else:
            raise AssertionError("Unsafe origin accepted: " + forbidden)
    print("stage2_offline_contract=PASS hosts=" + str(len(names)))

def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()
    if len(sys.argv) == 4 and sys.argv[1] == "--remote":
        return remote_main(sys.argv[2], sys.argv[3])
    if len(sys.argv) != 2 or sys.argv[1] != "--run":
        raise SystemExit("Use --self-test, --remote or --run")
    names = priority()
    de = via_ssh("DE", [{"host": n} for n in names])
    ru = via_ssh("RU", [{"host": n, "origin_ipv4": de[n].get("origin_ipv4")} for n in names])
    report(names, de, ru)

if __name__ == "__main__":
    main()
