#!/usr/bin/env python3
"""Isolated exact-host TLS test; NO live CoreDNS/Nginx/DB writes.

RU client -> transient SSH reverse forward -> GH runner -> transient SSH
local forward -> DE host -> pinned origin:443. This verifies a foreign-egress
TLS path, NOT the production RU-to-DE public edge, DNS policy, or client app.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import pathlib
import shlex
import signal
import socket
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAIRS = (("artifacts.elastic.co", "34.120.127.130"),
         ("brickset.com", "104.26.12.83"))
IP = {"ru": "188.120.254.223", "de": "89.125.90.101"}
PATHS = {
  "core": "/opt/mnebydns-dot/Corefile",
  "nginx": "/etc/nginx/nginx.conf",
  "proxy": "/etc/mnebydns-googlepilot/nginx.conf",
}

def load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

owner = load("isolated_owner", "mnebydns-owner-domain-controller-20261110.py")
pre = load("isolated_pre", "mnebydns-bulk-preflight-20261112.py")
scanner = pre.scanner
renderer = pre.renderer

REMOTE_PY = """import json,re,socket,ssl,sys
host,addr,port=sys.argv[1],sys.argv[2],int(sys.argv[3])
s=socket.create_connection((addr,port),timeout=8)
with ssl.create_default_context().wrap_socket(s,server_hostname=host) as tls:
 tls.settimeout(8)
 tls.sendall(("GET / HTTP/1.1\\r\\nHost: "+host+"\\r\\nUser-Agent: MNEBYDNS-ReadOnly-Research/1.0\\r\\nConnection: close\\r\\n\\r\\n").encode())
 line=tls.makefile("rb").readline(256).decode("latin1","replace").strip()
 m=re.match(r"HTTP/\\d(?:\\.\\d)?\\s+(\\d{3})\\b",line)
 if not m:raise RuntimeError("NO_HTTP_STATUS")
 print(json.dumps(dict(tls_cert_verified=True,http_status=int(m.group(1)))))
"""

def sshtunnel(role: str, mode: str, spec: str):
    passwd = os.environ.get({"de": "DE_PASS", "ru": "RU_PASS"}[role], "")
    if not passwd:
        raise RuntimeError("SSH_CREDENTIAL_NOT_AVAILABLE")
    env = os.environ.copy()
    env["SSHPASS"] = passwd
    cmd = ["sshpass", "-e", "ssh", "-T",
           "-o", "ConnectTimeout=12", *owner.SSH_TRUST,
           "-o", "LogLevel=ERROR",
           "-o", "ExitOnForwardFailure=yes",
           "-o", "ServerAliveInterval=10",
           "-o", "ServerAliveCountMax=2",
           "-N", mode, spec, "root@" + IP[role]]
    return subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True)

def end_tunnel(p):
    if p is None:
        return
    if p.poll() is None:
        try: os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError: pass
    try: p.wait(timeout=6)
    except subprocess.TimeoutExpired:
        try: os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        p.wait(timeout=3)

def run_ru_tls(host: str, port: int):
    cmd = ("python3 -c " + shlex.quote(REMOTE_PY) + " " +
           shlex.quote(host) + " 127.0.0.1 " + str(port))
    return json.loads(owner.ssh("ru", cmd, 30))

def run_test(host: str, ip: str, index: int):
    # Fixed high loopback ports, never production 443/853.
    local = 48311 + index
    remote = 48411 + index
    de_tunnel = None
    ru_tunnel = None
    try:
        de_tunnel = sshtunnel("de", "-L", f"127.0.0.1:{local}:{ip}:443")
        ready = False
        for _ in range(10):
            if de_tunnel.poll() is not None:
                raise RuntimeError("DE_TUNNEL_EXITED")
            try:
                s = socket.create_connection(("127.0.0.1", local), timeout=2)
                s.close()
                ready = True
                break
            except OSError: time.sleep(0.5)
        if not ready: raise RuntimeError("DE_TUNNEL_UNAVAILABLE")

        ru_tunnel = sshtunnel("ru", "-R",
                              f"127.0.0.1:{remote}:127.0.0.1:{local}")
        last = None
        for _ in range(4):
            if ru_tunnel.poll() is not None:
                raise RuntimeError("RU_TUNNEL_EXITED")
            try: return run_ru_tls(host, remote)
            except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
                last = type(exc).__name__
                time.sleep(1)
        raise RuntimeError("ISOLATED_TLS_FAILED_" + (last or "UNKNOWN"))
    finally:
        end_tunnel(ru_tunnel)
        end_tunnel(de_tunnel)

def snapshot():
    return {k: hashlib.sha256(pre.read_exact_remote("de", p).encode()).hexdigest()
            for k, p in PATHS.items()}

def statuses():
    query = ("SELECT domain||'|'||status FROM dns_admin_domains WHERE " +
             "product='Research 2026-11' AND domain IN " +
             "('artifacts.elastic.co','brickset.com') ORDER BY domain")
    entries = dict(row.split("|", 1) for row in owner.sql(query).splitlines())
    if set(entries) != set(h for h, _ in PAIRS):
        raise RuntimeError("MISSING_RESEARCH_DB_ROW")
    return entries

def main():
    for host, ip in PAIRS:
        renderer.validate_domain(host)
        renderer.validated_public_ip(ip)
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("CHECKPOINT_NOT_CLEAN_BEFORE")
    before = snapshot()
    start_status = statuses()
    if any(s != "PENDING" for s in start_status.values()):
        raise RuntimeError("DB_CANDIDATE_NOT_PENDING")
    try:
        de = scanner.via_ssh("DE", [{"host": h, "origin_ipv4": ip} for h, ip in PAIRS])
        ru = scanner.via_ssh("RU", [{"host": h, "origin_ipv4": ip} for h, ip in PAIRS])
        results = []
        for index, (host, ip) in enumerate(PAIRS):
            result = {"domain": host, "pinned_origin_ipv4": ip,
                      "de": de[host], "ru": ru[host]}
            if not (de[host].get("certificate_verified") and
                    200 <= (de[host].get("http_status") or 0) < 400 and
                    ru[host].get("http_status") in (403, 451)):
                result["isolated_route"] = {"status": "SKIPPED_UNVERIFIED_BASELINE"}
            else:
                try:
                    result["isolated_route"] = {"status": "TLS_VERIFIED",
                                                **run_test(host, ip, index)}
                except Exception as exc:
                    result["isolated_route"] = {"status": "FAIL",
                                                "error_type": type(exc).__name__,
                                                "error": str(exc)[:120]}
            results.append(result)
            print("ISOLATED_HOST_RESULT=" + json.dumps(result, sort_keys=True), flush=True)
    finally:
        after = snapshot()
        end_status = statuses()
        checkpoint_clean = owner.live_checkpoint_unchanged()
        controls = {"checkpoint_clean_after": checkpoint_clean,
                    "same_file_hashes": before == after,
                    "same_db_states": start_status == end_status}
        print("ISOLATED_SAFETY=" + json.dumps(controls, sort_keys=True), flush=True)
        if not all(controls.values()):
            raise RuntimeError("LIVE_STATE_CHANGED_DURING_READONLY_TEST")
    out = ROOT / "two-isolated-results"
    out.mkdir(exist_ok=True)
    (out / "summary.json").write_text(
       json.dumps({"results": results, "safety": controls,
                   "route": "RU -> SSH reverse via GitHub runner -> SSH DE -> pinned TLS origin",
                   "not_tested": ["public DE:443 ingress", "Smart DNS policy", "full application"]},
                  indent=2, ensure_ascii=False) + "\n")
    print("ISOLATED_TEST_DONE=2", flush=True)

if __name__ == "__main__":
    main()
