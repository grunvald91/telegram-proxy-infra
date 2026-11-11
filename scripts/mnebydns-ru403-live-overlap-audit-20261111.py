#!/usr/bin/env python3
"""Non-mutating overlap audit for 109 reviewed RU HTTP 403/451 candidates.
Reads exact live CoreDNS/Nginx snapshots and owner PostgreSQL statuses through
pinned SSH keys; never changes the services, routes or database.
"""
from __future__ import annotations
import csv
import importlib.util
import os
import pathlib
import re
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FILE = ROOT / "data/mnebydns-ru-403-451-review-20261111.txt"
SSH_KEYS = ROOT / "ops/mnebydns-owner-ssh-known_hosts"
RENDER = ROOT / "scripts/mnebydns-owner-domain-render-20261110.py"
SPEC = importlib.util.spec_from_file_location("mnebydns_exact_host_policy", RENDER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Missing strict exact-host renderer")
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)
RESULTS = ROOT / "overlap-audit-results"
SAMPLE_PUBLIC_ORIGIN = "93.184.215.14"   # ONLY an in-memory renderer input; never a live origin.

def host_list():
    lines = [x.strip() for x in FILE.read_text().splitlines()
             if x.strip() and not x.startswith("#")]
    if len(lines) != 109 or len(set(lines)) != len(lines):
        raise ValueError("Expected 109 unique owner-review hosts")
    if any(policy.validate_domain(x) != x for x in lines):
        raise ValueError("Unsafe hostname")
    if any(x in ("chatgpt.com","grok.com") for x in lines):
        raise ValueError("Already-confirmed owner routes must not be re-added")
    return lines

def ssh(role, command):
    if role not in ("DE","RU"):
        raise ValueError("Unknown host role")
    ip = "89.125.90.101" if role == "DE" else "188.120.254.223"
    key = "DE_PASS" if role == "DE" else "RU_PASS"
    password = os.environ.get(key)
    if not password:
        raise RuntimeError("Missing authorized SSH credentials")
    env = os.environ.copy()
    env["SSHPASS"] = password
    args = ["sshpass","-e","ssh","-T","-o","ConnectTimeout=12",
            "-o","StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
            "-o","UserKnownHostsFile="+str(SSH_KEYS),
            "-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no",
            "-o","LogLevel=ERROR","root@"+ip,command]
    p = subprocess.run(args,capture_output=True,text=True,env=env,timeout=100)
    if p.returncode:
        raise RuntimeError("Read-only "+role+" inspection failed (exit code "+
                           str(p.returncode)+")")
    return p.stdout

def live_snapshot():
    integrity = (
        "set -Eeuo pipefail; "
        "root=$(cat /opt/mnebydns-stable-checkpoints/current); "
        "[[ \"$root\" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]]; "
        "(cd \"$root\" && sha256sum -c stable-manifest.sha256 >/dev/null); "
        "cmp -s \"$root/dns.stable\" /opt/mnebydns-dot/Corefile; "
        "cmp -s \"$root/nginx.stable\" /etc/nginx/nginx.conf; "
        "cmp -s \"$root/proxy.stable\" /etc/mnebydns-googlepilot/nginx.conf; "
        "nginx -t >/dev/null 2>&1; "
        "systemctl is-active --quiet nginx; "
        "systemctl is-active --quiet mnebydns-dot.service; "
        "systemctl is-active --quiet mnebydns-googlepilot.service; "
        "echo BASELINE_VALID"
    )
    if ssh("DE", "bash -c "+shlex.quote(integrity)).strip() != "BASELINE_VALID":
        raise RuntimeError("Live checkpoint is not clean")
    paths = ["/opt/mnebydns-dot/Corefile", "/etc/nginx/nginx.conf",
             "/etc/mnebydns-googlepilot/nginx.conf"]
    return [ssh("DE","cat "+shlex.quote(p)) for p in paths]

def statuses():
    command = ("docker exec mnebyvpn-stage-postgres "
        "psql -XqAt -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage "
        "-c "+shlex.quote("SELECT domain || '|' || status FROM dns_admin_domains ORDER BY domain"))
    output = ssh("RU",command)
    parsed={}
    for line in output.splitlines():
        parts=line.split("|")
        if len(parts)!=2:
            raise ValueError("Unrecognized database inventory output")
        domain, state=parts
        parsed[domain]=state
    return parsed

def review(host, db, core, nginx, sidecar):
    # Strict renderer throws on exact, suffix or regex overlap and on
    # unknown import/includes. Error is not silently treated as "not routed".
    problems=[]
    try:
        policy.core_add(core,host)
    except (ValueError,AssertionError) as exc:
        problems.append("CORE_RULE_OVERLAP_OR_UNPARSEABLE")
    try:
        policy.nginx_add(nginx,host,SAMPLE_PUBLIC_ORIGIN)
    except (ValueError,AssertionError) as exc:
        problems.append("NGINX_SNI_OVERLAP_OR_UNPARSEABLE")
    if host.lower() in sidecar.lower():
        problems.append("SIDECAR_MENTIONS_HOST")
    state=db.get(host,"DB_MISSING")
    if state!="PENDING":
        problems.append("DB_STATUS_NOT_PENDING")
    return {"domain":host, "db_status":state,
            "policy_result":"PREFLIGHT_RENDER_CLEAR" if not problems else "EXCLUDE_UNTIL_REVIEW",
            "reasons":"|".join(problems)}

def summarize(items):
    RESULTS.mkdir(mode=0o700,exist_ok=True)
    columns=("domain","db_status","policy_result","reasons")
    with (RESULTS/"live-overlap-review.csv").open("w",newline="") as stream:
        writer=csv.DictWriter(stream,fieldnames=columns)
        writer.writeheader()
        writer.writerows(items)
    clear=[x for x in items if x["policy_result"]=="PREFLIGHT_RENDER_CLEAR"]
    excluded=[x for x in items if x["policy_result"]!="PREFLIGHT_RENDER_CLEAR"]
    (RESULTS/"render-clear-for-canary-review.txt").write_text(
        "".join(x["domain"]+"\n" for x in clear))
    (RESULTS/"already-covered-or-risk-review.txt").write_text(
        "".join(x["domain"]+" "+x["db_status"]+" "+x["reasons"]+"\n" for x in excluded))
    report = [
        "# MNEBYDNS 109-host live route overlap audit",
        "",
        "Read-only: verified DE stable checkpoint, actual CoreDNS and both Nginx "
        "configs, and canonical RU database statuses.",
        "The 109 hosts are filtered from confirmed RU HTTP 403/451 and DE "
        "2xx/3xx results, excluding user-reported already connected ChatGPT and Grok.",
        "",
        f"- Hosts assessed: **{len(items)}**.",
        f"- No detected exact CoreDNS/Nginx overlap and DB pending: **{len(clear)}**.",
        f"- Existing routing/DB status/unknown map concerns: **{len(excluded)}**.",
        "",
        "**Important:** A clean in-memory rendering check is NOT evidence of "
        "functional Smart DNS, complete app/CDN coverage, QUIC, correct origin "
        "pinned IP for live traffic, or RU→DE TLS reachability. "
        "No domain is automatically activated by this report.",
        "",
        "| Domain | Database state | Result | Reason |",
        "|---|---|---|---|",
    ]
    report += ["| "+r["domain"]+" | "+r["db_status"]+" | "+
              r["policy_result"]+" | "+(r["reasons"] or "none")+" |" for r in items]
    (RESULTS/"report.md").write_text("\n".join(report)+"\n")
    print("OVERLAP_AUDIT_TOTAL="+str(len(items)),flush=True)
    print("OVERLAP_RENDER_CLEAR="+str(len(clear)),flush=True)
    print("OVERLAP_NEEDS_REVIEW="+str(len(excluded)),flush=True)
    print("OVERLAP_PREVIOUSLY_CONNECTED_OWNER_EXCLUSIONS=chatgpt.com,grok.com",flush=True)
    print("OVERLAP_AUDIT_DETAIL_BEGIN")
    print(",".join(columns))
    for r in items:
        print(",".join(r[x] for x in columns),flush=True)
    print("OVERLAP_AUDIT_DETAIL_END")
    print("OVERLAP_LIVE_CHANGES=false",flush=True)

def self_test():
    names=host_list()
    assert len(names)==109
    assert policy.validate_domain(names[0])==names[0]
    assert "chatgpt.com" not in names and "grok.com" not in names
    sample_core = ("tls://.:853 {\n"
        "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
        "    cache 30\n}\n")
    sample_nginx = ("stream {\nmap $ssl_preread_server_name $direct_mtproxy_backend {\n"
        " default 127.0.0.1:9443;\n}\nserver { proxy_pass $direct_mtproxy_backend; }\n}\n")
    good=review("example.net",{"example.net":"PENDING"},sample_core,sample_nginx,"")
    assert good["policy_result"]=="PREFLIGHT_RENDER_CLEAR"
    bad=review("example.net",{"example.net":"ACTIVE"},sample_core,sample_nginx,"")
    assert bad["policy_result"]=="EXCLUDE_UNTIL_REVIEW"
    print("OVERLAP_OFFLINE_GATE=PASS 109 HOSTS",flush=True)

if __name__=="__main__":
    if sys.argv==["scripts/mnebydns-ru403-live-overlap-audit-20261111.py","--self-test"] or (
        len(sys.argv)==2 and sys.argv[1]=="--self-test"):
        self_test()
    elif len(sys.argv)==2 and sys.argv[1]=="--run":
        core,nginx,sidecar=live_snapshot()
        db=statuses()
        summarize([review(x,db,core,nginx,sidecar) for x in host_list()])
    else:
        raise SystemExit("Usage: --self-test | --run")
