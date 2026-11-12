#!/usr/bin/env python3
"""MNEBYDNS: bounded owner-authorized batch of reviewed RU 403/451 exact hosts.

This program deliberately reuses the tested single-host apply/confirm/rollback
controller; does not edit CoreDNS, nginx or their stable checkpoint directly.
One hostname, one independent systemd expiry timer, one verified promotion at a
time. No wildcard routes, unverified origin IPs or surprise database owners.

This is a technical HTTPS GET / canary, NOT a verified end-user app session.
"""
from __future__ import annotations
import argparse
import csv
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
CANDIDATES = ROOT / "data/mnebydns-108-canary-review-20261111.txt"
STRONG = ROOT / "data/mnebydns-ru-403-451-de-success-20261111.csv"
CONTROL = ROOT / "data/mnebydns-batch-auto-enabled-20261112.txt"
OWNER = ROOT / "scripts/mnebydns-owner-domain-controller-20261110.py"
OUTPUT = ROOT / "batch-108-results"
spec = importlib.util.spec_from_file_location("mnebydns_owner_for_batch", OWNER)
if spec is None or spec.loader is None:
    raise RuntimeError("Missing production owner controller")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
PRODUCT = "Research 2026-11"
BUSY = ("APPLY_REQUESTED", "PROBING", "CANARY", "CONFIRM_REQUESTED",
        "CONFIRMING", "ROLLBACK_REQUESTED", "REMOVAL_PENDING", "REMOVING")
MAX_PER_RUN = 5
MIN_RAM_KB = 160000
MIN_DISK_KB = 250000
HOSTNAME = re.compile(r"^[a-z0-9.-]{4,253}$")
# Use identical HTTP GET / and UA in the DE direct / RU direct / RU via DE tests.
# Never follow redirects, read response bodies, use credentials or bypass TLS.
HTTP_CODE = r'''import re,socket,ssl,sys
host=sys.argv[1]
ip=sys.argv[2]
stage="TCP"
try:
    s=socket.create_connection((ip,443),timeout=7)
    s.settimeout(7)
    stage="TLS"
    with ssl.create_default_context().wrap_socket(s,server_hostname=host) as t:
        stage="HTTP"
        t.sendall(("GET / HTTP/1.1\r\nHost: "+host+
          "\r\nUser-Agent: MNEBYDNS-ReadOnly-Research/1.0\r\n"+
          "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii"))
        received=t.recv(1024)
        m=re.match(rb"HTTP/1\.[01] ([1-5][0-9]{2})\b",received)
        if not m: raise RuntimeError("INVALID_HTTP_STATUS")
        print("HTTP_STATUS="+m.group(1).decode("ascii"))
except Exception as e:
    print("HTTP_PROBE_FAILED="+stage+":"+type(e).__name__)
    sys.exit(3)
'''

def inventory():
    lines = [x.strip() for x in CANDIDATES.read_text().splitlines()
             if x.strip() and not x.startswith("#")]
    with STRONG.open(newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["domain","ru_code","de_code","source_status","evidence"]:
            raise RuntimeError("Strong evidence file schema drift")
        strong = {row["domain"]:row for row in reader}
    if len(lines) != 108 or len(set(lines)) != 108 or len(strong)!=111:
        raise RuntimeError("Research inventory or duplicates changed; explicit re-review required")
    forbidden = {"chatgpt.com", "grok.com", "sentry.io"}
    if any(x in forbidden or x not in strong for x in lines):
        raise RuntimeError("Excluded/absent route included")
    for host in lines:
        if owner._render.validate_domain(host)!=host:
            raise ValueError("Unreviewed DNS name")
        entry=strong[host]
        if entry["ru_code"] not in ("403","451") or not (200<=int(entry["de_code"])<400):
            raise RuntimeError("Hostname has no recorded verified access difference")
        if entry["source_status"]!="PENDING_RESEARCH" or entry["evidence"]!="RU_403_451_DE_2XX_3XX":
            raise RuntimeError("Research evidence classification changed")
    return lines

def enabled():
    value = CONTROL.read_text().strip()
    if value not in ("enabled","disabled"):
        raise RuntimeError("Automation kill switch must be enabled or disabled")
    return value=="enabled"

def report(name, **data):
    OUTPUT.mkdir(exist_ok=True)
    record=dict(timestamp_utc=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                event=name,**data)
    with (OUTPUT/"events.jsonl").open("a") as stream:
        stream.write(json.dumps(record,sort_keys=True)+"\n")
    print("BATCH_EVENT="+name+" "+json.dumps(data,sort_keys=True),flush=True)

def db(query):
    return owner.sql(query).strip()

def ensure_quiet():
    ongoing=db("SELECT count(*) FROM dns_admin_domains WHERE status IN ("+
         ",".join("'"+s+"'" for s in BUSY)+")")
    if ongoing!="0":
        raise RuntimeError("OWNER_QUEUE_BUSY: defer to existing single-domain reconciler")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("LIVE_CHECKPOINT_DRIFT: defer until unrelated route pilot ends")

def capacity():
    command=(
        "set -Eeuo pipefail; "
        "systemctl is-active --quiet nginx; "
        "systemctl is-active --quiet mnebydns-dot.service; "
        "systemctl is-active --quiet mnebydns-googlepilot.service; "
        "systemctl is-active --quiet xray.service; "
        "nginx -t >/dev/null 2>&1; "
        "mem=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo); "
        "disk=$(df -Pk /opt/mnebydns-dot | awk 'NR==2 {print $4}'); "
        "[[ \"$mem\" =~ ^[0-9]+$ ]] && (( mem >= "+str(MIN_RAM_KB)+" )); "
        "[[ \"$disk\" =~ ^[0-9]+$ ]] && (( disk >= "+str(MIN_DISK_KB)+" )); "
        "echo CAPACITY_OK"
    )
    if owner.ssh("de",command,40).strip()!="CAPACITY_OK":
        raise RuntimeError("INSUFFICIENT_CAPACITY_OR_SERVICE_UNHEALTHY")

def table():
    raw=db("SELECT domain||'|'||status||'|'||coalesce(product,'')||'|'||"
           "coalesce(last_error_code,'') FROM dns_admin_domains ORDER BY domain")
    rows={}
    for line in raw.splitlines():
        parts=line.split("|")
        if len(parts)!=4:
            raise RuntimeError("Unexpected database domain inventory schema")
        domain,status,product,last_error=parts
        if domain in rows:
            raise RuntimeError("Non-unique domain database state")
        rows[domain]=(status,product,last_error)
    return rows

def preexisting_failure(rows, names):
    incidents=[h for h in names if h in rows and rows[h][1]==PRODUCT and rows[h][0]=="FAILED"
               and rows[h][2].startswith("BATCH_INCIDENT_")]
    if incidents:
        raise RuntimeError("BATCH_CIRCUIT_BREAKER_ACTIVE: "+",".join(incidents[:5]))

def select_next(names, rows):
    for host in names:
        if host not in rows:
            raise RuntimeError("RESEARCH_ROW_MISSING: "+host)
        status,product,_ = rows[host]
        if product!=PRODUCT:
            if status=="ACTIVE":
                continue  # Already active and owned by an earlier workflow; never touch it.
            raise RuntimeError("NON_RESEARCH_OWNER: "+host+" "+product)
        if status=="PENDING":
            return host
        if status not in ("ACTIVE", "FAILED"):
            raise RuntimeError("UNREVIEWED_DOMAIN_STATE: "+host+" "+status)
    return None

def status_of(host):
    host=owner._render.validate_domain(host)
    out=db("SELECT status FROM dns_admin_domains WHERE domain='"+host+
           "' AND product='"+PRODUCT+"'")
    if out not in ("PENDING","APPLY_REQUESTED","PROBING","CANARY","CONFIRM_REQUESTED",
                   "CONFIRMING","ACTIVE","CANCELLED","FAILED"):
        raise RuntimeError("Unexpected owner row state: "+host+"="+out)
    return out

def select_own_task(host, expected):
    item=owner.get_task()
    if item is None or item["domain"]!=host or item["status"]!=expected:
        raise RuntimeError("Different owner route claimed queue; refusing mutation")
    return item

def phase_id(i):
    base=os.environ.get("GITHUB_RUN_ID","")
    if not base.isdigit() or i not in range(1, MAX_PER_RUN+1):
        raise ValueError("Invalid run ID or batch step")
    seq=str(int(base)*10+i)
    if not re.fullmatch(r"[1-9][0-9]{8,12}",seq):
        raise ValueError("Independent canary id does not fit owner rollback layout")
    return seq

def set_phase(i):
    run=phase_id(i)
    owner.RUNID=run
    owner.WORK="/tmp/mnebydns-owner-domain-"+run
    return run

def http_probe(role, host, ip):
    # Original hostname and origin IP from protected source; no uncontrolled
    # shell data. The script checks TLS certificate against the original SNI.
    owner._render.validate_domain(host)
    if ip==owner.EDGE:
        if role!="ru":
            raise ValueError("Only RU-to-public-DE-edge test may use edge IP")
    else:
        owner._render.validated_public_ip(ip)
    script="python3 -c "+shlex.quote(HTTP_CODE)+" "+shlex.quote(host)+" "+shlex.quote(ip)
    raw=owner.ssh(role,script,45).strip()
    if not raw.startswith("HTTP_STATUS=") or not re.fullmatch(r"HTTP_STATUS=[1-5][0-9]{2}",raw):
        raise RuntimeError("No verifiable HTTPS status "+role+" "+host)
    return int(raw.rsplit("=",1)[1])

def preflight(host):
    # Resolver and origin TLS are *both* verified by the existing renderer,
    # executed from DE via SSH with its exact immutable public IP selection.
    code=(
        "import socket,ssl,ipaddress,sys; h=sys.argv[1];"
        "edge='89.125.90.101'; ru='188.120.254.223';"
        "ips=sorted({x[4][0] for x in socket.getaddrinfo(h,443,socket.AF_INET,socket.SOCK_STREAM)});"
        "found=None;"
        "\nfor ip in ips[:6]:"
        "\n try:"
        "\n  a=ipaddress.ip_address(ip)"
        "\n  if not a.is_global or ip in (edge,ru):continue"
        "\n  s=socket.create_connection((ip,443),timeout=5)"
        "\n  s.settimeout(5)"
        "\n  with ssl.create_default_context().wrap_socket(s,server_hostname=h) as t:"
        "\n   if t.getpeercert():found=ip;break"
        "\n except (OSError,ssl.SSLError):pass"
        "\nif not found:sys.exit(4)"
        "\nprint(found)"
    )
    raw=owner.ssh("de","python3 -c "+shlex.quote(code)+" "+shlex.quote(host),50).strip()
    ip=owner._render.validated_public_ip(raw)
    de=http_probe("de",host,ip)
    ru=http_probe("ru",host,ip)
    if not (200<=de<400 and ru in (403,451)):
        raise RuntimeError("STALE_DIFFERENTIAL (DE="+str(de)+" RU="+str(ru)+")")
    return ip, de, ru

def cas(host, from_state, to_state, update=""):
    if not re.fullmatch(r"[A-Z_]+",from_state) or not re.fullmatch(r"[A-Z_]+",to_state):
        raise ValueError("Invalid transition")
    host=owner._render.validate_domain(host)
    extra=","+update if update else ""
    changed=db("UPDATE dns_admin_domains SET status='"+to_state+
        "',revision=revision+1,updated_at=now()"+extra+
        " WHERE domain='"+host+"' AND product='"+PRODUCT+
        "' AND status='"+from_state+"' RETURNING domain")
    if changed!=host:
        raise RuntimeError("Database compare-and-swap rejected "+host+" "+from_state)

def fail_preflight(host,reason):
    # Explicit reason in DB prevents a permanently bad PENDING entry from
    # starving all other candidates. No DNS/Nginx changes on preflight failure.
    report("PRECHECK_SKIP",domain=host,reason=reason[:160])
    cas(host,"PENDING","FAILED","last_error_code='BATCH_PREFLIGHT_UNVERIFIED'")

def recover_failed_canary(host,run):
    state=status_of(host)
    # If promotion succeeded, a timer must NOT restore an older checkpoint.
    # Stop the automation for manual review rather than claim rollback.
    if state in ("ACTIVE","CONFIRM_REQUESTED","CONFIRMING"):
        report("INCIDENT_MANUAL_RECONCILIATION",domain=host,state=state)
        raise RuntimeError("BATCH_INCIDENT_CONFIRM_STATE_UNCERTAIN")
    if state in ("CANARY","PROBING","APPLY_REQUESTED"):
        owner.rollback_or_unchanged(run)
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("BATCH_INCIDENT_ROLLBACK_BASELINE_INVALID")
        owner.oracle_canary_check(host,False)
        host=owner._render.validate_domain(host)
        done=db("UPDATE dns_admin_domains SET status='FAILED',"
           "last_error_code='BATCH_INCIDENT_CANARY_ABORT',"
           "canary_expires_at=NULL,updated_at=now() "
           "WHERE domain='"+host+"' AND product='"+PRODUCT+
           "' AND status IN ('CANARY','PROBING','APPLY_REQUESTED') RETURNING domain")
        if done!=host:
            raise RuntimeError("BATCH_INCIDENT_ROLLBACK_DB_NOT_COMMITTED")
        report("CANARY_ROLLED_BACK",domain=host)
    elif state=="FAILED":
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("BATCH_INCIDENT_FAILED_BUT_BASELINE_DRIFT")
        db("UPDATE dns_admin_domains SET last_error_code='BATCH_INCIDENT_CANARY_ABORT' "
           "WHERE domain='"+host+"' AND product='"+PRODUCT+"' AND status='FAILED'")
        report("CANARY_FAILED_SAFE",domain=host)
    else:
        raise RuntimeError("BATCH_INCIDENT_UNRECOGNIZED_FAILURE_STATE="+state)

def run_one(host, index):
    ensure_quiet()
    capacity()
    set_phase(index)
    report("PRECHECK_STARTED",domain=host)
    try:
        origin,de,ru=preflight(host)
    except RuntimeError as ex:
        if str(ex).startswith("STALE_DIFFERENTIAL"):
            fail_preflight(host,"STALE_DIFFERENTIAL")
            return False
        report("PRECHECK_INFRA_ERROR",domain=host,error_type=type(ex).__name__)
        raise  # Network or SSH errors must NOT permanently reject the hostname.
    except Exception as ex:
        report("PRECHECK_INFRA_ERROR",domain=host,error_type=type(ex).__name__)
        raise
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("LIVE_CHANGED_AFTER_PRECHECK")
    ensure_quiet()
    report("PRECHECK_OK",domain=host,foreign_http=de,russian_http=ru,origin_ipv4=origin)
    cas(host,"PENDING","APPLY_REQUESTED","canary_run_id=NULL,canary_expires_at=NULL,last_error_code=NULL")
    try:
        owner.apply(select_own_task(host,"APPLY_REQUESTED"))
        if status_of(host)!="CANARY":
            raise RuntimeError("CANDIDATE_NOT_CANARY")
        pinned=db("SELECT coalesce(verified_origin_ip::text,'') FROM dns_admin_domains "
                  "WHERE domain='"+host+"' AND product='"+PRODUCT+"' AND status='CANARY'")
        if pinned!=origin:
            raise RuntimeError("CANDIDATE_CHANGED_ORIGIN_IP")
        # Real public RU->DE SNI route, not foreign localhost; strict TLS CA.
        through_edge=http_probe("ru",host,owner.EDGE)
        if not 200<=through_edge<400:
            raise RuntimeError("PUBLIC_EDGE_HTTPS_NOT_SUCCESSFUL status="+str(through_edge))
        # Native tests include all five stable DoT products and excluded
        # Instagram / Telegram records; now check a second time.
        owner.oracle_canary_check(host,True)
        capacity()
        report("PUBLIC_EDGE_CANARY_OK",domain=host,ru_through_de_http=through_edge)
        cas(host,"CANARY","CONFIRM_REQUESTED")
        owner.confirm(select_own_task(host,"CONFIRM_REQUESTED"))
        if status_of(host)!="ACTIVE" or not owner.live_checkpoint_unchanged():
            raise RuntimeError("CONFIRMED_ROUTE_NOT_STABLE")
        report("ACTIVE",domain=host,origin_ipv4=origin,ru_through_de_http=through_edge)
        return True
    except Exception as ex:
        report("CANARY_ERROR",domain=host,error_type=type(ex).__name__,state=status_of(host))
        recover_failed_canary(host,owner.RUNID)
        raise

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("mode",choices=("self-test","plan","deploy"))
    parser.add_argument("--max",type=int,default=1)
    args=parser.parse_args()
    names=inventory()
    if args.mode=="self-test":
        assert len(names)==108 and len(set(names))==108
        assert {"chatgpt.com","grok.com","sentry.io"}.isdisjoint(names)
        assert re.fullmatch(r"HTTP_STATUS=[1-5][0-9]{2}","HTTP_STATUS=403")
        assert not re.fullmatch(r"HTTP_STATUS=[1-5][0-9]{2}","HTTP_PROBE_FAILED=TLS:SSLError")
        assert enabled() in (True,False)
        print("BATCH_108_OFFLINE_VALIDATION=PASS")
        return
    if args.max<1 or args.max>MAX_PER_RUN:
        raise ValueError("Up to five independent canary transitions per run")
    if os.environ.get("GITHUB_REF")!="refs/heads/main":
        raise RuntimeError("No batch server access outside reviewed main")
    if args.mode=="deploy" and os.environ.get("GITHUB_EVENT_NAME")=="schedule" and not enabled():
        report("AUTOMATION_DISABLED")
        return
    if args.mode=="deploy" and os.environ.get("GITHUB_EVENT_NAME") not in ("workflow_dispatch","schedule"):
        raise RuntimeError("Deployment must be explicitly dispatched or scheduled after enable")
    rows=table()
    preexisting_failure(rows,names)
    next_host=select_next(names,rows)
    report("PLAN",candidate_count=len(names),remaining=sum(
        rows.get(n,("", "", ""))[0]=="PENDING" for n in names),next=next_host)
    if args.mode=="plan" or not next_host:
        return
    ensure_quiet()
    capacity()
    changed=0
    skipped=0
    for idx in range(1,args.max+1):
        rows=table()
        preexisting_failure(rows,names)
        host=select_next(names,rows)
        if host is None:break
        if run_one(host,idx):
            changed+=1
        else:
            skipped+=1
    report("WAVE_FINISHED",active=changed,precheck_skipped=skipped,requested=args.max)

if __name__=="__main__":
    main()
