#!/usr/bin/env python3
"""Read-only mass health screen of existing exact SmartDNS HTTPS routes.

Selects the actual live public Nginx pinned origin for each owner exact host,
cross-checks CoreDNS and canonical RU SQL state, probes original SNI with
verified TLS direct on DE and through DE public edge from RU. No client data,
no SQL updates, no route changes, and no forced CDN repinning.
"""
from __future__ import annotations
import base64
from collections import Counter
import datetime as dt
import importlib.util
import json
import re
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/"active-route-health"
OWNER=ROOT/"scripts/mnebydns-owner-domain-controller-20261110.py"
spec=importlib.util.spec_from_file_location("active_health_owner",OWNER)
assert spec and spec.loader
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)

REMOTE_CODE=r"""
import concurrent.futures,base64,json,re,socket,ssl,sys,time
mode=sys.argv[1]
entries=json.loads(base64.b64decode(sys.argv[2],validate=True))
if not isinstance(entries,list) or len(entries)>200:raise ValueError('invalid test batch')
ctx=ssl.create_default_context()
ctx.set_alpn_protocols(['http/1.1'])
def one(entry):
    host,ip=entry['domain'],entry['pinned_ip']
    try:
        start=time.monotonic()
        target=ip if mode=='origin' else '89.125.90.101'
        with socket.create_connection((target,443),timeout=5) as sock:
            sock.settimeout(6)
            tcp_ms=(time.monotonic()-start)*1000
            with ctx.wrap_socket(sock,server_hostname=host) as tls:
                tls_ms=(time.monotonic()-start)*1000
                if not tls.getpeercert():raise RuntimeError('missing_tls_certificate')
                tls.sendall(('GET / HTTP/1.1\r\nHost: '+host+'\r\n'
                             'User-Agent: MNEBYDNS-Readonly-Health/1.0\r\n'
                             'Connection: close\r\n\r\n').encode('ascii'))
                head=tls.recv(160)
                m=re.match(rb'HTTP/1\.[01] ([1-5][0-9]{2})\b',head)
                return {'domain':host,'tls_ok':True,'http':int(m.group(1)) if m else None,
                        'tcp_ms':round(tcp_ms,1),'tls_ms':round(tls_ms-tcp_ms,1),
                        'first_byte_ms':round((time.monotonic()-start)*1000,1),
                        'error':None}
    except Exception as ex:
        return {'domain':host,'tls_ok':False,'http':None,'error':type(ex).__name__}
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    for item in pool.map(one,entries):
        print(json.dumps(item,separators=(',',':')))
"""

def rows():
    q="SELECT domain||'|'||status||'|'||coalesce(product,'')||'|'||coalesce(verified_origin_ip::text,'') FROM dns_admin_domains ORDER BY domain"
    result={}
    for line in owner.sql(q).splitlines():
        parts=line.split("|")
        if len(parts)!=4:raise RuntimeError("Invalid DB owner inventory")
        host,state,product,ip=parts
        host=owner._render.validate_domain(host)
        if host in result:raise RuntimeError("Duplicate DB host")
        result[host]={"status":state,"product":product,"pinned_db_ip":ip}
    return result

def marks(text):
    raw=re.findall(r"(?m)^\s*# BEGIN MNEBYDNS_OWNER_EXACT_([a-z0-9_]+)\s*$",text)
    names=[owner._render.validate_domain(x.replace("_",".")) for x in raw]
    if len(names)!=len(set(names)):raise RuntimeError("Duplicate CoreDNS or Nginx owner mark")
    return set(names)

def pins(nginx,names):
    data=[]
    for host in sorted(names):
        regexp=r"(?m)^\s*"+re.escape(host)+r"\s+(\d+(?:\.\d+){3}):443;\s*$"
        vals=re.findall(regexp,nginx)
        if len(vals)!=1:
            data.append({"domain":host,"reason":"ORIGIN_PIN_MISSING_OR_AMBIGUOUS"})
            continue
        try:
            ip=owner._render.validated_public_ip(vals[0])
            data.append({"domain":host,"pinned_ip":ip})
        except ValueError:
            data.append({"domain":host,"reason":"INVALID_PIN_IP"})
    return data

def remote(role,mode,items):
    if role not in ("de","ru") or mode not in ("origin","edge"):
        raise ValueError("Remote role or mode invalid")
    secret = __import__("os").environ.get("DE_PASS" if role=="de" else "RU_PASS")
    if not secret:raise RuntimeError("Missing pinned SSH auth")
    import os,subprocess
    token=base64.b64encode(json.dumps(items).encode()).decode()
    env=os.environ.copy(); env["SSHPASS"]=secret
    cmd=["sshpass","-e","ssh","-T","-o","ConnectTimeout=12",
         *owner.SSH_TRUST,"-o","LogLevel=ERROR",
         "root@"+(owner.EDGE if role=="de" else owner.RU),
         "python3","-",mode,token]
    proc=subprocess.run(cmd,input=REMOTE_CODE.encode(),capture_output=True,env=env,timeout=180)
    if proc.returncode:
        raise RuntimeError("Remote TLS check failed role="+role+" exit="+str(proc.returncode)
                           +": "+proc.stderr.decode("utf-8","replace")[-150:])
    reply=[json.loads(x) for x in proc.stdout.decode().splitlines()]
    if len(reply)!=len(items) or [i["domain"] for i in reply]!=[i["domain"] for i in items]:
        raise RuntimeError("Missing/duplicate remote host results")
    return reply

def self_test():
    sample="# BEGIN MNEBYDNS_OWNER_EXACT_codebrowser_dev\n# END MNEBYDNS_OWNER_EXACT_codebrowser_dev\n"
    assert marks(sample)=={"codebrowser.dev"}
    test="codebrowser.dev 136.243.59.253:443;\n"
    assert pins(test,["codebrowser.dev"])==[{"domain":"codebrowser.dev","pinned_ip":"136.243.59.253"}]
    print("ACTIVE_ROUTE_HEALTH_OFFLINE=PASS")

def run():
    if not owner.live_checkpoint_unchanged():raise RuntimeError("Stable route checkpoint changed")
    db=rows()
    core=owner.ssh("de","cat /opt/mnebydns-dot/Corefile",40)
    nginx=owner.ssh("de","cat /etc/nginx/nginx.conf",40)
    a,b=marks(core),marks(nginx)
    matched=a & b
    misaligned=sorted(a ^ b)
    candidates=pins(nginx,matched)
    valid=[x for x in candidates if "pinned_ip" in x]
    local_missing=[x for x in candidates if "reason" in x]
    nonactive=[{"domain":h,"state":db[h]["status"] if h in db else "MISSING_IN_DB"}
               for h in matched if db.get(h,{}).get("status")!="ACTIVE"]
    # Test only the existing exact owner routes, no new DNS names or wildcard discovery.
    origin=remote("de","origin",valid)
    edge=remote("ru","edge",valid)
    matched_results=[]
    for ent,d,e in zip(valid,origin,edge):
        classified="OK" if d["tls_ok"] and e["tls_ok"] else "UNSTABLE"
        matched_results.append({
            "domain":ent["domain"],"db_status":db.get(ent["domain"],{}).get("status","MISSING"),
            "origin_ip":ent["pinned_ip"],"direct_de":d,"ru_via_de":e,
            "status":classified})
    response={
        "timestamp_utc":dt.datetime.now(dt.timezone.utc).isoformat(),
        "note":"read-only; exact hostname TLS with trusted CA; HTTP / only; no phone app coverage",
        "active_db_count":sum(x["status"]=="ACTIVE" for x in db.values()),
        "core_owner_markers":len(a),"nginx_owner_markers":len(b),
        "unmatched_markers":misaligned,
        "orphan_or_pending_markers":sorted(nonactive,key=lambda x:x["domain"]),
        "invalid_or_missing_origin":local_missing,
        "tested":len(matched_results),
        "route_probe_errors":[x for x in matched_results if x["status"]!="OK"],
        "routes":matched_results}
    OUT.mkdir(mode=0o700,exist_ok=True)
    (OUT/"metrics.json").write_text(json.dumps(response,ensure_ascii=False,indent=2)+"\n")
    lines=["# Smart DNS all exact-route TLS health (read only)","",
           "Time: "+response["timestamp_utc"],"",
           f"DB ACTIVE all products: {response['active_db_count']}",
           f"Core owner markers: {len(a)}; Nginx owner markers: {len(b)}; both: {len(matched)}",
           f"Tested with valid fixed origin: {len(valid)}",
           f"Failed trusted TLS to origin or public RU->DE: {len(response['route_probe_errors'])}",
           f"Non-ACTIVE/missing DB rows with live route markers: {len(nonactive)}",
           "",
           "| Domain | DE origin TLS | RU via DE TLS | DE HTTP | RU HTTP | RU first byte ms |",
           "|---|---|---|---:|---:|---:|"]
    for row in matched_results:
        d,e=row["direct_de"],row["ru_via_de"]
        lines.append(f"| {row['domain']} | {d['tls_ok']} | {e['tls_ok']} | "
                     f"{d['http']} | {e['http']} | {e.get('first_byte_ms')} |")
    (OUT/"report.md").write_text("\n".join(lines)+"\n")
    print("ACTIVE_ROUTE_READONLY_SUMMARY="+json.dumps({
        "active_db":response["active_db_count"],
        "tested":response["tested"],
        "tls_failures":len(response["route_probe_errors"]),
        "unmatched_markers":len(misaligned),
        "orphan_or_pending":len(nonactive),
        "invalid_pins":len(local_missing)},sort_keys=True),flush=True)
    print("ACTIVE_ROUTE_ERRORS="+json.dumps([
        {"domain":x["domain"],"de_error":x["direct_de"]["error"],
         "ru_error":x["ru_via_de"]["error"]} for x in response["route_probe_errors"]
    ],sort_keys=True),flush=True)
    print("ACTIVE_ROUTE_READONLY_DONE=true",flush=True)

if __name__=="__main__":
    if sys.argv[1:]==["--self-test"]:self_test()
    elif sys.argv[1:]==["--run"]:run()
    else:raise SystemExit("usage: --self-test|--run")
