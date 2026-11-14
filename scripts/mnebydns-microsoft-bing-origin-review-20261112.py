#!/usr/bin/env python3
"""Read-only origin and stable Smart DNS state diagnostic for Bing/Microsoft.

Does not install, stage, confirm, remove, reload or edit a route.
Designed to distinguish origin TLS failure, DNS resolver mismatch, route
collision, and a stale owner request, before any further Microsoft rollout.
"""
from __future__ import annotations
import importlib.util
import os
import pathlib
import re
import shlex
import sys

ROOT=pathlib.Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("microsoft_diagnose_owner",ROOT/"mnebydns-owner-domain-controller-20261110.py")
assert SPEC and SPEC.loader
owner=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owner)
HOSTS=("bing.com","microsoft.com")

# Runs read-only on the existing DE and RU servers. No credentials, cookies,
# redirects, TLS bypass or body downloads. TLS SNI and HTTP Host are original.
REMOTE=r'''
import ipaddress,os,re,socket,ssl,sys
names=('bing.com','microsoft.com')
def check(name):
    try:
        addresses=sorted({i[4][0] for i in socket.getaddrinfo(name,443,socket.AF_INET,socket.SOCK_STREAM)})
        addresses=[ip for ip in addresses if ipaddress.ip_address(ip).is_global
                   and ip not in ('89.125.90.101','188.120.254.223')]
        print('origin_dns='+name+'|'+(','.join(addresses) or 'NO_PUBLIC_IPV4'),flush=True)
    except Exception as err:
        print('origin_dns='+name+'|ERROR_'+type(err).__name__,flush=True)
        return
    ctx=ssl.create_default_context()
    ctx.set_alpn_protocols(['http/1.1'])
    for ip in addresses[:4]:
        try:
            with socket.create_connection((ip,443),timeout=5) as raw:
                raw.settimeout(5)
                with ctx.wrap_socket(raw,server_hostname=name) as tls:
                    if not tls.getpeercert():raise RuntimeError('NO_VERIFIED_CERT')
                    tls.sendall(('GET / HTTP/1.1\r\nHost: '+name+
                      '\r\nUser-Agent: MNEBYDNS-Owner-Route-QA/1.0\r\nConnection: close\r\n\r\n').encode())
                    data=tls.recv(256)
                    found=re.match(rb'HTTP/1\.[01] ([1-5]\d{2})\b',data)
                    status=found.group(1).decode() if found else 'NON_HTTP'
                    print('origin_tls='+name+'|'+ip+'|CERT_VALID|HTTP_'+status,flush=True)
        except Exception as err:
            print('origin_tls='+name+'|'+ip+'|'+type(err).__name__,flush=True)
for host in names:check(host)
'''
DE_STATE=r'''
from pathlib import Path
import re
hosts=('bing.com','microsoft.com')
root=Path('/opt/mnebydns-stable-checkpoints/current').read_text().strip()
ok=re.fullmatch(r'/opt/mnebydns-stable-checkpoints/\d+',root) is not None
print('checkpoint_path_format_ok='+str(ok),flush=True)
if not ok:raise ValueError('invalid checkpoint pointer')
cp=Path(root)
for kind,live in (('dns','/opt/mnebydns-dot/Corefile'),
                  ('nginx','/etc/nginx/nginx.conf'),
                  ('proxy','/etc/mnebydns-googlepilot/nginx.conf')):
    source=Path(live).read_bytes()
    stable=(cp/(kind+'.stable')).read_bytes()
    print('checkpoint_'+kind+'_matches_live='+str(source==stable),flush=True)
dns=Path('/opt/mnebydns-dot/Corefile').read_text()
nginx=Path('/etc/nginx/nginx.conf').read_text()
for host in hosts:
    marker='MNEBYDNS_OWNER_EXACT_'+host.replace('.','_')
    print('route='+host+'|core_marker='+str(marker in dns)+
          '|nginx_marker='+str(marker in nginx),flush=True)
    # Nearby stream map declarations and CoreDNS rules can collide. Rather
    # than dumping huge configs, count tokenized exact hostname mentions.
    exact=r'(?<![A-Za-z0-9.-])'+re.escape(host)+r'(?![A-Za-z0-9.-])'
    print('mentions='+host+'|core='+str(len(re.findall(exact,dns)))+
          '|nginx='+str(len(re.findall(exact,nginx))),flush=True)
'''
def checked_host(label):
    if label not in ("de","ru"):raise ValueError("invalid region")
    print("REGION_BEGIN="+label,flush=True)
    raw=owner.ssh(label,"python3 -c "+shlex.quote(REMOTE),125)
    print(raw,flush=True)
    print("REGION_END="+label,flush=True)

def live():
    print("MICROSOFT_ORIGIN_REVIEW=READ_ONLY",flush=True)
    for host in HOSTS:owner._render.validate_domain(host)
    raw=owner.sql(
      "SELECT domain||'|'||status||'|'||product||'|'||"
      "coalesce(last_error_code,'none')||'|'||"
      "coalesce(canary_run_id::text,'none')||'|'||"
      "coalesce(verified_origin_ip::text,'none')"
      " FROM dns_admin_domains WHERE domain IN ('bing.com','microsoft.com')"
      " ORDER BY domain"
    )
    print("MICROSOFT_DB_BEGIN",flush=True)
    print(raw,flush=True)
    print("MICROSOFT_DB_END",flush=True)
    blocked=owner.sql("SELECT domain||'|'||status FROM dns_admin_domains WHERE status IN "
       "('APPLY_REQUESTED','PROBING','CANARY','CONFIRM_REQUESTED','CONFIRMING',"
       "'ROLLBACK_REQUESTED','REMOVAL_PENDING','REMOVING') ORDER BY domain LIMIT 12")
    print("MICROSOFT_BUSY_OWNER_QUEUE="+(blocked.replace("\n","; ") or "empty"),flush=True)
    print("MICROSOFT_BASELINE_MATCH="+str(owner.live_checkpoint_unchanged()),flush=True)
    print("DE_STATE_BEGIN",flush=True)
    print(owner.ssh("de","python3 -c "+shlex.quote(DE_STATE),40),flush=True)
    print("DE_STATE_END",flush=True)
    checked_host("de")
    checked_host("ru")
    print("MICROSOFT_DIAGNOSIS_FINISHED_NO_MUTATIONS=true",flush=True)

def selftest():
    assert HOSTS==("bing.com","microsoft.com")
    assert "ssl.create_default_context" in REMOTE
    assert "GET / HTTP/1.1" in REMOTE
    assert "cookie" not in REMOTE.lower()
    assert "nginx -s reload" not in DE_STATE
    assert "UPDATE dns_admin_domains" not in REMOTE+DE_STATE
    print("MICROSOFT_ORIGIN_OFFLINE=PASS",flush=True)

if __name__=="__main__":
    if sys.argv[1:]==["self-test"]:selftest()
    elif sys.argv[1:]==["diagnose"]:live()
    else:raise SystemExit("Usage: self-test | diagnose")
