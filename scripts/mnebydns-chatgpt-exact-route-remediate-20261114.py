#!/usr/bin/env python3
"""Two exact ChatGPT SmartDNS routes using the established guarded owner controller.

No new DNS address, no proxy listener, no wildcard/origin-guessing, no IPv6.
Each additive change is individually canaried and committed to the EXISTING
stable checkpoint, preserving future owner route reconciliation. Never print
credentials or modify the subscriber DNS policy or quota database.
"""
from __future__ import annotations
import argparse
import datetime as dt
import importlib.util
import os
from pathlib import Path
import re
import shlex
import sys

ROOT=Path(__file__).resolve().parent.parent
CONTROLLER=ROOT/"scripts/mnebydns-owner-domain-controller-20261110.py"
spec=importlib.util.spec_from_file_location("owner_existing",CONTROLLER)
assert spec and spec.loader
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)

HOSTS=("chatgpt.com","auth.openai.com")
TRANSFER=(
    "mnebydns-owner-domain-render-20261110.py",
    "mnebydns-dot-config-change-20261111.sh",
    "mnebydns-owner-domain-stage-20261110.sh",
    "mnebydns-owner-domain-rollback-20261110.sh",
    "mnebydns-owner-domain-confirm-20261110.sh",
)

def safe_id(runid:str,index:int)->str:
    if not re.fullmatch(r"[1-9][0-9]{8,11}",runid):raise ValueError("Invalid run ID")
    derived=str(int(runid)*10+index)
    if not re.fullmatch(r"[1-9][0-9]{8,12}",derived):
        raise ValueError("Invalid stage identifier")
    return derived

def guard_current():
    script="""set -Eeuo pipefail
    current="$(cat /opt/mnebydns-stable-checkpoints/current)"
    [[ "$current" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]]
    (cd "$current" && sha256sum -c stable-manifest.sha256 >/dev/null)
    cmp -s "$current/dns.stable" /opt/mnebydns-dot/Corefile
    cmp -s "$current/nginx.stable" /etc/nginx/nginx.conf
    cmp -s "$current/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
    for unit in nginx mnebydns-dot.service mnebydns-googlepilot.service xray.service; do
      systemctl is-active --quiet "$unit"
    done
    nginx -t >/dev/null 2>&1
    grep -Fxq '    reload 5s 1s' /opt/mnebydns-dot/Corefile
    echo EXACT_CHATGPT_CHECKPOINT_AND_SERVICES=PASS
    """
    out=owner.ssh("de","bash -se <<'GUARD'\n"+script+"\nGUARD",90)
    if "EXACT_CHATGPT_CHECKPOINT_AND_SERVICES=PASS" not in out:
        raise RuntimeError("DE checkpoint drift")
    print("EXACT_CHATGPT_CHECKPOINT_AND_SERVICES=PASS",flush=True)

def stage_files(identifier:str)->str:
    work="/tmp/mnebydns-owner-domain-"+identifier
    owner.ssh("de","test ! -e "+shlex.quote(work)+
              " && mkdir -m 700 "+shlex.quote(work),50)
    for file in TRANSFER:
        source=ROOT/"scripts"/file
        assert source.is_file()
        owner.cmd(["sshpass","-e","scp","-q","-o","ConnectTimeout=12",
                   *owner.SSH_TRUST,"-o","LogLevel=ERROR",
                   str(source),"root@"+owner.EDGE+":"+work+"/"+file],
                  os.environ["DE_PASS"],timeout=75)
    return work

def remediate_one(host:str,identifier:str)->None:
    assert host in HOSTS
    guard_current()
    work=stage_files(identifier)
    base="/opt/mnebydns-owner-domain/"+identifier
    renderer=work+"/mnebydns-owner-domain-render-20261110.py"
    owner.ssh("de","python3 "+shlex.quote(renderer)+" self-test",35)
    origin=owner.ssh("de","python3 "+shlex.quote(renderer)+
                     " probe --domain "+shlex.quote(host),90).strip()
    if owner._render.validated_public_ip(origin)!=origin:
        raise RuntimeError("Origin IPv4 safety check failed")
    print("CHATGPT_ROUTE_"+host.replace(".","_").upper()+
          "_ORIGIN_TLS_VERIFIED=true",flush=True)
    deadline=(dt.datetime.now(dt.timezone.utc)+
              dt.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S UTC")
    stage="bash "+shlex.quote(work+"/mnebydns-owner-domain-stage-20261110.sh")+" "+" ".join(
        shlex.quote(x) for x in (work,identifier,host,origin,deadline))
    staged=False
    confirmed=False
    try:
        result=owner.ssh("de",stage,200)
        if "owner_domain_DNS_nginx_canary_active=true" not in result:
            raise RuntimeError("Owner route stage was not accepted")
        staged=True
        # Public DNS check validates A, AAAA, CNAME, HTTPS, SVCB, current
        # stable premium services and ordinary/direct-only controls.
        owner.oracle_canary_check(host,True)
        # The Russian vantage validates the real DE:443 TLS proxy SNI path.
        owner.tls_public_route(host)
        guard_current_candidate=" && ".join([
            "test -s "+shlex.quote(base+"/dns.pilot"),
            "test -s "+shlex.quote(base+"/nginx.pilot"),
            "cmp -s "+shlex.quote(base+"/dns.pilot")+" /opt/mnebydns-dot/Corefile",
            "cmp -s "+shlex.quote(base+"/nginx.pilot")+" /etc/nginx/nginx.conf",
        ])
        owner.ssh("de",guard_current_candidate,40)
        confirm=owner.ssh("de","bash "+shlex.quote(base+"/confirm.sh")+" "+
                           shlex.quote(base),100)
        if ("owner_domain_confirmed_stable=true" not in confirm and
            "owner_domain_already_confirmed=true" not in confirm):
            raise RuntimeError("Guarded stable checkpoint not confirmed")
        confirmed=True
        print("CHATGPT_ROUTE_"+host.replace(".","_").upper()+"=COMMITTED",flush=True)
    finally:
        if staged and not confirmed:
            try:
                response=owner.ssh("de","bash "+shlex.quote(base+"/rollback.sh")+" "+
                                    shlex.quote(base),110)
                print("CHATGPT_ROUTE_"+host.replace(".","_").upper()+
                      "_UNCONFIRMED_ROLLBACK_ATTEMPTED=true",flush=True)
            except Exception as e:
                print("CHATGPT_ROUTE_ROLLBACK_ERROR_CLASS="+type(e).__name__,flush=True)
                raise

def run():
    runid=os.environ.get("GITHUB_RUN_ID","")
    if not all((os.environ.get("RU_PASS"),os.environ.get("DE_PASS"))):
        raise RuntimeError("Production SSH secrets unavailable")
    identities=[safe_id(runid,i) for i in (1,2)]
    for host in HOSTS:owner._render.validate_domain(host)
    guard_current()
    for host,identifier in zip(HOSTS,identities):
        remediate_one(host,identifier)
    guard_current()
    for host in HOSTS:owner.oracle_canary_check(host,True)
    print("CHATGPT_TWO_EXACT_DOMAINS_MAPPED_AND_BILLED_ROUTES_VERIFIED=true",flush=True)

def self_test():
    assert safe_id("43581624878",1)=="435816248781"
    assert safe_id("43581624878",2)=="435816248782"
    assert HOSTS==("chatgpt.com","auth.openai.com")
    owner._render.self_test()
    print("CHATGPT_TWO_EXACT_ROUTE_OFFLINE=PASS",flush=True)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("command",choices=("self-test","deploy"))
    a=p.parse_args()
    if a.command=="self-test":self_test()
    else:run()
