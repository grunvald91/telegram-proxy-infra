#!/usr/bin/env python3
"""One-at-a-time owner Telegram DNS route reconciler via separately guarded Actions.

Only the canonical private DB on RU can authorize an exact hostname.
The bot has no SSH credentials, GitHub token or permission to edit CoreDNS.
Root SSH secrets exist only in the CI job. No arbitrary SQL or shell values.
"""
from __future__ import annotations
import datetime as dt
import os
import re
import shlex
import socket
import ssl
import struct
import subprocess
import sys
import time
import importlib.util
from pathlib import Path

RUNID=os.environ.get("GITHUB_RUN_ID","")
REPO=Path(__file__).resolve().parent
RENDER=REPO/"mnebydns-owner-domain-render-20261110.py"
_spec=importlib.util.spec_from_file_location("dns_owner_renderer",RENDER)
if not _spec or not _spec.loader:raise RuntimeError("Missing verified renderer")
_render=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_render)
EDGE="89.125.90.101"
RU="188.120.254.223"
BASE="/opt/mnebydns-owner-domain"
WORK="/tmp/mnebydns-owner-domain-"+RUNID
FILES=(
    "mnebydns-owner-domain-render-20261110.py",
    "mnebydns-owner-domain-stage-20261110.sh",
    "mnebydns-owner-domain-rollback-20261110.sh",
    "mnebydns-owner-domain-confirm-20261110.sh",
)
TIMEOUT=90


def cmd(args:list[str], password:str|None=None, timeout=TIMEOUT,
        input_bytes:bytes|None=None)->str:
    env=os.environ.copy()
    if password is not None:
        env["SSHPASS"]=password
    out=subprocess.run(args,env=env,input=input_bytes,capture_output=True,
                       timeout=timeout)
    if out.returncode:
        raise RuntimeError("remote command failed: code "+str(out.returncode)+
                           ", stderr tail "+out.stderr.decode("utf8","replace")[-900:])
    return out.stdout.decode("utf8","replace").strip()


def ssh(role:str,command:str,timeout=TIMEOUT)->str:
    if role not in ("ru","de"):raise ValueError("Invalid server")
    host=RU if role=="ru" else EDGE
    key="RU_PASS" if role=="ru" else "DE_PASS"
    password=os.environ.get(key)
    if not password:raise RuntimeError("Missing SSH credential")
    return cmd(["sshpass","-e","ssh","-o","ConnectTimeout=12",
                "-o","StrictHostKeyChecking=accept-new","-o","LogLevel=ERROR",
                "root@"+host,command],password,timeout)


def transfer_to_de()->None:
    ssh("de","test ! -e "+shlex.quote(WORK)+" && mkdir -m 700 "+shlex.quote(WORK))
    for file in FILES:
        pwd=os.environ["DE_PASS"]
        cmd(["sshpass","-e","scp","-q","-o","ConnectTimeout=12",
             "-o","StrictHostKeyChecking=accept-new","-o","LogLevel=ERROR",
             str(REPO/file),"root@"+EDGE+":"+WORK+"/"+file],pwd)
    print("owner_domain_verified_scripts_transferred=true",flush=True)


def sql(query:str)->str:
    # Only internally generated SQL containing checked integer identifiers
    # is accepted. PostgreSQL never sees arbitrary user-authored SQL.
    return ssh("ru", "docker exec mnebyvpn-stage-postgres psql -v ON_ERROR_STOP=1 -At "
               "-U mnebyvpn_stage -d mnebyvpn_stage -c "+shlex.quote(query),45)


def one(sql_query:str)->str:
    return sql(sql_query).splitlines()[0] if sql(sql_query).splitlines() else ""


def get_task():
    query=(
        "SELECT id||'|'||domain||'|'||status||'|'||revision||'|'||"
        "coalesce(canary_run_id::text,'')||'|'||"
        "coalesce(extract(epoch from canary_expires_at)::bigint::text,'')||'|'||"
        "coalesce(extract(epoch from updated_at)::bigint::text,'')"
        " FROM dns_admin_domains"
        " WHERE status IN ('APPLY_REQUESTED','PROBING','CONFIRM_REQUESTED',"
        "'ROLLBACK_REQUESTED','REMOVAL_PENDING','CANARY')"
        " ORDER BY CASE status WHEN 'ROLLBACK_REQUESTED' THEN 0"
        " WHEN 'CONFIRM_REQUESTED' THEN 1 WHEN 'REMOVAL_PENDING' THEN 2"
        " WHEN 'PROBING' THEN 3 WHEN 'APPLY_REQUESTED' THEN 4 ELSE 5 END,"
        " updated_at,id LIMIT 1"
    )
    raw=sql(query).strip()
    if not raw:return None
    parts=raw.split("|")
    if len(parts)!=7:raise ValueError("Unexpected domain queue format")
    item=dict(zip(("id","domain","status","revision","run","expires","updated"),parts))
    if not re.fullmatch(r"[1-9][0-9]{0,14}",item["id"]) or \
       not re.fullmatch(r"[1-9][0-9]{0,14}",item["revision"]):
        raise ValueError("Unsafe queue identifier")
    _render.validate_domain(item["domain"])
    if item["run"] and not re.fullmatch(r"[1-9][0-9]{8,12}",item["run"]):
        raise ValueError("Invalid stored canary ID")
    return item


def dns_q(host:str,kind=1)->tuple[int,list[str]]:
    labels=host.split(".")
    wire=b"".join(bytes([len(x)])+x.encode("ascii") for x in labels)+b"\0"
    qid=int.from_bytes(os.urandom(2),"big")
    packet=struct.pack("!HHHHHH",qid,0x100,1,0,0,0)+wire+struct.pack("!HH",kind,1)
    with socket.create_connection((EDGE,853),timeout=9) as tcp:
        tcp.settimeout(9)
        with ssl.create_default_context().wrap_socket(tcp,server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(len(packet).to_bytes(2,"big")+packet)
            head=tls.recv(2)
            if len(head)!=2:raise RuntimeError("No DoT length prefix")
            size=int.from_bytes(head,"big")
            if size<12 or size>4096:raise RuntimeError("Invalid DoT response size")
            buf=bytearray()
            while len(buf)<size:
                chunk=tls.recv(size-len(buf))
                if not chunk:raise RuntimeError("DoT truncated")
                buf.extend(chunk)
    if int.from_bytes(buf[:2],"big")!=qid:raise RuntimeError("DoT ID mismatch")
    rcode=buf[3]&15
    qd=int.from_bytes(buf[4:6],"big")
    an=int.from_bytes(buf[6:8],"big")
    pos=12
    def skip_name(p):
        for _ in range(128):
            if p>=len(buf):raise ValueError("Malformed DNS name")
            n=buf[p]
            if n&0xC0==0xC0:return p+2
            if n==0:return p+1
            p+=n+1
        raise ValueError("DNS name too long")
    for _ in range(qd):pos=skip_name(pos)+4
    addresses=[]
    for _ in range(an):
        pos=skip_name(pos)
        tp,cl,ttl,n=struct.unpack_from("!HHIH",buf,pos)
        pos+=10
        if tp==1 and cl==1 and n==4:
            addresses.append(socket.inet_ntoa(buf[pos:pos+4]))
        pos+=n
    return rcode,addresses


def oracle_canary_check(domain:str,expect_rewrite:bool)->None:
    code,ips=dns_q(domain,1)
    if code!=0:raise RuntimeError("DOMAIN_DOT_RCODE_BAD")
    if expect_rewrite and ips!=[EDGE]:
        raise RuntimeError("DOMAIN_DOT_REWRITE_NOT_EFFECTIVE")
    if not expect_rewrite and EDGE in ips:
        raise RuntimeError("DOMAIN_DOT_REWRITE_STILL_EFFECTIVE")
    if expect_rewrite:
        for qtype in (28,65):
            rcode,ipv4=dns_q(domain,qtype)
            if rcode!=0 or ipv4:
                raise RuntimeError("DOMAIN_DOT_ALT_RR_INCONSISTENT")
    stable=("gemini.google.com","claude.ai","grok.com","x.com","www.tiktok.com")
    for host in stable:
        rc,ips=dns_q(host)
        if rc!=0 or ips!=[EDGE]:
            raise RuntimeError("STABLE_SERVICE_DOT_REGRESSION_"+host)
    for host in ("i.instagram.com","graph.instagram.com","api.telegram.org"):
        rc,ips=dns_q(host)
        if rc!=0 or EDGE in ips or RU in ips:
            raise RuntimeError("EXCLUDED_DOMAIN_REWRITTEN_"+host)
    print("owner_domain_stable_DoT_regression=PASS",flush=True)


def tls_public_route(host:str)->None:
    # Must inspect the actual RU->DE public route, not foreign-origin localhost.
    py=("import ssl,socket,sys;"
        "domain=sys.argv[1];edge=sys.argv[2];"
        "sock=socket.create_connection((edge,443),timeout=9);"
        "sock.settimeout(9);"
        "tls=ssl.create_default_context().wrap_socket(sock,server_hostname=domain);"
        "assert bool(tls.getpeercert());"
        "tls.close();"
        "print('owner_domain_ru_public_TLS_verified=true')")
    output=ssh("ru","python3 -c "+shlex.quote(py)+" "+
               shlex.quote(host)+" "+shlex.quote(EDGE),30)
    if "owner_domain_ru_public_TLS_verified=true" not in output:
        raise RuntimeError("PUBLIC_TLS_VERIFICATION_FAILED")


def sql_change(query:str)->bool:
    return sql(query).strip()=="1"


def update_error(item,code:str)->None:
    if not re.fullmatch(r"[A-Z0-9_]{3,90}",code):code="CANARY_FAILURE"
    id=item["id"];rev=item["revision"]
    sql("UPDATE dns_admin_domains SET status='FAILED',last_error_code='"+code+
        "',updated_at=now(),canary_expires_at=NULL"
        " WHERE id="+id+" AND revision="+rev+
        " AND status IN ('PROBING','APPLY_REQUESTED','CANARY','CONFIRM_REQUESTED','ROLLBACK_REQUESTED')")


def rollback(runid:str)->None:
    if not re.fullmatch(r"[1-9][0-9]{8,12}",runid):
        raise ValueError("Bad canary ID")
    base=BASE+"/"+runid
    command=("test ! -s "+shlex.quote(base+"/rollback.sh")+
             " || bash "+shlex.quote(base+"/rollback.sh")+" "+shlex.quote(base))
    print(ssh("de",command,80))


def apply(item):
    if not RUNID.isdigit() or not (9<=len(RUNID)<=13):
        raise ValueError("Invalid GitHub RUN_ID")
    id=item["id"];rev=item["revision"];host=item["domain"]
    claimed=sql("UPDATE dns_admin_domains SET status='PROBING',"
      " canary_run_id="+RUNID+",updated_at=now()"
      " WHERE id="+id+" AND revision="+rev+
      " AND status='APPLY_REQUESTED' RETURNING id")
    if claimed!=id:
        print("owner_domain_claim_lost=true",flush=True)
        return
    base=BASE+"/"+RUNID
    try:
        transfer_to_de()
        origin=ssh("de","python3 "+shlex.quote(WORK+"/mnebydns-owner-domain-render-20261110.py")+
                   " probe --domain "+shlex.quote(host),60).strip()
        _render.validated_public_ip(origin)
        deadline=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=60)).strftime("%Y-%m-%d %H:%M:%S UTC")
        command="bash "+shlex.quote(WORK+"/mnebydns-owner-domain-stage-20261110.sh")+" "+ \
            " ".join(shlex.quote(x) for x in (WORK,RUNID,host,origin,deadline))
        staged=ssh("de",command,90)
        if "owner_domain_DNS_nginx_canary_active=true" not in staged:
            raise RuntimeError("CANARY_STAGE_NOT_VERIFIED")
        oracle_canary_check(host,True)
        tls_public_route(host)
        deadline_epoch=int(dt.datetime.strptime(deadline,"%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=dt.timezone.utc).timestamp())
        updated=sql(
          "UPDATE dns_admin_domains SET status='CANARY',"
          " verified_origin_ip='"+origin+"'::inet,"
          " canary_expires_at=to_timestamp("+str(deadline_epoch)+"),"
          " applied_at=now(),updated_at=now(),last_error_code=NULL"
          " WHERE id="+id+" AND revision="+rev+" AND status='PROBING'"
          " AND canary_run_id="+RUNID+" RETURNING id"
        )
        if updated!=id:raise RuntimeError("CANARY_DB_COMMIT_REJECTED")
        print("owner_domain_CANARY_live="+host,flush=True)
        print("owner_domain_CANARY_expires_UTC="+deadline,flush=True)
    except Exception as exc:
        print("owner_domain_CANARY_error_class="+type(exc).__name__,flush=True)
        try:
            rollback(RUNID)
        except Exception:
            print("owner_domain_ROLLBACK_NOT_VERIFIED=true",flush=True)
            raise
        update_error(item,"CANARY_PREFLIGHT_OR_DEPLOY_FAILED")
        raise


def confirm(item):
    id=item["id"];rev=item["revision"];runid=item["run"];domain=item["domain"]
    if not runid:raise RuntimeError("No canary ID to confirm")
    expiry=int(item["expires"] or 0)
    if expiry-int(time.time())<300:
        raise RuntimeError("Confirmation too late for safe action")
    oracle_canary_check(domain,True)
    tls_public_route(domain)
    base=BASE+"/"+runid
    output=ssh("de","bash "+shlex.quote(base+"/confirm.sh")+" "+shlex.quote(base),60)
    if "owner_domain_confirmed_stable=true" not in output and \
       "owner_domain_already_confirmed=true" not in output:
        raise RuntimeError("Checkpoint was not confirmed")
    updated=sql("UPDATE dns_admin_domains SET status='ACTIVE',"
        "confirmed_at=now(),updated_at=now(),last_error_code=NULL"
        " WHERE id="+id+" AND revision="+rev+" AND status='CONFIRM_REQUESTED'"
        " AND canary_run_id="+runid+" RETURNING id")
    if updated!=id:raise RuntimeError("DB confirmation incomplete")
    print("owner_domain_ACTIVE_verified="+domain,flush=True)


def cancel_canary(item,expired=False):
    id=item["id"];rev=item["revision"];runid=item["run"]
    if runid:rollback(runid)
    if expired:
        sql("UPDATE dns_admin_domains SET status='FAILED',"
            "last_error_code='CANARY_EXPIRED_UNCONFIRMED',"
            "canary_expires_at=NULL,updated_at=now()"
            " WHERE id="+id+" AND revision="+rev+" AND status='CANARY'")
    else:
        sql("UPDATE dns_admin_domains SET status='CANCELLED',"
            "canary_expires_at=NULL,updated_at=now()"
            " WHERE id="+id+" AND revision="+rev+" AND status='ROLLBACK_REQUESTED'")
    print("owner_domain_rollback_completed=true",flush=True)


def main():
    if len(sys.argv)==2 and sys.argv[1]=="self-test":
        assert _render.validate_domain("oracle.com")=="oracle.com"
        assert _render.validated_public_ip("93.184.215.14")=="93.184.215.14"
        assert not RUNID or RUNID.isdigit()
        print("owner_dns_controller_offline=PASS")
        return
    if len(sys.argv)!=2 or sys.argv[1]!="run":
        raise SystemExit("usage: controller self-test|run")
    item=get_task()
    if not item:
        print("owner_domain_queue_empty=true",flush=True)
        return
    status=item["status"]
    print("owner_domain_queue_action="+status,flush=True)
    if status=="APPLY_REQUESTED":
        apply(item)
    elif status=="CONFIRM_REQUESTED":
        confirm(item)
    elif status=="ROLLBACK_REQUESTED":
        cancel_canary(item)
    elif status=="CANARY":
        if int(item["expires"] or 0)<int(time.time()):
            cancel_canary(item,expired=True)
        else:
            print("owner_domain_canary_wait_for_user=true",flush=True)
    elif status=="PROBING":
        # Previous CI attempt may have crashed after staging. Never accept
        # orphaned test routes as permanent; try its independent rollback.
        if int(time.time())-int(item["updated"] or 0)>12*60:
            if item["run"]:rollback(item["run"])
            update_error(item,"INTERRUPTED_OWNER_DEPLOY")
        else:
            print("owner_domain_probe_in_progress=true",flush=True)
    elif status=="REMOVAL_PENDING":
        print("owner_domain_remove_requires_guarded_worker=true",flush=True)
        # No claim of successful removal until separate guarded remove action.
    else:
        raise RuntimeError("Unsupported job state")


if __name__=="__main__":
    main()
