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
PINNED_SSH_HOSTS=REPO.parent/"ops/mnebydns-owner-ssh-known_hosts"
SSH_TRUST=("-o","StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
           "-o","UserKnownHostsFile="+str(PINNED_SSH_HOSTS),
           "-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no")
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
    "mnebydns-owner-domain-remove-20261110.sh",
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
    if not PINNED_SSH_HOSTS.is_file():raise RuntimeError("PINNED_SSH_HOST_KEYS_MISSING")
    if role not in ("ru","de"):raise ValueError("Invalid server")
    host=RU if role=="ru" else EDGE
    key="RU_PASS" if role=="ru" else "DE_PASS"
    password=os.environ.get(key)
    if not password:raise RuntimeError("Missing SSH credential")
    return cmd(["sshpass","-e","ssh","-o","ConnectTimeout=12",
                *SSH_TRUST,"-o","LogLevel=ERROR",
                "root@"+host,command],password,timeout)


def transfer_to_de()->None:
    ssh("de","test ! -e "+shlex.quote(WORK)+" && mkdir -m 700 "+shlex.quote(WORK))
    for file in FILES:
        pwd=os.environ["DE_PASS"]
        cmd(["sshpass","-e","scp","-q","-o","ConnectTimeout=12",
             *SSH_TRUST,"-o","LogLevel=ERROR",
             str(REPO/file),"root@"+EDGE+":"+WORK+"/"+file],pwd)
    print("owner_domain_verified_scripts_transferred=true",flush=True)


def sql(query:str)->str:
    # Only internally generated SQL containing checked integer identifiers
    # is accepted. PostgreSQL never sees arbitrary user-authored SQL.
    return ssh("ru", "docker exec mnebyvpn-stage-postgres psql -XqAt -v ON_ERROR_STOP=1 "
               "-U mnebyvpn_stage -d mnebyvpn_stage -c "+shlex.quote(query),45)


def get_task():
    query=(
        "SELECT id||'|'||domain||'|'||status||'|'||revision||'|'||"
        "coalesce(canary_run_id::text,'')||'|'||"
        "coalesce(extract(epoch from canary_expires_at)::bigint::text,'')||'|'||"
        "coalesce(extract(epoch from updated_at)::bigint::text,'')"
        " FROM dns_admin_domains"
        " WHERE status IN ('APPLY_REQUESTED','PROBING','CONFIRM_REQUESTED',"
        "'CONFIRMING','ROLLBACK_REQUESTED','REMOVAL_PENDING','REMOVING','CANARY')"
        # Expired canaries outrank new activation requests: otherwise a
        # queued APPLY_REQUESTED item can starve CANARY cleanup indefinitely.
        " ORDER BY CASE WHEN status='ROLLBACK_REQUESTED' THEN 0"
        " WHEN status='CANARY' AND canary_expires_at<=now() THEN 0"
        " WHEN status='CONFIRMING' THEN 1 WHEN status='CONFIRM_REQUESTED' THEN 2"
        " WHEN status='REMOVING' THEN 3 WHEN status='REMOVAL_PENDING' THEN 4"
        " WHEN status='PROBING' THEN 5 WHEN status='APPLY_REQUESTED' THEN 6 ELSE 7 END,"
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


def connect_dot()->socket.socket:
    """Bounded retry only for transient TCP startup errors after CoreDNS restart.

    A successful TCP connection must still complete strict TLS and DNS validation.
    Never retry bad DNS answers as if they were startup errors.
    """
    for attempt in range(7):
        try:
            return socket.create_connection((EDGE,853),timeout=9)
        except (ConnectionRefusedError,TimeoutError) as exc:
            if attempt==6:
                raise RuntimeError("DOMAIN_DOT_RESTART_NOT_READY") from exc
            time.sleep(min(0.3*(2**attempt),2.0))
    raise RuntimeError("DOMAIN_DOT_RESTART_NOT_READY")


def dns_q(host:str,kind=1)->tuple[int,list[str]]:
    labels=host.split(".")
    wire=b"".join(bytes([len(x)])+x.encode("ascii") for x in labels)+b"\0"
    qid=int.from_bytes(os.urandom(2),"big")
    packet=struct.pack("!HHHHHH",qid,0x100,1,0,0,0)+wire+struct.pack("!HH",kind,1)
    with connect_dot() as tcp:
        tcp.settimeout(9)
        with ssl.create_default_context().wrap_socket(tcp,server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(len(packet).to_bytes(2,"big")+packet)
            head=bytearray()
            while len(head)<2:
                chunk=tls.recv(2-len(head))
                if not chunk:raise RuntimeError("No DoT length prefix")
                head.extend(chunk)
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
    # Alternate address/service answers bypass the pinned SmartDNS edge.
    # Checking only the parsed IPv4 list would silently miss these records.
    if kind in (5,28,64,65) and an:
        raise RuntimeError("DOMAIN_ALT_RR_NOT_SUPPRESSED")
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
        for qtype in (5,28,64,65):
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


def update_error(item,code:str)->None:
    if not re.fullmatch(r"[A-Z0-9_]{3,90}",code):code="CANARY_FAILURE"
    id=item["id"];rev=item["revision"]
    sql("UPDATE dns_admin_domains SET status='FAILED',last_error_code='"+code+
        "',updated_at=now(),canary_expires_at=NULL"
        " WHERE id="+id+" AND revision="+rev+
        " AND status IN ('PROBING','APPLY_REQUESTED','CANARY','CONFIRM_REQUESTED','CONFIRMING','ROLLBACK_REQUESTED')")


def rollback(runid:str)->None:
    if not re.fullmatch(r"[1-9][0-9]{8,12}",runid):
        raise ValueError("Bad canary ID")
    base=BASE+"/"+runid
    # A missing rollback file or a confirmed-no-op is NOT a successful revert.
    command=("test -s "+shlex.quote(base+"/rollback.sh")+
             " && bash "+shlex.quote(base+"/rollback.sh")+" "+shlex.quote(base))
    out=ssh("de",command,80)
    if "owner_domain_canary_rollback_verified=true" not in out:
        raise RuntimeError("ROLLBACK_NOT_VERIFIED")
    print(out)


def live_checkpoint_unchanged()->bool:
    """Read-only guard: defer owner DNS changes during unrelated live pilots."""
    probe=(
      "set -Eeuo pipefail; "
      "root=$(cat /opt/mnebydns-stable-checkpoints/current); "
      "test -d \"$root\"; "
      "(cd \"$root\" && sha256sum -c stable-manifest.sha256 >/dev/null); "
      "cmp -s \"$root/dns.stable\" /opt/mnebydns-dot/Corefile; "
      "cmp -s \"$root/nginx.stable\" /etc/nginx/nginx.conf; "
      "cmp -s \"$root/proxy.stable\" /etc/mnebydns-googlepilot/nginx.conf; "
      "echo BASELINE_READY"
    )
    try:
        return ssh("de",probe,40).strip()=="BASELINE_READY"
    except (RuntimeError,subprocess.TimeoutExpired):
        return False


def rollback_or_unchanged(runid:str)->None:
    """Recover safely even if a job died before installing rollback.sh.

    A missing script must not trap a queued row forever when the live
    Nginx/CoreDNS are byte-identical to the verified stable checkpoint.
    """
    try:
        rollback(runid)
    except Exception:
        if not live_checkpoint_unchanged():
            raise RuntimeError("OWNER_ROUTE_ROLLBACK_UNVERIFIED")
        print("owner_domain_unchanged_baseline_verified=true",flush=True)


def apply(item):
    if not RUNID.isdigit() or not (9<=len(RUNID)<=13):
        raise ValueError("Invalid GitHub RUN_ID")
    id=item["id"];rev=item["revision"];host=item["domain"]
    # A second independent canary cannot be staged while a previous test is
    # live; otherwise exact stable checkpoint equality would fail.
    existing=sql("SELECT count(*) FROM dns_admin_domains WHERE id<>"+id+
        " AND status IN ('PROBING','CANARY','CONFIRM_REQUESTED','CONFIRMING',"
        "'ROLLBACK_REQUESTED','REMOVING')")
    if int(existing)>0:
        print("owner_domain_wait_for_previous_canary=true",flush=True)
        return
    if not live_checkpoint_unchanged():
        # E.g. an active Threads canary: keep the request queued and do not
        # modify the unrelated shared CoreDNS/Nginx files.
        print("owner_domain_deferred_for_live_checkpoint_drift=true",flush=True)
        return
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
        rollback_or_unchanged(RUNID)
        update_error(item,"CANARY_PREFLIGHT_OR_DEPLOY_FAILED")
        raise


def is_confirmed(runid:str)->bool:
    if not re.fullmatch(r"[1-9][0-9]{8,12}",runid):raise ValueError("Bad canary ID")
    base=BASE+"/"+runid
    # Recover after atomic checkpoint promotion but before 'confirmed' touch.
    # A checkpoint equal to the pilot is proof of a committed transition;
    # merely having a sentinel, or an uncommitted live pilot, is not.
    command=(
        "set -Eeuo pipefail; base="+shlex.quote(base)+"; "
        "if test -f \"$base/confirmed\"; then echo true; exit 0; fi; "
        "root=$(cat /opt/mnebydns-stable-checkpoints/current); "
        "if test -d \"$root\" && "
        "(cd \"$root\" && sha256sum -c stable-manifest.sha256 >/dev/null) && "
        "cmp -s \"$root/dns.stable\" \"$base/dns.pilot\" && "
        "cmp -s \"$root/nginx.stable\" \"$base/nginx.pilot\" && "
        "cmp -s /opt/mnebydns-dot/Corefile \"$base/dns.pilot\" && "
        "cmp -s /etc/nginx/nginx.conf \"$base/nginx.pilot\"; then "
        "bash \"$base/confirm.sh\" \"$base\" >/dev/null; echo true; "
        "else echo false; fi"
    )
    return ssh("de",command,60).strip()=="true"


def verified_live_confirmed(runid:str)->None:
    if not re.fullmatch(r"[1-9][0-9]{8,12}",runid):raise ValueError("Bad canary ID")
    base=BASE+"/"+runid
    command=(
        "set -Eeuo pipefail; base="+shlex.quote(base)+"; "
        "test -f \"$base/confirmed\"; "
        "root=$(cat /opt/mnebydns-stable-checkpoints/current); "
        "(cd \"$root\" && sha256sum -c stable-manifest.sha256 >/dev/null); "
        "cmp -s \"$root/dns.stable\" \"$base/dns.pilot\"; "
        "cmp -s \"$root/nginx.stable\" \"$base/nginx.pilot\"; "
        "cmp -s /opt/mnebydns-dot/Corefile \"$base/dns.pilot\"; "
        "cmp -s /etc/nginx/nginx.conf \"$base/nginx.pilot\"; "
        "nginx -t >/dev/null 2>&1; "
        "systemctl is-active --quiet nginx; "
        "systemctl is-active --quiet mnebydns-dot.service; "
        "echo OWNER_CONFIRMED_LIVE"
    )
    if ssh("de",command,45).strip()!="OWNER_CONFIRMED_LIVE":
        raise RuntimeError("CONFIRMED_LIVE_PROOF_FAILED")


def confirm(item):
    id=item["id"];rev=item["revision"];runid=item["run"];domain=item["domain"]
    if not runid:raise RuntimeError("No canary ID to confirm")
    if item["status"]=="CONFIRM_REQUESTED":
        claimed=sql("UPDATE dns_admin_domains SET status='CONFIRMING',"
            "updated_at=now() WHERE id="+id+" AND revision="+rev+
            " AND status='CONFIRM_REQUESTED' RETURNING id")
        if claimed!=id:
            print("owner_domain_confirm_claim_lost=true",flush=True)
            return
    elif item["status"]!="CONFIRMING":
        raise ValueError("Not in confirmed owner state")
    base=BASE+"/"+runid
    expiry=int(item["expires"] or 0)
    if not is_confirmed(runid):
        if expiry-int(time.time())<300:
            rollback(runid)
            update_error(item,"CONFIRMATION_EXPIRED_BEFORE_COMMIT")
            print("owner_domain_confirmation_expired_rolled_back=true",flush=True)
            return
        oracle_canary_check(domain,True)
        tls_public_route(domain)
        output=ssh("de","bash "+shlex.quote(base+"/confirm.sh")+" "+shlex.quote(base),60)
        if "owner_domain_confirmed_stable=true" not in output and \
           "owner_domain_already_confirmed=true" not in output:
            raise RuntimeError("Checkpoint not confirmed")
    # Revalidate even on recovery: a checkpoint marker alone is not a live
    # connectivity result and must not turn the DB row into ACTIVE.
    verified_live_confirmed(runid)
    oracle_canary_check(domain,True)
    tls_public_route(domain)
    updated=sql("UPDATE dns_admin_domains SET status='ACTIVE',"
        "confirmed_at=now(),updated_at=now(),last_error_code=NULL"
        " WHERE id="+id+" AND revision="+rev+" AND status='CONFIRMING'"
        " AND canary_run_id="+runid+" RETURNING id")
    if updated!=id:raise RuntimeError("DB confirmation incomplete")
    print("owner_domain_ACTIVE_verified="+domain,flush=True)


def remove(item):
    if not RUNID.isdigit() or not (9<=len(RUNID)<=13):
        raise ValueError("Invalid GitHub RUN_ID")
    id=item["id"];rev=item["revision"];domain=item["domain"]
    if item["status"]=="REMOVAL_PENDING":
        claimed=sql("UPDATE dns_admin_domains SET status='REMOVING',"
            "canary_run_id="+RUNID+",updated_at=now()"
            " WHERE id="+id+" AND revision="+rev+
            " AND status='REMOVAL_PENDING' RETURNING id")
        if claimed!=id:return
        runid=RUNID
        try:
            transfer_to_de()
            deadline=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(minutes=15)).strftime(
                "%Y-%m-%d %H:%M:%S UTC")
            command="bash "+shlex.quote(WORK+"/mnebydns-owner-domain-remove-20261110.sh")+" "+ \
                " ".join(shlex.quote(x) for x in (WORK,RUNID,domain,deadline))
            staged=ssh("de",command,90)
            if "owner_domain_removal_canary_active=true" not in staged:
                raise RuntimeError("Removal stage not active")
            oracle_canary_check(domain,False)
            base=BASE+"/"+RUNID
            verified=ssh("de","bash "+shlex.quote(base+"/confirm.sh")+" "+shlex.quote(base),60)
            if "owner_domain_confirmed_stable=true" not in verified:
                raise RuntimeError("Removal stable checkpoint not promoted")
        except Exception:
            try:
                if not is_confirmed(runid):
                    rollback_or_unchanged(runid)
            except Exception:
                print("owner_domain_removal_rollback_UNVERIFIED=true",flush=True)
                raise
            if not is_confirmed(runid):
                sql("UPDATE dns_admin_domains SET status='ACTIVE',"
                    "last_error_code='REMOVAL_ABORTED',updated_at=now()"
                    " WHERE id="+id+" AND revision="+rev+" AND status='REMOVING'")
                raise
    else:
        runid=item["run"]
        if not runid:raise RuntimeError("Missing removal instance")
        if not is_confirmed(runid):
            rollback_or_unchanged(runid)
            sql("UPDATE dns_admin_domains SET status='ACTIVE',"
                "last_error_code='REMOVAL_INTERRUPTED',updated_at=now()"
                " WHERE id="+id+" AND revision="+rev+" AND status='REMOVING'")
            return
    # A recovered remove must be proved on the live server as well.
    # An old 'confirmed' sentinel alone is not sufficient to mark CANCELLED.
    verified_live_confirmed(runid)
    oracle_canary_check(domain,False)
    updated=sql("UPDATE dns_admin_domains SET status='CANCELLED',"
                "confirmed_at=NULL,canary_expires_at=NULL,"
                "verified_origin_ip=NULL,updated_at=now(),last_error_code=NULL"
                " WHERE id="+id+" AND revision="+rev+" AND status='REMOVING'"
                " AND canary_run_id="+runid+" RETURNING id")
    if updated!=id:raise RuntimeError("Removal completed but DB not updated")
    print("owner_domain_removed_and_confirmed="+domain,flush=True)


def cancel_canary(item,expired=False):
    id=item["id"];rev=item["revision"];runid=item["run"]
    if not runid:
        raise RuntimeError("Missing canary identifier, cannot verify rollback")
    rollback(runid)
    oracle_canary_check(item["domain"],False)
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



def active_health():
    """Inspect one ACTIVE row per idle cycle; never change a working route.

    The upstream can change after confirmation. Keep the pinned IP until an
    explicit, separately reviewed owner canary. Surface a health error in
    Telegram rather than silently replacing the address.
    """
    if not live_checkpoint_unchanged():
        print("owner_domain_active_audit_deferred_checkpoint_drift=true",flush=True)
        return
    raw=sql("SELECT id||'|'||domain||'|'||coalesce(verified_origin_ip::text,'')||'|'||"
            "revision FROM dns_admin_domains WHERE status='ACTIVE' ORDER BY id")
    entries=[line.split("|") for line in raw.splitlines() if line.strip()]
    if not entries:
        print("owner_domain_no_active_owner_routes=true",flush=True)
        return
    if len(entries)>500 or any(len(e)!=4 for e in entries):
        raise RuntimeError("Invalid ACTIVE domain health queue")
    # Across five-minute scheduler ticks this checks each active entry in turn.
    idx=int(time.time()//300)%len(entries)
    id,domain,ip,rev=entries[idx]
    if not re.fullmatch(r"[1-9][0-9]{0,14}",id) or \
       not re.fullmatch(r"[1-9][0-9]{0,14}",rev):
        raise RuntimeError("Invalid ACTIVE row identifier")
    domain=_render.validate_domain(domain)
    # Distinguish missing/invalid stored origin metadata from network failure.
    # Never invent an origin IP, change routing, or clear an ACTIVE state.
    try:
        _render.validated_public_ip(ip)
    except ValueError:
        sql("UPDATE dns_admin_domains SET last_error_code='ACTIVE_ROUTE_METADATA_INVALID'"
            " WHERE id="+id+" AND revision="+rev+" AND status='ACTIVE'")
        print("owner_domain_ACTIVE_metadata_invalid="+domain,flush=True)
        return
    try:
        tag=_render.mark(domain)
        probe=(
            "set -Eeuo pipefail; "
            "root=$(cat /opt/mnebydns-stable-checkpoints/current); "
            "(cd \"$root\" && sha256sum -c stable-manifest.sha256 >/dev/null); "
            "cmp -s \"$root/dns.stable\" /opt/mnebydns-dot/Corefile; "
            "cmp -s \"$root/nginx.stable\" /etc/nginx/nginx.conf; "
            "grep -Fq -- "+shlex.quote(tag)+" /opt/mnebydns-dot/Corefile; "
            "grep -Fq -- "+shlex.quote(tag)+" /etc/nginx/nginx.conf; "
            "grep -Fq -- "+shlex.quote(domain+" "+ip+":443;")+
                " /etc/nginx/nginx.conf; "
            "nginx -t >/dev/null 2>&1; "
            "systemctl is-active --quiet nginx; "
            "systemctl is-active --quiet mnebydns-dot.service; "
            "echo ACTIVE_PINNED_ROUTE_VERIFIED"
        )
        if ssh("de",probe,40).strip()!="ACTIVE_PINNED_ROUTE_VERIFIED":
            raise RuntimeError("ACTIVE_CHECKPOINT_ROUTE_MISMATCH")
        # Both origin IP and end-to-end SNI must validate TLS independently.
        origin_py=("import ssl,socket,sys;"
                   "s=socket.create_connection((sys.argv[2],443),timeout=8);"
                   "s.settimeout(8);"
                   "ssl.create_default_context().wrap_socket(s,server_hostname=sys.argv[1]).close();"
                   "print('ACTIVE_PINNED_ORIGIN_TLS_OK')")
        result=ssh("de","python3 -c "+shlex.quote(origin_py)+" "+
                   shlex.quote(domain)+" "+shlex.quote(ip),30)
        if "ACTIVE_PINNED_ORIGIN_TLS_OK" not in result:
            raise RuntimeError("ACTIVE_ORIGIN_TLS_FAILED")
        oracle_canary_check(domain,True)
        tls_public_route(domain)
    except Exception as exc:
        # Set only an error indicator. Never mutate live CoreDNS, Nginx or
        # existing upstream. The owner must approve any future remediation.
        sql("UPDATE dns_admin_domains SET last_error_code='ACTIVE_ROUTE_CHECK_FAILED'"
            " WHERE id="+id+" AND revision="+rev+" AND status='ACTIVE'")
        print("owner_domain_ACTIVE_health_alert="+domain+
              " error_class="+type(exc).__name__,flush=True)
        return
    sql("UPDATE dns_admin_domains SET last_error_code=NULL"
        " WHERE id="+id+" AND revision="+rev+" AND status='ACTIVE'"
        " AND last_error_code IN ('ACTIVE_ROUTE_CHECK_FAILED',"
        "'ACTIVE_ROUTE_METADATA_INVALID')")
    print("owner_domain_ACTIVE_health_verified="+domain,flush=True)


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
        active_health()
        return
    # A non-empty owner queue must not starve the ACTIVE-route monitor.
    # Only read/inspect: active_health() refuses to touch routes while the
    # shared live checkpoint differs from its committed baseline.
    # Never let a health-monitor failure conceal a domain transition failure.
    try:
        status=item["status"]
        print("owner_domain_queue_action="+status,flush=True)
        if status=="APPLY_REQUESTED":
            apply(item)
        elif status in ("CONFIRM_REQUESTED","CONFIRMING"):
            confirm(item)
        elif status=="ROLLBACK_REQUESTED":
            cancel_canary(item)
        elif status=="CANARY":
            if int(item["expires"] or 0)<int(time.time()):
                cancel_canary(item,expired=True)
            else:
                print("owner_domain_canary_wait_for_user=true",flush=True)
        elif status=="PROBING":
            # Crash recovery: never accept orphaned tests as permanent.
            if int(time.time())-int(item["updated"] or 0)>12*60:
                if item["run"]:
                    rollback_or_unchanged(item["run"])
                elif not live_checkpoint_unchanged():
                    raise RuntimeError("INTERRUPTED_OWNER_DEPLOY_ROLLBACK_UNVERIFIED")
                update_error(item,"INTERRUPTED_OWNER_DEPLOY")
            else:
                print("owner_domain_probe_in_progress=true",flush=True)
        elif status in ("REMOVAL_PENDING","REMOVING"):
            remove(item)
        else:
            raise RuntimeError("Unsupported job state")
    finally:
        try:
            active_health()
        except Exception as exc:
            print("owner_domain_active_audit_exception="+type(exc).__name__,flush=True)


if __name__=="__main__":
    main()
