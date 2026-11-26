#!/usr/bin/env python3
"""One bounded, external FI customer-path canary. Never enables public issuance.

The fixture is an isolated zero-value synthetic order, no payment event,
no Telegram identity, no notification, and a ten-minute expiration.
No existing account, order, credentials or quota is modified.
"""
import hashlib
import os
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT="/var/lib/mnebyvpn-nodekit/fi-test-01/dns-auth"
MARKER=ROOT+"/customer-dataplane.enable"
PROVIDER="fi_dns_release_canary"
RU="188.120.254.223"
FI="217.11.167.91"
DB="docker exec -i mnebyvpn-stage-postgres psql -XqAt -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage"
COMMON=["-F","/dev/null","-o","StrictHostKeyChecking=yes","-o","GlobalKnownHostsFile=/dev/null",
        "-o","HostKeyAlgorithms=ssh-ed25519","-o","UpdateHostKeys=no","-o","ForwardAgent=no",
        "-o","ClearAllForwardings=yes","-o","ControlMaster=no","-o","PubkeyAuthentication=no",
        "-o","PreferredAuthentications=password","-o","ConnectTimeout=12","-o","LogLevel=ERROR"]
class Blocked(Exception): pass
def require(condition, reason):
    if not condition: raise Blocked(reason)
def ssh(node, command, data=None, *, phase="command"):
    fi=node==FI
    env=dict(os.environ, SSHPASS=os.environ["FI_PASSWORD" if fi else "RU_PASSWORD"])
    pin=Path(sys.argv[1]) if fi else Path("ops/mnebydns-owner-ssh-known_hosts").resolve()
    opts=COMMON+["-o","UserKnownHostsFile="+str(pin)]
    if fi: opts+=["-o","HostKeyAlias=fi.mnebyvpn.site"]
    p=subprocess.run(["sshpass","-e","ssh","-T",*opts,"root@"+node,command],
                     input=data, text=True, capture_output=True,env=env,timeout=35)
    if p.returncode:
        # Return only a fixed stage, numeric exit status and allowlisted category.
        # Never include the remote stderr, command or private profile.
        err=p.stderr.lower()
        category=next((label for needle,label in (
            ("host key verification failed","HOST_KEY"),("permission denied","PERMISSION"),
            ("connection timed out","TIMEOUT"),("connection refused","REFUSED"),
            ("could not resolve","RESOLVE"),("error:  role","DB_ROLE"),
            ("error:  function","DB_FUNCTION"),("error:  relation","DB_RELATION"),
            ("error:  column","DB_COLUMN"),("error:  syntax","DB_SYNTAX"),
            ("error:","REMOTE_ERROR")) if needle in err),"OTHER")
        raise Blocked(f"REMOTE_{'FI' if fi else 'RU'}_{phase}_{p.returncode}_{category}")
    return p.stdout.strip()
def sql(statement):
    return ssh(RU, DB, "SET statement_timeout='8s'; SET lock_timeout='4s';\n"+statement,phase="SQL")
def verify_ru_database():
    # The legacy bot deployment copies DATABASE_URL from staging, not
    # necessarily from the optional mnebyvpn_bot role. Check the actual
    # authenticated login from inside the existing running bot container.
    probe = """const {Client}=require('pg');
const db=new Client({connectionString:process.env.DATABASE_URL,connectionTimeoutMillis:4000,statement_timeout:4000});
(async()=>{try{await db.connect();
const {rows}=await db.query('SELECT current_user AS role,current_database() AS db');
const r=rows[0];
if(r.db!=='mnebyvpn_stage'||!['mnebyvpn_stage','mnebyvpn_bot'].includes(r.role))process.exitCode=2;
else console.log(r.role);
}finally{await db.end();}})().catch(()=>{process.exitCode=2;});"""
    import shlex
    role=ssh(RU,"docker exec mnebyvpn-bot-info node -e "+shlex.quote(probe),phase="BOT_DB_IDENTITY")
    require(role in ("mnebyvpn_stage","mnebyvpn_bot"),"RU_UNKNOWN_BOT_DB_ROLE")
    print("FI_CANARY_RU_BOT_DB_ROLE="+role,flush=True)
    checks={
        "GATE_CLOSED": "COALESCE((SELECT NOT enabled FROM public.fi_dns_meter_gate WHERE singleton),false)",
        "NO_ACTIVE_FI_GRANTS": "NOT EXISTS(SELECT 1 FROM public.fi_dns_regional_credentials WHERE revoked_at IS NULL)",
        "REVISION_FUNCTION": "to_regprocedure('public.telegram_regional_dns_revision(bigint,text)') IS NOT NULL",
        "ISSUE_FUNCTION": "to_regprocedure('public.telegram_issue_regional_dns_credential(bigint,text,text,bigint)') IS NOT NULL",
        "CORE_ISSUER": "to_regprocedure('public.issue_regional_dns_credential(uuid,uuid,text,text,bigint)') IS NOT NULL",
        "REVISION_EXECUTE": f"COALESCE(has_function_privilege(to_regrole('{role}'),to_regprocedure('public.telegram_regional_dns_revision(bigint,text)'),'EXECUTE'),false)",
        "ISSUE_EXECUTE": f"COALESCE(has_function_privilege(to_regrole('{role}'),to_regprocedure('public.telegram_issue_regional_dns_credential(bigint,text,text,bigint)'),'EXECUTE'),false)",
    }
    # All booleans in a single read-only statement; no grants or writes.
    fields=", ".join("("+v+")::text" for v in checks.values())
    results=sql("SELECT "+fields+";").split("|")
    require(len(results)==len(checks) and all(v in ("true","false") for v in results),"RU_DB_PREFLIGHT_FORMAT")
    failed=[]
    for name,value in zip(checks,results):
        print("FI_CANARY_RU_"+name+"="+value,flush=True)
        if value!="true": failed.append(name)
    require(not failed,"RU_DB_CHECK_FAILED_"+",".join(failed))

def exactly(stream,n):
    result=b""
    while len(result)<n:
        block=stream.recv(n-len(result))
        if not block: raise EOFError()
        result+=block
    return result
def question(domain):
    return struct.pack("!6H",0x71ac,0x0100,1,0,0,0)+b"".join(bytes([len(x)])+x.encode("ascii") for x in domain.split("."))+b"\0\0\1\0\1"
def dot(host, domain):
    q=question(domain)
    with socket.create_connection((host,853),timeout=6) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as tls:
            tls.sendall(struct.pack("!H",len(q))+q)
            n=struct.unpack("!H",exactly(tls,2))[0]
            require(12<=n<=16384,"DNS_FRAME")
            a=exactly(tls,n)
            ident,flags,qd,an,_,_=struct.unpack("!6H",a[:12])
            require(ident==0x71ac and flags&0x8000 and qd==1 and a[12:len(q)]==q[12:],"DNS_RESPONSE")
            return flags&15,an,a
def a_addresses(answer,domain):
    offset=len(question(domain))
    count=struct.unpack("!H",answer[6:8])[0]
    result=set()
    for _ in range(count):
        while True:
            require(offset<len(answer),"DNS_RR_NAME")
            size=answer[offset]
            offset+=1
            if size==0: break
            if size&0xc0==0xc0:
                require(offset<len(answer),"DNS_RR_POINTER")
                offset+=1
                break
            require(0<size<=63 and offset+size<=len(answer),"DNS_RR_LABEL")
            offset+=size
        require(offset+10<=len(answer),"DNS_RR_HEADER")
        kind,cls,ttl,length=struct.unpack("!HHIH",answer[offset:offset+10])
        offset+=10
        require(offset+length<=len(answer),"DNS_RR_DATA")
        if kind==1 and cls==1 and length==4:
            result.add(socket.inet_ntoa(answer[offset:offset+4]))
        offset+=length
    return result
def positive(host,domain):
    rc,an,a=dot(host,domain)
    require(rc==0 and an>0,"DNS_POSITIVE")
    return a
def denied(host,domain):
    try:
        rc,an,_=dot(host,domain)
        return rc!=0 and an==0
    except (EOFError,ConnectionResetError,ssl.SSLEOFError):
        return True
def await_positive(host,domain,seconds=100):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        try: return positive(host,domain)
        except (Blocked,EOFError,OSError): time.sleep(4)
    raise Blocked("SIGNED_GRANT_NOT_USABLE")
def await_denied(host,domain,seconds=110):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if denied(host,domain): return
        time.sleep(4)
    raise Blocked("REVOKE_NOT_PROPAGATED")
def main():
    # No real Telegram identity or monetary payment is created.
    a,o,e=[str(uuid.uuid4()) for _ in range(3)]
    de,fi=secrets.token_hex(6),secrets.token_hex(6)
    dehost, fihost=de+".dns.mnebyvpn.site",fi+".fi.mnebyvpn.site"
    digest=hashlib.sha256(de.encode()).hexdigest()
    assert de!=fi
    ru_status=ssh(RU, """for unit in mnebyvpn-fi-dns-meter.service mnebyvpn-fi-dns-publisher.service; do
        if systemctl is-active --quiet "$unit"; then printf '%s=active\\n' "$unit"; else printf '%s=inactive\\n' "$unit"; fi
      done
      if test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-bot-info 2>/dev/null)" = true; then echo bot=active; else echo bot=inactive; fi
      if docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-bot-info 2>/dev/null | grep -Fxq MNEBYDNS_REGIONAL_DOT_ENABLED=yes; then echo issuance=enabled; else echo issuance=closed; fi
    """,phase="PREFLIGHT")
    expected={"mnebyvpn-fi-dns-meter.service=active","mnebyvpn-fi-dns-publisher.service=active","bot=active","issuance=closed"}
    safe=expected|{"mnebyvpn-fi-dns-meter.service=inactive","mnebyvpn-fi-dns-publisher.service=inactive","bot=inactive","issuance=enabled"}
    statuses=set(ru_status.splitlines())
    for item in sorted(statuses&safe):print("FI_CANARY_RU_"+item,flush=True)
    require(statuses==expected,"RU_SERVICES_OR_ISSUANCE_NOT_READY")
    verify_ru_database()
    print("FI_CANARY_RU_SCHEMA=PASS",flush=True)
    ssh(FI,"systemctl is-active --quiet mnebyvpn-fi-dns-country.service && systemctl is-active --quiet mnebyvpn-fi-public-dot.socket && systemctl is-active --quiet mnebyvpn-fi-public-https.socket && "
        "systemctl show -p ExecStart --value mnebyvpn-fi-dns-country.service | grep -q /opt/mnebyvpn-fi-dns-customers-v1/ && "
        "test ! -e "+MARKER+" && test ! -L "+MARKER,phase="PREFLIGHT")
    require(denied(secrets.token_hex(6)+".fi.mnebyvpn.site","example.com"),"UNKNOWN_BEFORE")
    print("FI_CANARY_PREFLIGHT=PASS",flush=True)
    attempted=False
    marker_attempted=False
    timer_attempted=False
    try:
        # Independent bounded controller rollback if the runner is interrupted.
        timer_attempted=True
        ssh(RU,"systemd-run --quiet --unit=mnebyvpn-fi-dns-canary-gate-close --on-active=9m "
            "/usr/bin/docker exec mnebyvpn-stage-postgres psql -XqAt -v ON_ERROR_STOP=1 "
            "-U mnebyvpn_stage -d mnebyvpn_stage -c 'UPDATE fi_dns_meter_gate SET enabled=false WHERE singleton;'")
        attempted=True
        # Only a new, short-lived, explicitly marked zero-value test fixture.
        # Commit the transaction so the real isolated meter and publisher see it.
        require(sql(f"""BEGIN;
        INSERT INTO accounts(id) VALUES('{a}');
        INSERT INTO orders(id,account_id,product,provider,amount_minor,currency,state)
          VALUES('{o}','{a}','smart_dns','{PROVIDER}',0,'RUB','PAID');
        INSERT INTO entitlements(id,account_id,source_order_id,product,state,revision,starts_at,expires_at,dns_query_quota_per_30d)
          VALUES('{e}','{a}','{o}','smart_dns','ACTIVE',1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '10 minutes',2);
        DO $canary$ BEGIN
          IF issue_personal_dns_credential('{e}','{de}','{digest}',2)<>'ISSUED' THEN RAISE EXCEPTION 'DE fixture'; END IF;
          UPDATE fi_dns_meter_gate SET enabled=true WHERE singleton AND NOT enabled;
          IF NOT FOUND THEN RAISE EXCEPTION 'gate changed'; END IF;
          IF public.issue_regional_dns_credential('{a}','{e}','FI','{fi}',0)<>'ISSUED' THEN RAISE EXCEPTION 'FI fixture'; END IF;
        END $canary$;
        COMMIT; SELECT 'READY';""")=="READY","FIXTURE_NOT_CREATED")
        # Bound the FI marker even if the runner is interrupted. The marker
        # has no value after expiry; the normal public bot flag remains off.
        marker_attempted=True
        ssh(FI,"umask 077; set -eu; test ! -e "+MARKER+"; test ! -L "+MARKER+
            "; systemd-run --quiet --unit=mnebyvpn-fi-dns-canary-close --on-active=9m /usr/bin/rm -f "+MARKER+
            "; (set -C; printf 'fi-dns-customer-v1\\n' > "+MARKER+")")
        def quota():
            return sql(f"SELECT COALESCE((SELECT used_queries::text||'|'||reserved_queries::text FROM personal_dns_query_windows WHERE entitlement_id='{e}' AND period_index=0),'0|0');")
        # Both public country hostnames and CA verification are real.
        await_positive(fihost,"example.com")
        require(quota()=="0|0","ORDINARY_FI_CHARGED")
        positive(dehost,"example.com")
        require(quota()=="0|0","ORDINARY_DE_CHARGED")
        positive(dehost,"www.youtube.com")
        require(quota()=="1|0","DE_COUNTER")
        response=positive(fihost,"www.youtube.com")
        require(FI in a_addresses(response,"www.youtube.com"),"FI_ROUTE")
        require(quota()=="2|0","SHARED_COUNTER")
        require(denied(fihost,"www.youtube.com"),"FI_QUOTA_NOT_ENFORCED")
        # Some DE policy implementations return an ordinary direct answer
        # on exhausted quota. The canonical shared meter must deny reserve.
        request=str(uuid.uuid4())
        require(sql(f"SELECT reserve_personal_dns_query('{de}','{request}');")=="DENY_QUOTA","DE_SHARED_QUOTA_NOT_ENFORCED")
        positive(fihost,"example.com")
        require(quota()=="2|0","ORDINARY_AFTER_LIMIT_CHARGED")
        print("FI_EXTERNAL_DOT=PASS;DE_EXTERNAL_DOT=PASS;SHARED_QUOTA=2/2;ORDINARY_FREE=true",flush=True)
        sql(f"UPDATE fi_dns_regional_credentials SET revoked_at=clock_timestamp() WHERE entitlement_id='{e}';")
        await_denied(fihost,"example.com")
        print("FI_EXTERNAL_REVOCATION=PASS",flush=True)
    finally:
        cleanup_ok=True
        if marker_attempted:
            try:
                ssh(FI,"rm -f "+MARKER+"; systemctl stop mnebyvpn-fi-dns-canary-close.timer")
            except (Blocked,subprocess.SubprocessError): cleanup_ok=False
        if attempted:
            try:
                # Close the gate independently of fixture deletion.
                require(sql("UPDATE fi_dns_meter_gate SET enabled=false WHERE singleton; SELECT (NOT (SELECT enabled FROM fi_dns_meter_gate WHERE singleton))::text;")=="true","GATE_CLOSE")
            except (Blocked,subprocess.SubprocessError): cleanup_ok=False
            try:
                # Delete only this fixture; no payment/capture rows ever created.
                require(sql(f"""BEGIN;
                  DELETE FROM fi_dns_meter_requests WHERE entitlement_id='{e}';
                  DELETE FROM personal_dns_query_reservations WHERE entitlement_id='{e}';
                  DELETE FROM personal_dns_query_windows WHERE entitlement_id='{e}';
                  DELETE FROM fi_dns_regional_credentials WHERE entitlement_id='{e}';
                  DELETE FROM personal_dns_credentials WHERE entitlement_id='{e}';
                  DELETE FROM entitlements WHERE id='{e}' AND account_id='{a}' AND source_order_id='{o}';
                  DELETE FROM orders WHERE id='{o}' AND account_id='{a}' AND provider='{PROVIDER}' AND amount_minor=0;
                  DELETE FROM accounts WHERE id='{a}' AND telegram_user_id IS NULL;
                  COMMIT;
                  SELECT (NOT (SELECT enabled FROM fi_dns_meter_gate WHERE singleton)
                   AND NOT EXISTS(SELECT 1 FROM accounts WHERE id='{a}'))::text;""")=="true","FIXTURE_CLEANUP")
            except (Blocked,subprocess.SubprocessError): cleanup_ok=False
        if timer_attempted and cleanup_ok:
            try: ssh(RU,"systemctl stop mnebyvpn-fi-dns-canary-gate-close.timer")
            except (Blocked,subprocess.SubprocessError): cleanup_ok=False
        require(cleanup_ok,"CANARY_ROLLBACK_UNCONFIRMED")
        print("FI_CANARY_GATES_CLOSED_AND_FIXTURE_REMOVED=true",flush=True)
    require(denied(secrets.token_hex(6)+".fi.mnebyvpn.site","example.com"),"UNKNOWN_AFTER")
    print("FI_CUSTOMER_EXTERNAL_E2E=PASS;PUBLIC_ISSUANCE=false",flush=True)

if __name__=="__main__":
    try: main()
    except Blocked as exc:
        print("FI_CUSTOMER_EXTERNAL_E2E=BLOCKED:"+str(exc),file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print("FI_CUSTOMER_EXTERNAL_E2E=BLOCKED:"+type(exc).__name__,file=sys.stderr)
        sys.exit(2)
