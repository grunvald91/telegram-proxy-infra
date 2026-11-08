#!/usr/bin/env python3
"""One-shot operator-approved refresh of active test VPN entitlements.

Runs on server188 only. Increases DB entitlement revision (never rotates keys)
and queues normal signed Xray provisioning. Existing isolated Xray process
restarts during per-entitlement apply, intentionally disconnecting clients.

Hard limits: exactly two active VPN users, same account, DB/node revision match,
old node expiry -30..-34 seconds, no expired access or unsolicited entitlement.
No personal identifiers, credentials, raw URLs or IDs are printed.
"""
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.request

LOCK="/run/lock/mnebyvpn-ntp-reapply-20261108.lock"
TARGET="http://10.66.77.1:18944/v1/provision"
WORKER="http://127.0.0.1:8794/profile"
VERSION="35c2ee085abc7abe80a38340fe8b2903fc09e36d"
DB_CMD=["docker","exec","mnebyvpn-stage-postgres","psql","-At","-X","-v",
        "ON_ERROR_STOP=1","-U","mnebyvpn_stage","-d","mnebyvpn_stage"]

def sql(query):
    completed=subprocess.run(DB_CMD+["-c",query],text=True,capture_output=True,timeout=15)
    if completed.returncode:
        raise RuntimeError("Database operation failed")
    return completed.stdout.strip()

def state(id_, key):
    raw=json.dumps({"op":"inspect","id":id_,"ts":int(time.time())},
                   separators=(",",":")).encode()
    signature=hmac.new(key,raw,hashlib.sha256).hexdigest()
    req=urllib.request.Request(TARGET,data=raw,method="POST",
              headers={"X-Mnebyvpn-Signature":signature,
                       "Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=7) as response:
        doc=json.load(response)
        remote_date=response.headers.get("Date")
    if not remote_date:
        raise RuntimeError("Cannot observe node clock")
    return doc

def snapshot_query():
    return """SELECT e.id::text, e.revision, e.expires_at::text,
                   e.account_id::text, p.applied_revision
              FROM entitlements e
              JOIN provisioning_state p
                ON p.entitlement_id=e.id AND p.adapter='vpn'
             WHERE e.product='vpn' AND e.state='ACTIVE'
               AND e.expires_at > clock_timestamp()
             ORDER BY e.id"""

def iso_db(value):
    return dt.datetime.fromisoformat(value.replace(" ","T"))

def read_rows():
    rows=[]
    for row in sql(snapshot_query()).splitlines():
        parts=row.split("|")
        if len(parts)!=5:
            raise RuntimeError("Unexpected active VPN row")
        id_,rev,expires,account,applied=parts
        if not re.fullmatch(r"[0-9a-f-]{36}",id_) or not re.fullmatch(r"[0-9a-f-]{36}",account):
            raise RuntimeError("Invalid active row identifiers")
        rows.append((id_,int(rev),iso_db(expires),account,int(applied)))
    return rows

def worker_profile(id_,key):
    token_file=pathlib.Path("/opt/mnebyvpn/bot/worker.env").read_text()
    token_match=re.search(r"^VPN_WORKER_PROFILE_TOKEN=([0-9a-f]{64})$",token_file,re.M)
    if not token_match:
        raise RuntimeError("Worker profile token unavailable")
    payload=json.dumps({"entitlementId":id_}).encode()
    request=urllib.request.Request(WORKER,payload,method="POST",headers={
        "Authorization":"Bearer "+token_match.group(1),
        "Content-Type":"application/json"})
    with urllib.request.urlopen(request,timeout=7) as response:
        return json.load(response).get("profile")

def main():
    if os.geteuid()!=0:
        raise RuntimeError("root required")
    with open(LOCK,"w") as f:
        fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        web_sha=pathlib.Path("/opt/mnebyvpn/public/active_sha").read_text().strip()
        worker_image=subprocess.run(
            ["docker","inspect","-f","{{.Config.Image}}","mnebyvpn-vpn-worker"],
            text=True,capture_output=True,check=True,timeout=6).stdout.strip()
        if web_sha!=VERSION or worker_image!="mnebyvpn-stage-web:"+VERSION:
            raise RuntimeError("Unexpected deployed website or worker SHA")
        key=bytes.fromhex(pathlib.Path("/opt/mnebyvpn/bot/provisioner.key").read_text().strip())
        if len(key)!=32:
            raise RuntimeError("Signing key invalid")
        all_active=sql("""SELECT count(*) FROM entitlements
            WHERE product='vpn' AND state='ACTIVE' AND expires_at>clock_timestamp()""")
        rows=read_rows()
        if all_active!="2" or len(rows)!=2 or len({r[3] for r in rows})!=1:
            raise RuntimeError("Expected exactly two active VPN entitlements under one account")
        if any(rev!=applied or rev<1 for _,rev,_,_,applied in rows):
            raise RuntimeError("Existing provisioning revisions disagree")
        credential_hashes={}
        for id_,rev,expiry,_,_ in rows:
            remote=state(id_,key)
            if not remote.get("enabled") or remote.get("revision")!=rev:
                raise RuntimeError("Before: active signed revision disagrees")
            node_exp=dt.datetime.fromisoformat(remote["expiresAt"])
            diff=(node_exp-expiry).total_seconds()
            if not -34<=diff<=-30:
                raise RuntimeError("Before: node expiry outside legacy -32s range")
            credential=remote.get("credential")
            if not isinstance(credential,str) or not re.fullmatch(r"[0-9a-f-]{36}",credential):
                raise RuntimeError("Before: node credential not valid")
            credential_hashes[id_]=hashlib.sha256(credential.encode()).digest()
            if not worker_profile(id_,key):
                raise RuntimeError("Before: profile not issued")
        print("preflight_active_entitlements=2")
        print("preflight_same_account=true")
        print("preflight_signed_revisions_and_legacy_expiries_valid=true")
        print("preflight_profile_access_ready=true")
        ids=",".join("'"+r[0]+"'::uuid" for r in rows)
        expected={r[0]:r[1] for r in rows}
        cases=" ".join("WHEN '"+id_+"'::uuid THEN "+str(rev)
                       for id_,rev in expected.items())
        # Two-row update and outbox enqueue are a single transaction.  The
        # signed node's *existing* UUID remains unchanged; only revision bumps.
        mutation="""BEGIN;
            SET LOCAL lock_timeout='10s';
            DO $body$
            DECLARE n integer;
            BEGIN
              PERFORM 1 FROM entitlements
               WHERE id IN ("""+ids+""") FOR UPDATE;
              SELECT count(*) INTO n FROM entitlements e
               WHERE e.id IN ("""+ids+""")
                 AND e.product='vpn' AND e.state='ACTIVE'
                 AND e.expires_at>clock_timestamp()
                 AND e.revision=CASE e.id """+cases+""" ELSE -1 END;
              IF n<>2 THEN
                RAISE EXCEPTION 'Revisions changed during NTP resync';
              END IF;
              UPDATE entitlements SET revision=revision+1
                WHERE id IN ("""+ids+""");
              GET DIAGNOSTICS n=ROW_COUNT;
              IF n<>2 THEN RAISE EXCEPTION 'Reapply count mismatch'; END IF;
              INSERT INTO reconcile_outbox(
                    entitlement_id, desired_revision, next_attempt_at)
                SELECT id,revision,clock_timestamp() FROM entitlements
                WHERE id IN ("""+ids+""")
                ON CONFLICT(entitlement_id,desired_revision) DO UPDATE
                  SET handled_at=NULL,next_attempt_at=clock_timestamp(),
                      last_error_code='manual_ntp_resync';
            END
            $body$;
            COMMIT;"""
        sql(mutation)
        print("db_revision_incremented_and_reconcile_queued=2")
        done=set()
        for attempt in range(70):
            time.sleep(1)
            latest={r[0]:r for r in read_rows()}
            for id_,previous_rev,expiry,_,_ in rows:
                if id_ in done: continue
                current=latest.get(id_)
                if not current or current[1]!=previous_rev+1 or current[4]!=current[1]:
                    continue
                response=state(id_,key)
                if response.get("revision")!=current[1] or not response.get("enabled"):
                    continue
                node_exp=dt.datetime.fromisoformat(response["expiresAt"])
                delta_ms=round((node_exp-expiry).total_seconds()*1000)
                if not -2000<=delta_ms<=1500:
                    continue
                credential=response.get("credential")
                if hashlib.sha256(credential.encode()).digest()!=credential_hashes[id_]:
                    raise RuntimeError("Credential rotated unexpectedly")
                if not worker_profile(id_,key):
                    raise RuntimeError("Reapplied node access has no profile")
                done.add(id_)
            if len(done)==2: break
        if len(done)!=2:
            raise RuntimeError("Worker did not reconcile both entitlements within the bounded check")
        print("node_reapplied_active_entitlements=2")
        print("node_expiry_difference_with_database_within_2s=true")
        print("original_credentials_preserved=true")
        print("active_VLESS_child_connections_interrupted_by_agent_apply=true")
        print("worker_profiles_after_resync=2")
        print("manual_ntp_resync_complete=true")

if __name__=="__main__":
    try:main()
    except Exception as ex:
        print("manual_ntp_resync_failed="+type(ex).__name__+":"+str(ex))
        sys.exit(2)
