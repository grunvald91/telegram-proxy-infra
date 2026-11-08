#!/usr/bin/env python3
"""Keep one operator VPN entitlement live. No changes to trial/payment ledgers."""
import datetime as dt
import email.utils
import fcntl
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys
import time
import urllib.request

TOKEN_SHA='65159196f6dc7ce18685dd61f958679927889b3a8db907ce80c6b57ce6154a4e'
NODE='http://10.66.77.1:18944/v1/provision'
PSQL=['docker','exec','-i','mnebyvpn-stage-postgres','psql','-qAtX','-v','ON_ERROR_STOP=1',
      '-U','mnebyvpn_stage','-d','mnebyvpn_stage']

def db(statement):
    out=subprocess.run(PSQL,input=statement,text=True,capture_output=True,timeout=30)
    if out.returncode:raise RuntimeError('PostgreSQL operator transaction failed')
    return [x.strip() for x in out.stdout.splitlines() if x.strip()]

def health():
    for endpoint in ('http://127.0.0.1:8794/readyz',
                     'http://10.66.77.1:18944/healthz',
                     'http://127.0.0.1:8792/healthz'):
        with urllib.request.urlopen(endpoint,timeout=8) as response:
            if response.status!=200:raise RuntimeError('Runtime preflight failed')
    print('operator_preflight_worker_node_web=ready',flush=True)

def inspect(identity):
    key=bytes.fromhex(pathlib.Path('/opt/mnebyvpn/bot/provisioner.key').read_text().strip())
    if len(key)!=32:raise RuntimeError('Signing key missing')
    raw=json.dumps({'op':'inspect','id':identity,'ts':int(time.time())},
                   separators=(',',':')).encode()
    signature=hmac.new(key,raw,hashlib.sha256).hexdigest()
    req=urllib.request.Request(NODE,raw,{'Content-Type':'application/json',
             'X-Mnebyvpn-Signature':signature},method='POST')
    with urllib.request.urlopen(req,timeout=10) as result:
        return json.load(result),email.utils.parsedate_to_datetime(result.headers['Date'])

def initial_grant():
    statement="""
BEGIN;
SET LOCAL lock_timeout='8s';
SELECT pg_advisory_xact_lock(hashtext('mnebyvpn:operator'),hashtext('grant'));
CREATE TABLE IF NOT EXISTS vpn_operator_test_grants (
 entitlement_id uuid PRIMARY KEY REFERENCES entitlements(id) ON DELETE RESTRICT,
 token_sha256 text NOT NULL UNIQUE CHECK(token_sha256 ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 revoked_at timestamptz,
 last_renewed_at timestamptz
);
REVOKE ALL ON vpn_operator_test_grants FROM PUBLIC;
DO $body$
DECLARE target entitlements%ROWTYPE; matches integer;
BEGIN
 SELECT count(*) INTO matches FROM vpn_subscription_links l
 JOIN entitlements e ON e.id=l.entitlement_id
 JOIN orders o ON o.id=e.source_order_id
 JOIN trial_grants t ON t.order_id=o.id AND t.account_id=e.account_id
 WHERE l.token_sha256='""" + TOKEN_SHA + """' AND l.revoked_at IS NULL
 AND e.product='vpn' AND e.state='ACTIVE'
 AND e.expires_at>clock_timestamp() AND o.provider='internal_trial'
 AND o.state='TRIAL' AND t.activated_at IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM entitlement_credits c WHERE c.entitlement_id=e.id)
 AND NOT EXISTS(SELECT 1 FROM order_renewals r WHERE r.entitlement_id=e.id);
 IF matches<>1 THEN RAISE EXCEPTION 'Expected one unexpired owner trial'; END IF;
 SELECT e.* INTO target FROM vpn_subscription_links l
 JOIN entitlements e ON e.id=l.entitlement_id
 WHERE l.token_sha256='""" + TOKEN_SHA + """' FOR UPDATE OF e;
 IF EXISTS(SELECT 1 FROM vpn_operator_test_grants WHERE entitlement_id<>target.id)
 THEN RAISE EXCEPTION 'Unknown operator grant exists'; END IF;
 INSERT INTO vpn_operator_test_grants(entitlement_id,token_sha256)
 VALUES(target.id,'""" + TOKEN_SHA + """')
 ON CONFLICT(entitlement_id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM vpn_operator_test_grants
  WHERE entitlement_id=target.id AND token_sha256='""" + TOKEN_SHA + """'
  AND revoked_at IS NULL) THEN RAISE EXCEPTION 'Grant revoked or changed'; END IF;
END $body$;
COMMIT;
SELECT 'operator_grant=enabled' FROM vpn_operator_test_grants
 WHERE token_sha256='""" + TOKEN_SHA + """' AND revoked_at IS NULL;
"""
    result=db(statement)
    if result!=['operator_grant=enabled']:raise RuntimeError('Grant not confirmed')
    print('operator_grant=enabled',flush=True)

def state():
    sql="""SELECT e.id::text||'|'||e.revision::text||'|'||e.expires_at::text
 FROM vpn_operator_test_grants g JOIN entitlements e ON e.id=g.entitlement_id
 WHERE g.token_sha256='""" + TOKEN_SHA + """' AND g.revoked_at IS NULL;"""
    rows=db(sql)
    if len(rows)!=1 or rows[0].count('|')!=2:raise RuntimeError('Operator row not unique')
    identity,revision,expiration=rows[0].split('|')
    return identity,int(revision),dt.datetime.fromisoformat(expiration.replace(' ','T'))

def extend():
    sql="""
BEGIN;
SET LOCAL lock_timeout='8s';
SELECT pg_advisory_xact_lock(hashtext('mnebyvpn:operator'),hashtext('grant'));
DO $body$
DECLARE target entitlements%ROWTYPE; matches integer;
BEGIN
 SELECT count(*) INTO matches FROM vpn_operator_test_grants g
 JOIN vpn_subscription_links l ON l.entitlement_id=g.entitlement_id AND l.token_sha256=g.token_sha256
 JOIN entitlements e ON e.id=g.entitlement_id
 WHERE g.token_sha256='""" + TOKEN_SHA + """' AND g.revoked_at IS NULL
 AND l.revoked_at IS NULL AND e.product='vpn' AND e.state='ACTIVE'
 AND e.expires_at>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM entitlement_credits c WHERE c.entitlement_id=e.id);
 IF matches<>1 THEN RAISE EXCEPTION 'Operator grant not eligible'; END IF;
 SELECT e.* INTO target FROM vpn_operator_test_grants g
 JOIN entitlements e ON e.id=g.entitlement_id
 WHERE g.token_sha256='""" + TOKEN_SHA + """' FOR UPDATE OF e;
 IF target.expires_at<clock_timestamp()+interval '45 days' THEN
  UPDATE entitlements SET expires_at=clock_timestamp()+interval '75 days',
    revision=revision+1 WHERE id=target.id AND state='ACTIVE';
  UPDATE vpn_operator_test_grants SET last_renewed_at=clock_timestamp()
    WHERE entitlement_id=target.id;
  INSERT INTO reconcile_outbox(entitlement_id,desired_revision,next_attempt_at)
   SELECT id,revision,clock_timestamp() FROM entitlements WHERE id=target.id
   ON CONFLICT(entitlement_id,desired_revision) DO UPDATE SET
     handled_at=NULL,next_attempt_at=clock_timestamp();
 END IF;
END $body$;
COMMIT;
"""
    db(sql)
    identity,revision,expires=state()
    days=(expires-dt.datetime.now(dt.timezone.utc)).total_seconds()/86400
    print('operator_days_remaining='+str(round(days,2)),flush=True)
    if days<44 or days>77:raise RuntimeError('Unexpected operator deadline')
    return identity,revision,expires

def verify(identity,revision,expires,old_hash):
    for attempt in range(30):
        node,node_now=inspect(identity)
        if node.get('enabled') is True and node.get('revision')==revision:
            credential=node.get('credential')
            if not credential or hashlib.sha256(credential.encode()).hexdigest()!=old_hash:
                raise RuntimeError('Original VPN credential changed')
            if node.get('expiresAt'):
                node_exp=dt.datetime.fromisoformat(node['expiresAt'].replace('Z','+00:00'))
                node_left=(node_exp-node_now).total_seconds()
                db_left=(expires-dt.datetime.now(dt.timezone.utc)).total_seconds()
                if node_left>0 and abs(node_left-db_left)<90:
                    print('operator_node_deadline=verified',flush=True)
                    print('operator_original_uuid=preserved',flush=True)
                    return
        time.sleep(3)
    raise RuntimeError('Node deadline not applied by signed worker')

def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('activate','renew'):
        raise RuntimeError('Expected activate or renew')
    with open('/run/lock/mnebyvpn-owner-keepalive.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        health()
        if sys.argv[1]=='activate':initial_grant()
        identity,revision,expires=state()
        before,_=inspect(identity)
        if not before.get('enabled') or before.get('revision')!=revision:
            raise RuntimeError('Old node revision inconsistent with DB')
        old_credential=before.get('credential')
        if not old_credential:raise RuntimeError('Old VPN credential missing')
        old_hash=hashlib.sha256(old_credential.encode()).hexdigest()
        identity,revision,expires=extend()
        verify(identity,revision,expires,old_hash)
        print('operator_keepalive_complete=true',flush=True)

if __name__=='__main__':
    try:main()
    except Exception as error:
        print('operator_keepalive_failed='+type(error).__name__,file=sys.stderr)
        sys.exit(2)
