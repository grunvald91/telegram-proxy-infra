#!/usr/bin/env python3
"""Ephemeral VPN speed test credential via the existing private WireGuard API.

Run on 188 only. Never print the node HMAC key. "create" prints a UUID
credential solely for the ephemeral GitHub Actions runner; "revoke" checks
read-back before reporting success. No user subscriptions are modified.
"""
import datetime as dt
import email.utils
import hashlib
import hmac
import json
import os
import pathlib
import sys
import time
import urllib.request
import uuid

KEY_PATH=pathlib.Path('/opt/mnebyvpn/bot/provisioner.key')
NODE_URL='http://10.66.77.1:18944/v1/provision'
NODE_HEALTH='http://10.66.77.1:18944/healthz'

def action(secret, payload):
    data=json.dumps({**payload,'ts':int(time.time())},
        separators=(',',':')).encode('utf8')
    sig=hmac.new(secret,data,hashlib.sha256).hexdigest()
    request=urllib.request.Request(NODE_URL,data,
        {'X-Mnebyvpn-Signature':sig,'Content-Type':'application/json'},
        method='POST')
    with urllib.request.urlopen(request,timeout=12) as response:
        if response.status != 200:
            raise RuntimeError('Node error')
        return json.load(response)

def main():
    if len(sys.argv)!=3 or sys.argv[1] not in ('create','revoke'):
        raise SystemExit('Usage: script.py create|revoke entitlement-uuid')
    mode,identity=sys.argv[1:]
    identity=str(uuid.UUID(identity))
    # Production-agent apply stops its whole Xray child and drops every
    # subscriber socket. Merely testing with a disposable UUID is disruptive.
    # New diagnostic profiles need an explicit operator-approved opt-in;
    # never gate revoke, so interrupted tests can always clean themselves up.
    if mode=='create' and os.environ.get('MNEBYVPN_ALLOW_DISRUPTIVE_LIVE_TEST')!='yes':
        raise RuntimeError('Refusing disruptive production Xray restart: use isolated canary or explicit opt-in')
    key=bytes.fromhex(KEY_PATH.read_text().strip())
    if len(key)!=32:raise RuntimeError('Invalid private node key')
    if mode=='create':
        before=action(key,{'op':'inspect','id':identity})
        if before['enabled'] or before['revision']!=0:
            raise RuntimeError('Ephemeral profile unexpectedly exists')
        with urllib.request.urlopen(NODE_HEALTH,timeout=8) as response:
            node_date=response.headers.get('Date')
            if response.status!=200 or not node_date:
                raise RuntimeError('Node health or clock unavailable')
        node_now=email.utils.parsedate_to_datetime(node_date)
        expires=(node_now+dt.timedelta(minutes=8)).isoformat()
        result=action(key,{'op':'apply','id':identity,'revision':1,
                           'enabled':True,'expiresAt':expires})
        if result.get('status')!='applied' or result.get('revision')!=1:
            raise RuntimeError('Ephemeral provisioning rejected')
        found=action(key,{'op':'inspect','id':identity})
        credential=found.get('credential')
        uuid.UUID(credential)
        if found.get('revision')!=1 or not found.get('enabled'):
            raise RuntimeError('Ephemeral profile was not enabled')
        # The caller must suppress this from CI logs and mask it before use.
        print(json.dumps({'credential':credential},separators=(',',':')))
    else:
        result=action(key,{'op':'apply','id':identity,
                           'revision':2,'enabled':False})
        found=action(key,{'op':'inspect','id':identity})
        if (result.get('status')!='applied' or
                found.get('revision')!=2 or found.get('enabled')):
            raise RuntimeError('VPN node did not confirm credential revocation')
        print('benchmark_profile_revoked=true')

if __name__=='__main__':
    main()
