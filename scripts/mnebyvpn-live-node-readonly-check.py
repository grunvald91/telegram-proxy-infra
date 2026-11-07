#!/usr/bin/env python3
"""Verify existing active VPN profile(s) against foreign Xray node without mutation.

This script makes only signed INSPECT calls. No IDs, profiles, credentials,
subscriptions or HMAC keys are written to stdout, stderr or GitHub logs.
Requires existing private node-to-control-plane WireGuard reachability.
"""
import datetime as dt
import email.utils
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys
import time
import urllib.request

NODE_URL = 'http://10.66.77.1:18944/v1/provision'
KEY_FILE = pathlib.Path('/opt/mnebyvpn/bot/provisioner.key')

def utc_timestamp(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Node timestamp lacks timezone')
    return parsed.astimezone(dt.timezone.utc)

def active_rows() -> list[tuple[str,int,dt.datetime]]:
    sql = """
      SELECT e.id::text,e.revision::text,e.expires_at::text
      FROM entitlements e
      JOIN provisioning_state p
        ON p.entitlement_id=e.id AND p.adapter='vpn'
      WHERE e.product='vpn' AND e.state='ACTIVE'
        AND e.expires_at > clock_timestamp() + interval '60 seconds'
        AND p.applied_revision=e.revision
      ORDER BY e.id LIMIT 25
    """
    result = subprocess.run([
        'docker','exec','mnebyvpn-stage-postgres',
        'psql','-AtX','-F','|','-v','ON_ERROR_STOP=1',
        '-U','mnebyvpn_stage','-d','mnebyvpn_stage','-c',sql
    ], check=True, capture_output=True, text=True, timeout=20)
    rows = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        uid, revision, expiry = line.split('|', 2)
        rows.append((uid, int(revision), utc_timestamp(expiry)))
    return rows

def inspect(key: bytes, uid: str) -> tuple[dict,dt.datetime]:
    raw = json.dumps({'op':'inspect','id':uid,'ts':int(time.time())},
                     separators=(',',':')).encode('utf8')
    sig = hmac.new(key, raw, hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        NODE_URL, raw, {'Content-Type':'application/json',
            'X-Mnebyvpn-Signature':sig}, method='POST'
    )
    with urllib.request.urlopen(request,timeout=9) as response:
        if response.status != 200:
            raise ValueError('Unverified foreign node response')
        header = response.headers.get('Date')
        if header is None:
            raise ValueError('Foreign node clock not observable')
        remote_now = email.utils.parsedate_to_datetime(header).astimezone(dt.timezone.utc)
        status = json.load(response)
        if not isinstance(status,dict):
            raise ValueError('Invalid node inspection response')
    return status,remote_now

def run() -> None:
    key = bytes.fromhex(KEY_FILE.read_text().strip())
    if len(key) != 32:
        raise ValueError('Invalid private node key')
    rows = active_rows()
    if not rows:
        # Other checks must still verify that the node API itself is reachable.
        print('vpn_live_expiry_readback=no_sample_available')
        return
    for uid, revision, local_expiry in rows:
        status, remote_now = inspect(key,uid)
        remote_expiry = utc_timestamp(str(status.get('expiresAt','')))
        # Comparing relative TTLs avoids the known remote-node clock skew.
        remote_left = (remote_expiry-remote_now).total_seconds()
        local_left = (local_expiry-dt.datetime.now(dt.timezone.utc)).total_seconds()
        if not (status.get('enabled') is True and
                status.get('revision') == revision and
                remote_left > 0 and local_left > 0 and
                abs(remote_left-local_left) < 90):
            raise ValueError('Active VPN profile or enforced deadline not verified')
    print('vpn_live_node_active_deadlines=verified_readonly')
    print('vpn_live_node_profiles_checked='+str(len(rows)))

if __name__ == '__main__':
    try:
        run()
    except Exception:
        print('vpn_live_node_active_deadlines=verification_failed',file=sys.stderr)
        sys.exit(2)
