#!/usr/bin/env python3
"""One isolated ephemeral Xray entitlement on the existing private Node.
Run ONLY after checking that live customer entitlements are zero.
No IDs, keys, URLs or credentials are printed. Revoke in finally.
"""
import datetime as dt
import hashlib
import hmac
import json
import pathlib
import time
import urllib.request
import uuid

KEY=bytes.fromhex(pathlib.Path('/opt/mnebyvpn/bot/provisioner.key').read_text().strip())
assert len(KEY)==32
URL='http://10.66.77.1:18944/v1/provision'
entitlement=str(uuid.uuid4())

def call(body):
    raw=json.dumps({**body,'id':entitlement,'ts':int(time.time())},
                   separators=(',',':')).encode('utf8')
    signature=hmac.new(KEY,raw,hashlib.sha256).hexdigest()
    request=urllib.request.Request(
      URL,raw,{'Content-Type':'application/json',
               'X-Mnebyvpn-Signature':signature},method='POST')
    with urllib.request.urlopen(request,timeout=12) as response:
        assert response.status==200
        return json.load(response)

created=False
try:
    before=call({'op':'inspect'})
    assert before['enabled'] is False and before['revision']==0
    deadline=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=11)
    applied=call({'op':'apply','revision':1,'enabled':True,
                  'expiresAt':deadline.isoformat()})
    assert applied['status']=='applied' and applied['revision']==1
    created=True
    active=call({'op':'inspect'})
    assert active['revision']==1 and active['enabled'] is True
    assert uuid.UUID(active['credential'])
    print('ephemeral_node_profile_created_and_observed=true',flush=True)
    # The foreign agent periodically enforces expiry without a DB deadline.
    time.sleep(15)
    expired=call({'op':'inspect'})
    assert expired['revision']==1 and expired['enabled'] is False
    print('ephemeral_node_deadline_expired=true',flush=True)
finally:
    if created:
        revoked=call({'op':'apply','revision':2,'enabled':False})
        assert revoked['status']=='applied'
        observed=call({'op':'inspect'})
        assert observed['revision']==2 and observed['enabled'] is False
        print('ephemeral_node_profile_revoked=true',flush=True)
