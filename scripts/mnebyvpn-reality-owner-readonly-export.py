#!/usr/bin/env python3
"""Read-only audit of a single operator's existing VPN identity. Secret JSON to redirected stdout only."""
import datetime as dt
import hashlib
import hmac
import json
import pathlib
import subprocess
import sys
import time
import urllib.request

HASH = "65159196f6dc7ce18685dd61f958679927889b3a8db907ce80c6b57ce6154a4e"
SQL = """SELECT e.id::text||'|'||e.revision::text
 FROM vpn_subscription_links l JOIN entitlements e ON e.id=l.entitlement_id
 JOIN provisioning_state p ON p.entitlement_id=e.id AND p.adapter='vpn'
 WHERE l.token_sha256='"""+HASH+"""'
 AND l.revoked_at IS NULL AND e.product='vpn' AND e.state='ACTIVE'
 AND e.expires_at>clock_timestamp() AND p.applied_revision=e.revision;"""
PSQL = ["docker","exec","mnebyvpn-stage-postgres","psql","-qAtX","-v","ON_ERROR_STOP=1",
    "-U","mnebyvpn_stage","-d","mnebyvpn_stage","-c",SQL]
proc=subprocess.run(PSQL,capture_output=True,text=True,check=True,timeout=15)
rows=[x for x in proc.stdout.splitlines() if x]
if len(rows)!=1 or rows[0].count("|")!=1:
    sys.exit("Operator link is not unique and active")
identity,rev=rows[0].split("|")
key=bytes.fromhex(pathlib.Path("/opt/mnebyvpn/bot/provisioner.key").read_text().strip())
raw=json.dumps({"op":"inspect","id":identity,"ts":int(time.time())},
    separators=(",",":")).encode()
req=urllib.request.Request("http://10.66.77.1:18944/v1/provision",raw,method="POST",headers={
    "Content-Type":"application/json",
    "X-Mnebyvpn-Signature":hmac.new(key,raw,hashlib.sha256).hexdigest()})
with urllib.request.urlopen(req,timeout=10) as res:
    node=json.load(res)
if node.get("revision")!=int(rev) or node.get("enabled") is not True:
    sys.exit("Unacknowledged node profile")
if not node.get("credential") or not node.get("reality"):
    sys.exit("REALITY not announced to this verified subscriber")
expiry=dt.datetime.fromisoformat(node["expiresAt"].replace("Z","+00:00"))
if (expiry-dt.datetime.now(dt.timezone.utc)).total_seconds()<3600:
    sys.exit("Node profile near expiry")
meta=node["reality"]
if meta.get("port")!=2053 or len(meta.get("publicKey",""))!=43 or len(meta.get("shortId",""))!=16:
    sys.exit("Node REALITY metadata invalid")
print(json.dumps({"credential":node["credential"],"publicKey":meta["publicKey"],"shortId":meta["shortId"]},
                 separators=(",",":")),flush=True)
