#!/usr/bin/env python3
"""Temporary REAL production FI217 AWG3.1 test peer, signed by RU188.

Independent runner proves a real encrypted handshake, HTTPS egress and
bidirectional bytes. Only after signed grant+revoke receipts are verified may
RU188 record the external E2E pool attestation; never fake verified_at.
"""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import uuid

import fi_awg_signed_canary as trust
from fi_awg_production_policy import canonical_key
from install_components import safe_manifest
from awg_lifecycle import validate as validate_awg

NODE="fi-test-01"
FI_IP=trust.FI_IP
RU_IP=trust.RU_IP
FI=trust.FI_NODE
CONFIG=FI/"amneziawg/awg0.conf"
CLIENT_IP="10.73.91.253"
MAGIC="FI_AWG_LIVE_E2E_V1"
FIELDS={"op","entitlementId","peerPublicKey","clientIpv4"}
KEY=re.compile(r"[A-Za-z0-9+/]{43}=\Z")
HEX=re.compile(r"[a-f0-9]{64}\Z")

class Blocked(ValueError): pass

def secure_json(path:Path,limit:int=16000)->dict:
    obj=json.loads(trust.protected(path,limit))
    if not isinstance(obj,dict):raise Blocked("nonobject")
    return obj

def cmd(args:list[str])->str:
    r=subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,text=True,check=True,timeout=12)
    if len(r.stdout)>10000:raise Blocked("output too large")
    return r.stdout.strip()

def live_fi()->dict:
    if not trust.is_host(FI_IP):raise Blocked("wrong FI host")
    for unit in ("mnebyvpn-nodekit-awg@fi-test-01.service",
                 "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service",
                 "mnebyvpn-nodekit-awg-egress@fi-test-01.service"):
        if subprocess.run(["systemctl","is-active","--quiet",unit],
                          capture_output=True,check=False,timeout=8).returncode:
            raise Blocked("FI runtime inactive")
    proof=validate_awg(FI)
    if proof.get("mode")!="production" or proof.get("production_approval")!="signed":
        raise Blocked("FI production signature missing")
    if cmd(["/opt/mnebyvpn-amneziawg/awg","show","awg0","listen-port"])!="51821":
        raise Blocked("port changed")
    awg=safe_manifest(FI/"amneziawg/manifest.json")
    original=trust.protected(CONFIG,16000).decode()
    matches=re.findall(r"^HeaderProtectionKey\s*=\s*([A-Za-z0-9+/]{43}=)\s*$",
                       original,re.MULTILINE)
    if len(matches)!=1:raise Blocked("missing exact header key")
    canonical_key(matches[0])
    canonical_key(awg.get("server_public_key"))
    return {"nodeId":NODE,"hostname":trust.HOST,"port":51821,
            "serverPublicKey":awg["server_public_key"],"headerKey":matches[0],
            "clientIp":CLIENT_IP}

def read_request(path:Path)->dict:
    obj=secure_json(path,4096)
    if (set(obj)!=FIELDS or obj.get("op") not in ("grant","revoke") or
        obj.get("clientIpv4")!=CLIENT_IP or
        not isinstance(obj.get("entitlementId"),str) or
        not isinstance(obj.get("peerPublicKey"),str) or
        not KEY.fullmatch(obj["peerPublicKey"])):
        raise Blocked("invalid production test request")
    try:
        if str(uuid.UUID(obj["entitlementId"]))!=obj["entitlementId"]:
            raise Blocked("noncanonical id")
    except ValueError:
        raise Blocked("invalid id")
    canonical_key(obj["peerPublicKey"])
    return obj

def sign_on_ru(request:dict)->dict:
    if not trust.is_host(RU_IP):raise Blocked("wrong RU signer")
    trust.pinned_spki(trust.RU_ROOT/"controller-public.spki",trust.CONTROLLER_SHA)
    signer=trust.RU_ROOT/"controller-signing-key.pem"
    trust.protected(signer,8192)
    issued=dt.datetime.now(dt.timezone.utc)
    expiry=issued+dt.timedelta(seconds=180)
    command={
        "nodeId":NODE,"op":request["op"],"entitlementId":request["entitlementId"],
        "revision":1 if request["op"]=="grant" else 2,
        "peerPublicKey":request["peerPublicKey"],
        "clientIpv4":CLIENT_IP,
        "issuedAt":trust.iso(issued),
        "expiresAt":trust.iso(expiry) if request["op"]=="grant" else None,
        "nonce":secrets.token_hex(32),
    }
    return trust.sign(signer,command)

def verify_receipt(command:dict,result:dict)->None:
    if result.get("signed_command_verified") is not True or result.get("active") is not True:
        raise Blocked("node did not apply signed command")
    r=result.get("node_receipt")
    expected={"nodeId","op","entitlementId","revision","commandSha256",
              "appliedAt","nonce","signature"}
    if (not isinstance(r,dict) or set(r)!=expected or
        r["nodeId"]!=NODE or r["op"]!=command["op"] or
        r["entitlementId"]!=command["entitlementId"] or
        r["revision"]!=command["revision"] or
        r["commandSha256"]!=hashlib.sha256(trust.message(command)).hexdigest()):
        raise Blocked("node receipt not linked to test command")
    if not isinstance(r["nonce"],str) or not HEX.fullmatch(r["nonce"]):
        raise Blocked("receipt nonce invalid")
    try:
        applied=dt.datetime.fromisoformat(r["appliedAt"].replace("Z","+00:00"))
        if abs((dt.datetime.now(dt.timezone.utc)-applied).total_seconds())>180:
            raise Blocked("receipt stale")
        sig=base64.urlsafe_b64decode(r["signature"]+"==")
    except (ValueError,TypeError):
        raise Blocked("receipt signature invalid")
    if len(sig)!=64:raise Blocked("receipt signature wrong length")
    payload=json.dumps([
        "MNEBYVPN_AWG_APPLIED_V1",r["nodeId"],r["op"],r["entitlementId"],
        r["revision"],r["commandSha256"],r["appliedAt"],r["nonce"],
    ],separators=(",",":"),ensure_ascii=False).encode()
    with __import__("tempfile").TemporaryDirectory(prefix="fi-awg-proof-") as folder:
        src=Path(folder)
        (src/"payload").write_bytes(payload)
        (src/"signature").write_bytes(sig)
        node_spki=trust.RU_ROOT/"fi-node-public.spki"
        trust.pinned_spki(node_spki,trust.NODE_SHA)
        subprocess.run(["openssl","pkeyutl","-verify","-pubin",
            "-inkey",str(node_spki),"-keyform","DER","-rawin",
            "-in",str(src/"payload"),"-sigfile",str(src/"signature")],
            check=True,capture_output=True,timeout=8)

def record_on_ru(path:Path)->None:
    if not trust.is_host(RU_IP):raise Blocked("wrong controller")
    data=secure_json(path)
    if set(data)!={"magic","grant","grantApplied","revoke","revokeApplied","external","serverPublicKey"} or data["magic"]!=MAGIC:
        raise Blocked("unknown external proof")
    grant,revoke=data["grant"],data["revoke"]
    if not isinstance(grant,dict) or not isinstance(revoke,dict):
        raise Blocked("invalid command evidence")
    for entry,applied in ((grant,data["grantApplied"]),(revoke,data["revokeApplied"])):
        if not isinstance(applied,dict):raise Blocked("invalid receipt")
        verify_receipt(entry,applied)
    if grant["op"]!="grant" or revoke["op"]!="revoke" or grant["entitlementId"]!=revoke["entitlementId"] or grant["peerPublicKey"]!=revoke["peerPublicKey"] or grant["clientIpv4"]!=CLIENT_IP or revoke["clientIpv4"]!=CLIENT_IP:
        raise Blocked("test identity mismatch")
    ext=data["external"]
    if (not isinstance(ext,dict) or set(ext)!={"handshake","encryptedBytes","ping","https","egressIp"} or
        any(ext[k] is not True for k in ("handshake","encryptedBytes","ping","https")) or
        ext["egressIp"]!=FI_IP):
        raise Blocked("external handshake/egress was not verified")
    key=data["serverPublicKey"]
    canonical_key(key)
    sha=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    # Only exact existing FI pool identity can receive this fresh REAL proof.
    sql=f"""
BEGIN;
DO $e2e$
DECLARE affected integer;
BEGIN
 UPDATE public.vpn_awg_node_pools
 SET state='verified',external_e2e_proof_sha256='{sha}',verified_at=clock_timestamp()
 WHERE node_id='fi-test-01' AND endpoint_host='fi.mnebyvpn.site'
   AND server_public_key='{key}' AND listen_port=51821
   AND subnet_cidr='10.73.91.0/24'::cidr
   AND state IN ('staged','verified','degraded');
 GET DIAGNOSTICS affected=ROW_COUNT;
 IF affected<>1 THEN
   RAISE EXCEPTION 'FI production pool proof identity mismatch';
 END IF;
END $e2e$;
COMMIT;
"""
    out=subprocess.run(["docker","exec","-i","mnebyvpn-stage-postgres","psql",
        "-X","-q","-A","-t","-v","ON_ERROR_STOP=1","-U","mnebyvpn_stage",
        "-d","mnebyvpn_stage"],input=sql,text=True,capture_output=True,timeout=16)
    if out.returncode:raise Blocked("canonical pool update denied")
    print("FI_AWG_REAL_E2E=VERIFIED;HANDSHAKE=true;HTTPS=true;ENCRYPTED_BYTES=true;GRANT_REVOKED=true;POOL=FRESH")

def prune_on_fi(path:Path)->None:
    """Retire ONLY the fully revoked synthetic peer after replay window closes.

    No production customer grant is removed or rewritten. The local signed
    ledger and active AWG peer set are checked under the watchdog's lock.
    """
    import time
    if not trust.is_host(FI_IP):raise Blocked("wrong cleanup host")
    if not all(subprocess.run(["systemctl","is-active","--quiet",unit],
                             capture_output=True,check=False,timeout=8).returncode==0
               for unit in ("mnebyvpn-nodekit-awg@fi-test-01.service",
                            "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service",
                            "mnebyvpn-nodekit-awg-egress@fi-test-01.service")):
        raise Blocked("signed local watchdog missing")
    req=secure_json(path,4096)
    import sys
    sys.path.insert(0,"/opt/mnebyvpn-nodekit")
    from awg_peer_grants import (LedgerLock,protected_file,validate_state,
                                 persist_state,verify_signature,active_peers,
                                 assert_runtime_peers)
    from awg_peer_grants import CMD_FIELDS
    if (set(req)!=CMD_FIELDS or req.get("nodeId")!=NODE or req.get("op")!="revoke"
        or req.get("clientIpv4")!=CLIENT_IP or req.get("revision")!=2
        or req.get("expiresAt") is not None):
        raise Blocked("not exact signed synthetic revoke")
    verify_signature(req,FI/"controller-access.spki")
    issued=dt.datetime.fromisoformat(req["issuedAt"].replace("Z","+00:00"))
    delta=(dt.datetime.now(dt.timezone.utc)-issued).total_seconds()
    if not 50<=delta<=1500:
        raise Blocked("replay window not expired or test too old")
    ledger=FI/"amneziawg/peer-grants.json"
    with LedgerLock(FI):
        data=validate_state(json.loads(protected_file(ledger)),NODE)
        row=data["grants"].get(req["entitlementId"])
        if (not isinstance(row,dict) or row.get("enabled") is not False
            or row.get("expiresAt") is not None
            or row.get("revision")!=2
            or row.get("peerPublicKey")!=req["peerPublicKey"]
            or row.get("clientIpv4")!=CLIENT_IP):
            raise Blocked("synthetic revocation not exact")
        actual=active_peers(data,time.time())
        if any(peer["public_key"]==req["peerPublicKey"] or
               peer["allowed_ips"]==CLIENT_IP+"/32" for peer in actual):
            raise Blocked("synthetic peer still active")
        assert_runtime_peers(actual)
        del data["grants"][req["entitlementId"]]
        persist_state(ledger,validate_state(data,NODE))
    print("FI_AWG_REAL_E2E_TOMBSTONE=PRUNED;CUSTOMER_PEERS_UNCHANGED=true")



def prune_stale_on_fi()->str:
    """Remove an old, disabled synthetic test tombstone; never a customer peer.

    Caller must independently verify via RU188 that the fixed synthetic
    client address has ZERO customer allocations in canonical PostgreSQL.
    """
    import time
    if not trust.is_host(FI_IP):raise Blocked("wrong FI host")
    for unit in ("mnebyvpn-nodekit-awg@fi-test-01.service",
                 "mnebyvpn-nodekit-awg-watchdog@fi-test-01.service",
                 "mnebyvpn-nodekit-awg-egress@fi-test-01.service"):
        if subprocess.run(["systemctl","is-active","--quiet",unit],
                          capture_output=True,check=False,timeout=8).returncode:
            raise Blocked("production watchdog/egress not active")
    sys.path.insert(0,"/opt/mnebyvpn-nodekit")
    from awg_peer_grants import (LedgerLock,protected_file,validate_state,
                                 persist_state,active_peers,assert_runtime_peers)
    ledger=FI/"amneziawg/peer-grants.json"
    with LedgerLock(FI):
        if not ledger.exists() and not ledger.is_symlink():
            return "ABSENT"
        state=validate_state(json.loads(protected_file(ledger)),NODE)
        rows=[(uid,row) for uid,row in state["grants"].items()
              if row["clientIpv4"]==CLIENT_IP]
        if not rows:return "ABSENT"
        if len(rows)!=1:raise Blocked("synthetic IP collision")
        uid,row=rows[0]
        if (row.get("enabled") is not False or row.get("expiresAt") is not None
            or row.get("revision")!=2):
            raise Blocked("synthetic IP not a fully revoked test entry")
        # Signed grant/revoke commands expire after 45s; the persisted
        # ledger must be undisturbed for an additional safety interval.
        age=time.time()-ledger.stat().st_mtime
        if not 90<=age<=86400*30:
            raise Blocked("revoked entry still in replay window")
        expected=active_peers(state,time.time())
        if any(peer["allowed_ips"]==CLIENT_IP+"/32" for peer in expected):
            raise Blocked("test IP active")
        # Includes every paying peer, not only the synthetic address.
        assert_runtime_peers(expected)
        del state["grants"][uid]
        persist_state(ledger,validate_state(state,NODE))
    return "PRUNED"


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--mode",required=True,choices=("fi-material","ru-sign","ru-record","fi-prune","fi-prune-stale"))
    p.add_argument("--request",type=Path)
    args=p.parse_args()
    try:
        if os.geteuid()!=0:raise Blocked("root required")
        if args.mode=="fi-material":
            if args.request:raise Blocked("unexpected input")
            print(json.dumps(live_fi(),sort_keys=True))
        elif args.mode=="ru-sign":
            if not args.request:raise Blocked("request missing")
            print(json.dumps(sign_on_ru(read_request(args.request)),sort_keys=True))
        elif args.mode=="ru-record":
            if not args.request:raise Blocked("proof missing")
            record_on_ru(args.request)
        elif args.mode=="fi-prune":
            if not args.request:raise Blocked("signed revoke missing")
            prune_on_fi(args.request)
        else:
            if args.request:raise Blocked("unexpected input")
            print("FI_AWG_REAL_E2E_OLD_TEST_TOMBSTONE="+prune_stale_on_fi())
        return 0
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError,
            trust.CanaryError):
        print("FI_AWG_REAL_E2E=BLOCKED",file=sys.stderr)
        return 2

if __name__=="__main__":sys.exit(main())
