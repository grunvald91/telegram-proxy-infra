#!/usr/bin/env python3
"""Disposable REAL FI217 AWG signed apply/receipt/revoke canary (no clients).

This uses only an RU188 signed synthetic grant with a RANDOM public key that
has NO private counterpart, IP 10.73.91.254 and a 120-second lease. FI217
temporarily starts its existing AWG service + offline expiry watchdog, applies
grant/revoke using the exact production Nodekit handler, signs genuine
APPLIED_V1 node receipts and removes its fake peer. The external customer
release flag, RU188 worker, billing and IPAM rows are NEVER written.

Independent systemd 95-second kill timer is armed BEFORE AWG starts. Any
failure must tear down the interface; timer stays armed if cleanup is unsure.
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
import subprocess
import sys
import tempfile
import time

import fi_awg_signed_canary as canary

NODE=canary.NODE_ID
UNIT="mnebyvpn-nodekit-awg@fi-test-01.service"
WATCHDOG="mnebyvpn-nodekit-awg-watchdog@fi-test-01.service"
TIMER="fi-awg-disposable-apply-expiry"
LEDGER=canary.FI_NODE/"amneziawg/peer-grants.json"
APP=Path("/opt/mnebyvpn-nodekit/awg_peer_grants.py")
AWG=Path("/opt/mnebyvpn-amneziawg/awg")
CLIENT_IP=canary.IP

class CanaryBlocked(ValueError):
    pass

def block(code:str)->None:
    # Only fixed enum reason; do not echo commands, keys or receipts.
    print("FI_AWG_APPLY_CANARY_BLOCKED="+code,file=sys.stderr)
    raise CanaryBlocked(code)

def command(args:list[str],timeout:int=20)->subprocess.CompletedProcess:
    try:
        return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):
        block("local_service_command_unavailable")

def inactive(unit:str)->bool:
    return command(["/usr/bin/systemctl","is-active","--quiet",unit],9).returncode!=0

def call_or_block(args:list[str],reason:str,timeout:int=20)->str:
    result=command(args,timeout)
    if result.returncode:
        block(reason)
    return result.stdout

def preflight(bundle:Path)->dict:
    if not canary.is_host(canary.FI_IP):
        block("not_pinned_fi217_root")
    # The real FI-only local state machine verifies the two RU signatures
    # against the pinned controller public SPKI BEFORE any AWG start.
    canary.node_verify(bundle,announce=False)
    from awg_lifecycle import validate
    validate(canary.FI_NODE)
    for unit in (UNIT,WATCHDOG,TIMER+".timer"):
        if not inactive(unit):
            block("existing_awg_or_expiry_timer")
    if LEDGER.exists() or LEDGER.is_symlink():
        block("existing_awg_peer_ledger")
    if Path("/sys/class/net/awg0").exists():
        block("unexpected_live_awg_interface")
    data=json.loads(canary.protected(bundle,6000))
    if (data["grant"]["peerPublicKey"] != data["revoke"]["peerPublicKey"] or
        data["grant"]["clientIpv4"] != CLIENT_IP or
        data["grant"]["expiresAt"] is None or
        data["revoke"]["expiresAt"] is not None):
        block("unexpected_signed_disposable_peer")
    return data

def install_watchdog()->None:
    from install_awg_watchdog import install
    install(canary.FI_NODE,Path(__file__).with_name("awg_peer_grants.py"))
    if not APP.is_file() or APP.is_symlink():
        block("missing_installed_awg_authorizer")

def run_apply(req:dict,folder:Path)->dict:
    file=folder/(req["op"]+".json")
    file.write_text(json.dumps(req,sort_keys=True,separators=(",",":"))+"\n")
    file.chmod(0o600)
    response=call_or_block([
        "/usr/bin/python3",str(APP),"--node-id",NODE,"--mode","apply",
        "--command",str(file)],"node_rejected_signed_"+req["op"],20)
    try:
        report=json.loads(response)
    except ValueError:
        block("invalid_node_applied_response")
    receipt=report.get("node_receipt")
    if (not isinstance(receipt,dict) or receipt.get("op")!=req["op"] or
        receipt.get("entitlementId")!=req["entitlementId"] or
        receipt.get("revision")!=req["revision"] or
        report.get("active") is not True or
        report.get("peers")!=(1 if req["op"]=="grant" else 0)):
        block("node_receipt_or_live_peer_count_mismatch")
    return receipt

def live_peers()->str:
    return call_or_block([str(AWG),"show","awg0","allowed-ips"],
                         "cannot_read_live_awg_peers",8).strip()

def safe_cleanup(expected:dict)->bool:
    # Always stop the watchdog first, then the associated AWG service.
    # Never disable the rollback timer unless every safety postcondition holds.
    for unit in (WATCHDOG,UNIT):
        command(["/usr/bin/systemctl","stop",unit],35)
    if not all(inactive(unit) for unit in (WATCHDOG,UNIT)):
        return False
    if Path("/sys/class/net/awg0").exists():
        return False
    if LEDGER.exists() or LEDGER.is_symlink():
        try:
            from awg_peer_grants import validate_state
            data=validate_state(json.loads(canary.protected(LEDGER,50000)),NODE)
            rows=data["grants"]
            if (set(rows)!={expected["entitlementId"]} or
                rows[expected["entitlementId"]]["peerPublicKey"]!=expected["peerPublicKey"] or
                rows[expected["entitlementId"]]["clientIpv4"]!=CLIENT_IP or
                rows[expected["entitlementId"]]["revision"] not in (1,2)):
                return False
            LEDGER.unlink()
        except (OSError,ValueError,TypeError,KeyError):
            return False
    if LEDGER.exists() or Path("/sys/class/net/awg0").exists():
        return False
    command(["/usr/bin/systemctl","stop",TIMER+".timer"],9)
    return True

def real_roundtrip(bundle:Path)->dict:
    data=preflight(bundle)
    install_watchdog()
    # One-shot systemd timer independent of GitHub, SSH, Python and RU188.
    # If a process dies mid-apply, the node is forcibly disconnected.
    call_or_block([
      "/usr/bin/systemd-run","--quiet","--collect",
      "--unit="+TIMER,"--on-active=95s",
      "/usr/bin/systemctl","stop",WATCHDOG,UNIT
    ],"disposable_timeout_not_armed",12)
    cleaned=False
    output=None
    try:
        call_or_block(["/usr/bin/systemctl","start",UNIT],
                      "temporary_awg_start_failed",48)
        call_or_block(["/usr/bin/systemctl","start",WATCHDOG],
                      "offline_expiry_watchdog_start_failed",22)
        if any(inactive(unit) for unit in (UNIT,WATCHDOG)):
            block("watchdog_or_awg_did_not_stay_active")
        with tempfile.TemporaryDirectory(prefix="fi-awg-applied-",dir="/run") as folder:
            root=Path(folder)
            grant=run_apply(data["grant"],root)
            peer_state=live_peers()
            want=data["grant"]["peerPublicKey"]+"\t"+CLIENT_IP+"/32"
            if peer_state.split()!=want.split():
                block("grant_not_present_in_real_awg_table")
            revoke=run_apply(data["revoke"],root)
            if live_peers():
                block("revoked_peer_survived_in_awg_table")
            # The exact signed revision 1 must never resurrect a revoked peer.
            old=root/"grant.json"
            replay=command(["/usr/bin/python3",str(APP),"--node-id",NODE,
                            "--mode","apply","--command",str(old)],12)
            if replay.returncode==0 or live_peers():
                block("replayed_grant_resurrected_peer")
            output={"version":1,"nodeId":NODE,"publicCustomerRelease":False,
                    "grantReceipt":grant,"revokeReceipt":revoke,
                    "realGrantApplied":True,"realRevokeApplied":True,
                    "peersLeft":0}
    finally:
        cleaned=safe_cleanup(data["grant"])
    if not cleaned:
        block("cleanup_unverified_systemd_timer_remains_armed")
    if output is None:
        block("signed_node_receipts_incomplete")
    return output

def verify_output(bundle:Path,reply:Path,pub:Path)->None:
    # This verifies GENUINE APPLIED_V1 signatures, not the earlier
    # deliberately incompatible TEST_PROOF_V1 in-memory attestation.
    signed=json.loads(bundle.read_bytes())
    record=json.loads(reply.read_bytes())
    if (set(record)!={"version","nodeId","publicCustomerRelease","grantReceipt",
                     "revokeReceipt","realGrantApplied","realRevokeApplied","peersLeft"} or
        record["version"]!=1 or record["nodeId"]!=NODE or
        record["publicCustomerRelease"] is not False or
        record["realGrantApplied"] is not True or
        record["realRevokeApplied"] is not True or record["peersLeft"]!=0):
        block("unexpected_real_canary_result")
    if pub.is_symlink() or not pub.is_file():
        block("missing_pinned_node_public_key")
    data=pub.read_bytes()
    if (len(data)!=44 or not data.startswith(canary.SPKI_HEADER) or
        hashlib.sha256(data).hexdigest()!=canary.NODE_SHA):
        block("unexpected_fi_node_public_identity")
    for op in ("grant","revoke"):
        cmd=signed[op]
        receipt=record[op+"Receipt"]
        keys={"nodeId","op","entitlementId","revision","commandSha256",
              "appliedAt","nonce","signature"}
        if not isinstance(receipt,dict) or set(receipt)!=keys:
            block("malformed_node_receipt")
        if (receipt["nodeId"]!=NODE or receipt["op"]!=op or
            receipt["entitlementId"]!=cmd["entitlementId"] or
            receipt["revision"]!=cmd["revision"] or
            receipt["commandSha256"]!=hashlib.sha256(canary.message(cmd)).hexdigest() or
            not isinstance(receipt["nonce"],str) or
            not re.fullmatch("[a-f0-9]{64}",receipt["nonce"]) or
            not isinstance(receipt["signature"],str) or
            not re.fullmatch("[A-Za-z0-9_-]{86}",receipt["signature"])):
            block("node_receipt_does_not_bind_signed_command")
        try:
            stamp=receipt["appliedAt"]
            if (not isinstance(stamp,str) or
                not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z",stamp)):
                block("noncanonical_node_receipt_time")
            parsed=dt.datetime.fromisoformat(stamp.replace("Z","+00:00"))
            if canary.iso(parsed)!=stamp:
                block("noncanonical_node_receipt_time")
            when=parsed.timestamp()
        except (ValueError,TypeError):
            block("invalid_node_receipt_time")
        if abs(time.time()-when)>180:
            block("node_applied_receipt_expired")
        sig=base64.urlsafe_b64decode(receipt["signature"]+"==")
        if len(sig)!=64 or base64.urlsafe_b64encode(sig).rstrip(b"=").decode()!=receipt["signature"]:
            block("node_receipt_invalid_encoding")
        payload=json.dumps([
          "MNEBYVPN_AWG_APPLIED_V1",NODE,op,receipt["entitlementId"],
          receipt["revision"],receipt["commandSha256"],receipt["appliedAt"],
          receipt["nonce"]
        ],separators=(",",":"),ensure_ascii=False).encode()
        with tempfile.TemporaryDirectory(prefix="fi-apply-verify-") as tmp:
            message=Path(tmp)/"payload"; signature=Path(tmp)/"signature"
            message.write_bytes(payload); signature.write_bytes(sig)
            ok=subprocess.run([
              "/usr/bin/openssl","pkeyutl","-verify","-pubin","-inkey",str(pub),
              "-keyform","DER","-rawin","-in",str(message),"-sigfile",str(signature)
            ],capture_output=True,timeout=8,check=False)
            if ok.returncode:
                block("node_applied_receipt_signature_invalid")
    print("FI_AWG_DISPOSABLE_APPLIED=PASS;SIGNED_GRANT_ACK=true;"
          "SIGNED_REVOKE_ACK=true;PEERS_LEFT=0;CUSTOMER_RELEASE=false")

def main()->None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",required=True,choices=("run-fi","verify-runner"))
    parser.add_argument("--signed",type=Path,required=True)
    parser.add_argument("--reply",type=Path)
    parser.add_argument("--node-public",type=Path)
    args=parser.parse_args()
    if args.mode=="run-fi":
        if args.reply or args.node_public:block("unexpected_fi_arguments")
        print(json.dumps(real_roundtrip(args.signed),
                         sort_keys=True,separators=(",",":")))
    else:
        if not args.reply or not args.node_public:
            block("missing_verified_receipt_files")
        verify_output(args.signed,args.reply,args.node_public)

if __name__=="__main__":
    try:
        main()
    except (CanaryBlocked,canary.CanaryError,ValueError,TypeError,
            KeyError,OSError,UnicodeError,subprocess.SubprocessError):
        raise SystemExit(2)
