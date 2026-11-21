#!/usr/bin/env python3
"""Explicitly gated FI-only AWG V2 per-slot signed apply and node receipt.

No public HTTP handlers, no unpinned trust, no new private client keys.
The pre-existing watchdog remains authoritative and reconciles BOTH V1 and
V2 ledgers atomically under the same root-only lock. Default release OFF.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

import awg_peer_grants as v1
import awg_slot_contract as v2
from awg_lifecycle import active_unit, unit_name

SLOT_LEDGER = "owner-device-slots-v2.json"
RELEASE_MARKER = "owner-v2-release.json"


class SlotRuntimeError(ValueError):
    pass


def release_approved(node: Path) -> None:
    if node.name != "fi-test-01":
        raise SlotRuntimeError("AWG V2 per-seat runtime is only approved on FI")
    marker = node / "amneziawg" / RELEASE_MARKER
    try:
        obj = json.loads(v1.protected_file(marker, max_bytes=512))
    except (OSError, ValueError) as exc:
        raise SlotRuntimeError("Root-only AWG V2 release marker missing or unsafe") from exc
    if obj != {"node_id": node.name, "enabled": True}:
        raise SlotRuntimeError("Per-device V2 release is not enabled")


def load_ledgers(node: Path) -> tuple[dict, dict]:
    first = node / "amneziawg" / "peer-grants.json"
    second = node / "amneziawg" / SLOT_LEDGER
    legacy = (v1.validate_state(json.loads(v1.protected_file(first)),node.name)
              if first.exists() or first.is_symlink()
              else v1.empty_state(node.name))
    slots = (v2.validate_state(json.loads(v1.protected_file(second)),node.name)
             if second.exists() or second.is_symlink()
             else v2.empty_state(node.name))
    return legacy, slots


def sign_slot_node_receipt(node: Path, command: dict, *,
                           runner=subprocess.run) -> dict:
    """Ed25519 node-signed proof of post-reconcile command identity and slot."""
    private = node / "identity" / "node-private.pk8"
    public = node / "identity" / "node-public.spki"
    pk8 = v1.protected_file(private, max_bytes=256)
    spki = v1.protected_file(public, max_bytes=100)
    if (not pk8.startswith(bytes.fromhex("302e020100300506032b6570"))
            or len(spki) != 44 or not spki.startswith(v1.KEY_PREFIX)):
        raise SlotRuntimeError("Invalid pinned node Ed25519 keypair")
    try:
        derived = runner([
            "/usr/bin/openssl","pkey","-inform","DER","-in",str(private),
            "-pubout","-outform","DER",
        ],capture_output=True,check=True,timeout=5).stdout
        if derived != spki:
            raise SlotRuntimeError("Local node private/public key mismatch")
        applied = dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00","Z")
        receipt = {
            "nodeId":command["nodeId"],"op":command["op"],
            "entitlementId":command["entitlementId"],
            "slotNumber":command["slotNumber"],"revision":command["revision"],
            "commandSha256":v2.command_digest(command),
            "appliedAt":applied,"nonce":secrets.token_hex(32),
            "signature":"A"*86,
        }
        with tempfile.TemporaryDirectory(prefix="nodekit-v2-ack-") as folder:
            msg = Path(folder)/"receipt"
            sig = Path(folder)/"signature"
            msg.write_bytes(v2.receipt_message(receipt))
            msg.chmod(0o600)
            runner([
                "/usr/bin/openssl","pkeyutl","-sign","-inkey",str(private),
                "-keyform","DER","-rawin","-in",str(msg),"-out",str(sig),
            ],capture_output=True,check=True,timeout=5)
            raw = sig.read_bytes()
        if len(raw)!=64:
            raise SlotRuntimeError("Invalid Ed25519 node acknowledgement length")
        receipt["signature"]=base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return receipt
    except (OSError, subprocess.SubprocessError) as exc:
        raise SlotRuntimeError("Node could not sign its V2 receipt") from exc


def execute_signed_slot_command(node: Path, command: dict, *,
                                clock=None,
                                reconcile_func=None,
                                signer=None) -> dict:
    """One verified root-locked slot update, live runtime check and node ACK.

    Direct invocation is forbidden without preinstalled AWG+watchdog and an
    independent root-protected release marker. The caller must have verified
    root ownership of the command file and node directory.
    """
    if not isinstance(command,dict):
        raise SlotRuntimeError("Expected a signed V2 JSON command")
    if clock is None:
        clock = v1.OfflineClock(node/"amneziawg"/"clock-highwater.json")
    if reconcile_func is None:
        reconcile_func = v1.reconcile
    if signer is None:
        signer = sign_slot_node_receipt

    with v1.LedgerLock(node):
        release_approved(node)
        v1.pinned_controller_key(node)
        now = clock.now()
        v2.validate_command(command,node.name,now)
        v2.verify_signature(command,v1.pinned_controller_key(node))

        old, current = load_ledgers(node)
        proposed = v2.transition(current,command,now)
        v2.merged_active_peers(old,proposed,now)
        awg_unit = unit_name(node.name)
        watchdog = "mnebyvpn-nodekit-awg-watchdog@" + node.name + ".service"
        if not active_unit(awg_unit) or not active_unit(watchdog):
            raise SlotRuntimeError("Both AmneziaWG and V2-aware watchdog must be running")

        path=node/"amneziawg"/SLOT_LEDGER
        v1.persist_state(path,proposed)
        try:
            applied=reconcile_func(node,old,now)
            if not isinstance(applied,dict) or applied.get("active") is not True:
                raise SlotRuntimeError("AWG V2 peer not applied to running interface")
            receipt=signer(node,command)
            return {
                "node_receipt":receipt,"active":True,
                "signed_command_verified":True,"published":False,
            }
        except BaseException:
            # A failed ACK/partial sync must never leave unchecked access.
            # The proposed ledger preserves the signed per-slot revision so
            # an old controller command cannot be replayed after restart.
            subprocess.run(["systemctl","stop",awg_unit],
                           capture_output=True,check=False,timeout=40)
            raise


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id",required=True)
    parser.add_argument("--mode",choices=("inspect","apply"),required=True)
    parser.add_argument("--command",type=Path)
    parser.add_argument("--stage-root",type=Path,default=v1.ROOT)
    args=parser.parse_args()
    try:
        if os.geteuid()!=0:
            raise SlotRuntimeError("Root-only signed V2 nodekit")
        node=args.stage_root/args.node_id
        v1.safe_dir(args.stage_root)
        v1.safe_dir(node)
        v1.safe_dir(node/"amneziawg")
        v1.validate_awg(node)
        release_approved(node)
        v1.pinned_controller_key(node)
        if args.mode=="inspect":
            with v1.LedgerLock(node):
                old,slots=load_ledgers(node)
                now=v1.OfflineClock(node/"amneziawg"/"clock-highwater.json").now()
                peers=v2.merged_active_peers(old,slots,now)
                print(json.dumps({
                    "v2_release":True,"node_id":node.name,
                    "active_peers":len(peers),"published":False,
                },sort_keys=True))
                return 0
        if args.command is None:
            raise SlotRuntimeError("Root-only signed command path required")
        command=json.loads(v1.protected_file(args.command,max_bytes=4096))
        result=execute_signed_slot_command(node,command)
        print(json.dumps(result,sort_keys=True,separators=(",",":")))
        return 0
    except (SlotRuntimeError,v1.GrantError,v2.SlotError,OSError,ValueError,
            subprocess.SubprocessError) as exc:
        print("AWG V2 access denied: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    sys.exit(main())
