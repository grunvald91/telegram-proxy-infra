#!/usr/bin/env python3
"""FI217 signed production-mode admission, independent of subscriber release.

The controller approves exactly one immutable, already-tested AWG binary and
configuration identity. A node may start persistently only when its root-owned
approval has a verifiable Ed25519 signature from the *enrolled* controller.
No secrets are read from other nodes, no network calls, and no state changes.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from install_components import safe_manifest

NODE="fi-test-01"
HOST="fi.mnebyvpn.site"
SPKI_HEADER=bytes.fromhex("302a300506032b6570032100")
KEY=re.compile(r"[A-Za-z0-9+/]{43}=\Z")
SHA=re.compile(r"[a-f0-9]{64}\Z")
SIGNATURE=re.compile(r"[A-Za-z0-9_-]{86}\Z")
BINARIES={"awg","awg-quick","amneziawg-go"}
POLICY_KEYS={
    "schemaVersion","nodeId","endpointHost","configSha256",
    "serverPublicKeySha256","sourceBinarySha256","approvalRevision","signature",
}

class ProductionAdmissionError(ValueError):
    pass

def deny()->None:
    raise ProductionAdmissionError("FI217 signed production approval missing or invalid")

def canonical_key(value:object)->bytes:
    if not isinstance(value,str) or not KEY.fullmatch(value):
        deny()
    try:
        decoded=base64.b64decode(value,validate=True)
        if len(decoded)!=32 or base64.b64encode(decoded).decode()!=value or not any(decoded):
            deny()
        return decoded
    except (ValueError,base64.binascii.Error):
        deny()

def approval_message(approval:dict)->bytes:
    if (not isinstance(approval,dict) or set(approval)!=POLICY_KEYS or
        type(approval["schemaVersion"]) is not int or approval["schemaVersion"]!=1 or
        approval["nodeId"]!=NODE or approval["endpointHost"]!=HOST or
        type(approval["approvalRevision"]) is not int or
        not 1<=approval["approvalRevision"]<=1_000_000_000 or
        not all(isinstance(approval[k],str) and SHA.fullmatch(approval[k])
                for k in ("configSha256","serverPublicKeySha256")) or
        not isinstance(approval["sourceBinarySha256"],dict) or
        set(approval["sourceBinarySha256"])!=BINARIES or
        not all(isinstance(v,str) and SHA.fullmatch(v)
                for v in approval["sourceBinarySha256"].values()) or
        not isinstance(approval["signature"],str) or
        not SIGNATURE.fullmatch(approval["signature"])):
        deny()
    return json.dumps([
        "MNEBYVPN_FI_AWG_PRODUCTION_V1",
        approval["schemaVersion"],approval["nodeId"],approval["endpointHost"],
        approval["configSha256"],approval["serverPublicKeySha256"],
        [approval["sourceBinarySha256"][name] for name in sorted(BINARIES)],
        approval["approvalRevision"],
    ],separators=(",",":"),ensure_ascii=True).encode("ascii")

def verify_approval(approval:dict,public_spki:bytes, *,
                    runner=subprocess.run)->None:
    message=approval_message(approval)
    if (not isinstance(public_spki,bytes) or len(public_spki)!=44 or
        not public_spki.startswith(SPKI_HEADER)):
        deny()
    try:
        signature=base64.urlsafe_b64decode(approval["signature"]+"==")
    except (ValueError,base64.binascii.Error):
        deny()
    if (len(signature)!=64 or
        base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")!=
        approval["signature"]):
        deny()
    with tempfile.TemporaryDirectory(prefix="fi-awg-production-verify-") as temp:
        root=Path(temp)
        key=root/"controller.spki"
        sig=root/"signature"
        msg=root/"message"
        key.write_bytes(public_spki)
        sig.write_bytes(signature)
        msg.write_bytes(message)
        try:
            proof=runner([
                "/usr/bin/openssl","pkeyutl","-verify","-pubin",
                "-inkey",str(key),"-keyform","DER","-rawin",
                "-in",str(msg),"-sigfile",str(sig),
            ],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
              check=False,timeout=8)
            if proof.returncode!=0:
                deny()
        except (OSError,subprocess.TimeoutExpired):
            deny()

def admit(node:Path,manifest:dict,awg:dict, *, runner=subprocess.run)->dict:
    if (node.name!=NODE or
        manifest.get("node_id")!=NODE or
        manifest.get("advertise_host")!=HOST or
        manifest.get("state")!="active" or
        manifest.get("activation_enabled") is not True or
        manifest.get("registration_enabled") is not True or
        not isinstance(manifest.get("roles"),list) or
        not {"vpn","dns","sni-proxy","tunnel"}.issubset(set(manifest["roles"])) or
        awg.get("node_id")!=NODE or awg.get("state")!="active" or
        awg.get("activation_enabled") is not True or
        awg.get("peers_enabled") is not True or
        awg.get("subscribers_enabled") is not False):
        deny()
    # Public website publication is controlled independently on RU188.
    # In particular, a signed FI *runtime* approval is NOT a subscriber grant.
    policy=safe_manifest(node/"amneziawg"/"production-approval.json")
    if not isinstance(policy,dict):
        deny()
    message=approval_message(policy)
    del message
    if (policy["configSha256"]!=awg.get("config_sha256") or
        policy["sourceBinarySha256"]!=awg.get("source_binary_sha256") or
        policy["serverPublicKeySha256"]!=hashlib.sha256(
            canonical_key(awg.get("server_public_key"))).hexdigest()):
        deny()
    # Existing pinned root-only controller SPKI is the same trust used by the
    # signed grant/revoke verifier. Never download a live key from RU188 here.
    from awg_lifecycle import checked_file
    pinned=checked_file(node/"controller-access.spki",100)
    verify_approval(policy,pinned,runner=runner)
    return {
        "production_approval":"signed",
        "node_id":NODE,
        "approved_binary_identity":"pinned",
        "approved_config_identity":"pinned",
        "customer_release":False,
    }
