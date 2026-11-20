#!/usr/bin/env python3
"""Issue FI217 signed runtime admission using the existing RU188 Ed25519 key.

Signer never leaves RU188; this approval does NOT grant users or release VPN.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from fi_awg_production_policy import approval_message, verify_approval
import fi_awg_signed_canary as trust

MATERIAL_KEYS={"nodeId","endpointHost","configSha256","serverPublicKeySha256","sourceBinarySha256"}
HEXDIGEST=re.compile(r"[a-f0-9]{64}\Z")

class Refused(ValueError):
    pass

def material_file(path: Path) -> dict:
    raw=trust.protected(path,4096)
    try: obj=json.loads(raw)
    except (ValueError,UnicodeDecodeError):raise Refused("material invalid")
    if (not isinstance(obj,dict) or set(obj)!=MATERIAL_KEYS or
        obj["nodeId"]!="fi-test-01" or
        obj["endpointHost"]!="fi.mnebyvpn.site" or
        any(not isinstance(obj[field],str) or not HEXDIGEST.fullmatch(obj[field])
            for field in ("configSha256","serverPublicKeySha256")) or
        not isinstance(obj["sourceBinarySha256"],dict) or
        set(obj["sourceBinarySha256"])!={"awg","awg-quick","amneziawg-go"} or
        any(not isinstance(v,str) or not HEXDIGEST.fullmatch(v)
            for v in obj["sourceBinarySha256"].values())):
        raise Refused("material identity mismatch")
    return obj

def signed(material:dict)->dict:
    if not trust.is_host(trust.RU_IP):raise Refused("wrong signing host")
    public=trust.pinned_spki(trust.RU_ROOT/"controller-public.spki",trust.CONTROLLER_SHA)
    private=trust.RU_ROOT/"controller-signing-key.pem"
    trust.protected(private,8192)
    trust.pinned_spki(trust.RU_ROOT/"fi-node-public.spki",trust.NODE_SHA)
    match=subprocess.run(
        ["/usr/bin/openssl","pkey","-in",str(private),"-pubout","-outform","DER"],
        stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=8)
    if match.stdout!=public:raise Refused("signer identity differs from enrolled controller")
    # Signature field is a strict placeholder while building the canonical
    # message. OpenSSL signs the exact production policy's own serialization.
    approval={
        "schemaVersion":1,"nodeId":material["nodeId"],
        "endpointHost":material["endpointHost"],
        "configSha256":material["configSha256"],
        "serverPublicKeySha256":material["serverPublicKeySha256"],
        "sourceBinarySha256":material["sourceBinarySha256"],
        "approvalRevision":1,"signature":"A"*86,
    }
    payload=approval_message(approval)
    with tempfile.TemporaryDirectory(prefix="fi217-production-sign-",dir="/run") as t:
        source=Path(t)/"message"
        source.write_bytes(payload)
        source.chmod(0o600)
        result=subprocess.run(
            ["/usr/bin/openssl","pkeyutl","-sign","-inkey",str(private),
             "-rawin","-in",str(source)],
            stdin=subprocess.DEVNULL,capture_output=True,check=True,timeout=8)
    if len(result.stdout)!=64:raise Refused("invalid signing output")
    approval["signature"]=base64.urlsafe_b64encode(result.stdout).rstrip(b"=").decode()
    verify_approval(approval,public)
    return approval

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--material",type=Path,required=True)
    args=p.parse_args()
    try:
        if os.geteuid()!=0:raise Refused("root required")
        approval=signed(material_file(args.material))
        # Workflow redirects stdout into a mode-0600 file; NEVER log payload.
        print(json.dumps(approval,sort_keys=True,separators=(",",":")))
        return 0
    except (OSError,TypeError,ValueError,KeyError,subprocess.SubprocessError,
            trust.CanaryError):
        print("FI_AWG_APPROVAL=BLOCKED;CLIENT_RELEASE=false",file=sys.stderr)
        return 2

if __name__=="__main__":
    sys.exit(main())
