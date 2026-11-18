#!/usr/bin/env python3
"""Read-only Nodekit AWG control-plane readiness audit.

Never generates keys, starts services, modifies firewall or publishes a
subscription. A missing controller public trust anchor is a normal blocker,
not permission to substitute an ephemeral key.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from awg_lifecycle import active_unit,enabled_unit,unit_name,validate as awg_validate
from install_awg_watchdog import unit as watchdog_unit
from awg_egress import unit_source as egress_unit
from awg_peer_grants import validate_state,protected_file,pinned_controller_key
from install_components import node_ready,safe_manifest

ROOT=Path("/var/lib/mnebyvpn-nodekit")
HEX64=re.compile(r"[0-9a-f]{64}\Z")
NODE_REVIEWED="fi-test-01"
HOST_REVIEWED="fi.mnebyvpn.site"

class ReadinessError(ValueError):
    pass

def optional_controller_spki(node:Path)->tuple[bool,str|None]:
    key=node/"controller-access.spki"
    if not key.exists() and not key.is_symlink():
        return False,None
    # Malformed or symlinked keys are an ERROR, never interpreted as
    # unconfigured and silently replaced.
    pinned_controller_key(node)
    return True,hashlib.sha256(protected_file(key,max_bytes=100)).hexdigest()

def source_is_installed(path:Path,expected:str)->bool:
    if not path.exists() and not path.is_symlink():
        return False
    if path.is_symlink() or not path.is_file():
        raise ReadinessError("Unexpected unit symlink")
    st=path.stat()
    if st.st_uid!=0 or st.st_mode&0o022 or not stat.S_ISREG(st.st_mode):
        raise ReadinessError("Untrusted installed systemd unit")
    if path.read_bytes()!=expected.encode():
        raise ReadinessError("Reviewed AWG systemd unit code drift")
    return True

def inspect(node:Path,hostname:str,expected_identity_sha:str,
            expected_controller_sha:str='')->dict:
    if os.geteuid()!=0 or node.name!=NODE_REVIEWED or hostname!=HOST_REVIEWED:
        raise ReadinessError("Only reviewed FI test node is supported")
    if not isinstance(expected_identity_sha,str) or not HEX64.fullmatch(expected_identity_sha):
        raise ReadinessError("Independent Ed25519 identity fingerprint required")
    awg_validate(node)
    manifest=safe_manifest(node/"manifest.json")
    if manifest.get("advertise_host")!=hostname:
        raise ReadinessError("Controller hostname differs from staged manifest")
    identity=protected_file(node/"identity"/"node-public.spki",max_bytes=100)
    expected=hashlib.sha256(identity).hexdigest()
    if expected!=expected_identity_sha or len(identity)!=44 or not identity.startswith(
            bytes.fromhex("302a300506032b6570032100")):
        raise ReadinessError("Node identity differs from reviewed inventory")
    pinned,controller_sha=optional_controller_spki(node)
    if expected_controller_sha and not HEX64.fullmatch(expected_controller_sha):
        raise ReadinessError("Invalid reviewed controller public key fingerprint")
    independently_pinned=bool(pinned and expected_controller_sha and
                              controller_sha==expected_controller_sha)
    if pinned and expected_controller_sha and not independently_pinned:
        raise ReadinessError("Installed controller public key differs from approved pin")
    directory=node/"amneziawg"
    ledger=directory/"peer-grants.json"
    state=(validate_state(json.loads(protected_file(ledger)),node.name)
           if ledger.exists() or ledger.is_symlink() else
           {"grants":{}})
    awg_unit=unit_name(node.name)
    watchdog="mnebyvpn-nodekit-awg-watchdog@"+node.name+".service"
    egress="mnebyvpn-nodekit-awg-egress@"+node.name+".service"
    disabled=all(not active_unit(name) and not enabled_unit(name)
                 for name in (awg_unit,watchdog,egress))
    watch_installed=source_is_installed(
        Path("/etc/systemd/system/mnebyvpn-nodekit-awg-watchdog@.service"),
        watchdog_unit())
    egress_installed=source_is_installed(
        Path("/etc/systemd/system/mnebyvpn-nodekit-awg-egress@.service"),
        egress_unit())
    if (Path("/run/nodekit-awg-fi-egress.json").exists() or
        Path("/run/nodekit-fi-awg-external.json").exists()):
        raise ReadinessError("Unexpected live NAT lease during controller audit")
    return {
        "node_id":node.name,
        "hostname":hostname,
        "node_identity_pinned":True,
        "node_identity_sha256":expected,
        "controller_public_key_installed":pinned,
        "controller_public_key_independently_pinned":independently_pinned,
        "controller_public_key_sha256":controller_sha,
        "watchdog_unit_installed":watch_installed,
        "egress_unit_installed":egress_installed,
        "services_inactive_and_disabled":disabled,
        "grant_ledger_count":len(state["grants"]),
        "subscriber_publication_enabled":False,
        "control_plane_prerequisites_met":bool(
            independently_pinned and watch_installed and egress_installed and disabled
            and not state["grants"]),
        "database_enrollment_verified":False,
        "external_client_entitlement_verified":False,
        "note":"DB enrollment and paid release require independent controller audit",
    }

def main()->int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id",required=True)
    p.add_argument("--host",required=True)
    p.add_argument("--expected-identity-sha256",required=True)
    p.add_argument("--expected-controller-sha256",default="")
    p.add_argument("--stage-root",type=Path,default=ROOT)
    a=p.parse_args()
    try:
        node=node_ready(a.stage_root,a.node_id)
        print(json.dumps(inspect(node,a.host,a.expected_identity_sha256,
                                 a.expected_controller_sha256),
                         sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError) as exc:
        print("NODEKIT_CONTROLLER_READINESS_ERROR="+type(exc).__name__,file=sys.stderr)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
