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
import stat
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
LEGACY_AUTHORIZER_SHA256="e22d603c73502cf91bf4d2a808aaaf55eda48675322354f74e0e39118dd00aac"
CANDIDATE_AUTHORIZER_SHA256="ee320dde6828271e99fcdea5faa04f1f2e3395f61f268eba9550c2eb82c0e1d4"

class CanaryBlocked(ValueError):
    pass

def phase(value: str) -> None:
    """Emit only fixed non-secret phase markers, even for unexpected failures."""
    print("FI_AWG_APPLY_PHASE=" + value, file=sys.stderr, flush=True)

def block(code:str)->None:
    # Only fixed enum reason; do not echo commands, keys or receipts.
    print("FI_AWG_APPLY_CANARY_BLOCKED="+code,file=sys.stderr)
    raise CanaryBlocked(code)

def command(args:list[str],timeout:int=20)->subprocess.CompletedProcess:
    try:
        return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
    except (OSError,subprocess.TimeoutExpired):
        block("local_service_command_unavailable")

def systemd_active_state(unit:str)->str:
    check=command(["/usr/bin/systemctl","show","-p","ActiveState","--value",unit],9)
    value=check.stdout.strip()
    return value if (check.returncode==0 and value in
                     {"inactive","active","failed","activating","deactivating","reloading"}) else "unknown"

def inactive(unit:str)->bool:
    return systemd_active_state(unit)=="inactive"

def call_or_block(args:list[str],reason:str,timeout:int=20)->str:
    result=command(args,timeout)
    if result.returncode:
        block(reason)
    return result.stdout

def residual_ledger_status() -> str:
    """Read-only summary: never print entitlement IDs or public peer keys."""
    if LEDGER.is_symlink():
        return "SYMLINK_UNTRUSTED"
    if not LEDGER.exists():
        return "ABSENT"
    try:
        from awg_peer_grants import validate_state
        state = validate_state(json.loads(canary.protected(LEDGER, 50000)), NODE)
        rows = list(state["grants"].values())
        if not rows:
            return "VALID_EMPTY"
        if (len(rows) == 1 and rows[0]["clientIpv4"] == CLIENT_IP and
            rows[0]["enabled"] is False and rows[0]["expiresAt"] is None and
            rows[0]["revision"] == 2):
            return "ONLY_REVOKED_DISPOSABLE"
        return "OTHER_ENTITLEMENTS_PRESENT"
    except (OSError,ValueError,TypeError,KeyError):
        return "UNVERIFIED"

def recover_revoked_previous_canary(states:dict,interface_present:bool,
                                   ledger_status:str)->bool:
    """Safely archive only the known inactive, revoked FI test residue.

    Never touch a running interface, enabled grant, arbitrary ledger, or the
    independent kill timer. No rollback into a client's live data path.
    """
    if not (states == {"AWG":"failed","WATCHDOG":"inactive","TIMER":"inactive"} and
            not interface_present and ledger_status=="ONLY_REVOKED_DISPOSABLE"):
        return False
    if not canary.is_host(canary.FI_IP):
        block("prior_canary_recovery_wrong_host")
    old=canary.protected(LEDGER,50000)
    digest=hashlib.sha256(old).hexdigest()
    archive=LEDGER.with_name(".peer-grants.fi217-revoked-"+digest[:20]+".bak")
    if archive.exists() or archive.is_symlink():
        block("prior_canary_archive_already_exists")
    if systemd_active_state(UNIT)!="failed" or systemd_active_state(WATCHDOG)!="inactive":
        block("prior_canary_status_changed")
    if Path("/sys/class/net/awg0").exists() or residual_ledger_status()!="ONLY_REVOKED_DISPOSABLE":
        block("prior_canary_data_changed")
    phase("PRIOR_REVOKED_CANARY_ARCHIVE_BEGIN")
    os.rename(LEDGER,archive)
    try:
        # Durable atomic archive before clearing the stale systemd failure flag.
        fd=os.open(LEDGER.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        if command(["/usr/bin/systemctl","reset-failed",UNIT],9).returncode:
            block("prior_canary_reset_failed_failed")
        if (systemd_active_state(UNIT)!="inactive" or
            systemd_active_state(WATCHDOG)!="inactive" or
            systemd_active_state(TIMER+".timer")!="inactive" or
            LEDGER.exists() or Path("/sys/class/net/awg0").exists()):
            block("prior_canary_reset_postcheck_failed")
    except BaseException:
        # Preserve prior proof if reset-failed did not establish safe readiness.
        if not LEDGER.exists() and archive.exists():
            os.rename(archive,LEDGER)
        raise
    phase("PRIOR_REVOKED_CANARY_ARCHIVED_AND_UNIT_RESET")
    return True

def preflight(bundle:Path)->dict:
    if not canary.is_host(canary.FI_IP):
        block("not_pinned_fi217_root")
    # The real FI-only local state machine verifies the two RU signatures
    # against the pinned controller public SPKI BEFORE any AWG start.
    canary.node_verify(bundle,announce=False)
    phase("SIGNED_COMMANDS_VERIFIED")
    from awg_lifecycle import validate
    validate(canary.FI_NODE)
    phase("STAGED_AWG_INTEGRITY_VERIFIED")
    states={}
    for label,unit in (("AWG",UNIT),("WATCHDOG",WATCHDOG),("TIMER",TIMER+".timer")):
        states[label]=systemd_active_state(unit)
        phase("PREFLIGHT_"+label+"_STATE_"+states[label].upper())
    # Report ALL residual categories before blocking: a failed systemd unit
    # must never hide whether the previous disposable ledger survived.
    interface_present=Path("/sys/class/net/awg0").exists()
    ledger_status=residual_ledger_status()
    phase("PREFLIGHT_INTERFACE_"+("PRESENT" if interface_present else "ABSENT"))
    phase("PREFLIGHT_LEDGER_"+ledger_status)
    if recover_revoked_previous_canary(states,interface_present,ledger_status):
        states["AWG"]="inactive"
        ledger_status="ABSENT"
    if any(state != "inactive" for state in states.values()):
        block("existing_awg_or_expiry_timer")
    phase("SYSTEMD_DORMANT_VERIFIED")
    if ledger_status != "ABSENT":
        block("existing_awg_peer_ledger")
    if interface_present:
        block("unexpected_live_awg_interface")
    data=json.loads(canary.protected(bundle,6000))
    if (data["grant"]["peerPublicKey"] != data["revoke"]["peerPublicKey"] or
        data["grant"]["clientIpv4"] != CLIENT_IP or
        data["grant"]["expiresAt"] is None or
        data["revoke"]["expiresAt"] is not None):
        block("unexpected_signed_disposable_peer")
    phase("DISPOSABLE_PREFLIGHT_PASSED")
    return data

def watchdog_file_state(path: Path, expected: bytes) -> str:
    """Read-only, non-secret diagnostic for an immutable installation target."""
    if path.is_symlink():
        return "SYMLINK"
    if not path.exists():
        return "MISSING"
    if not path.is_file():
        return "NOT_FILE"
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        return "UNTRUSTED"
    return "MATCH" if path.read_bytes() == expected else "DRIFT"

def authorizer_upgrade_allowed(old_code: bytes, new_code: bytes) -> bool:
    return (hashlib.sha256(old_code).hexdigest() == LEGACY_AUTHORIZER_SHA256 and
            hashlib.sha256(new_code).hexdigest() == CANDIDATE_AUTHORIZER_SHA256)

def migrate_pinned_authorizer(source: Path) -> None:
    """One-off root-only, dormant FI217 migration of a precisely pinned file.

    A backup is retained at the old pinned SHA. Unknown revisions and unsafe
    ownership abort. This does NOT activate any AWG or subscription.
    """
    if not canary.is_host(canary.FI_IP):
        block("authorizer_upgrade_wrong_host")
    if not all(inactive(name) for name in (UNIT, WATCHDOG, TIMER + ".timer")):
        block("authorizer_upgrade_service_active")
    for name in (UNIT, WATCHDOG):
        enabled = command(["/usr/bin/systemctl", "is-enabled", "--quiet", name], 8)
        if enabled.returncode == 0:
            block("authorizer_upgrade_service_enabled")
    if Path("/sys/class/net/awg0").exists() or LEDGER.exists() or LEDGER.is_symlink():
        block("authorizer_upgrade_runtime_not_empty")
    home = APP.parent
    parent_stat = home.lstat()
    file_stat = APP.lstat()
    if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != 0 or
        parent_stat.st_mode & 0o022 or
        not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != 0 or
        file_stat.st_mode & 0o077 or file_stat.st_nlink != 1):
        block("authorizer_upgrade_untrusted_install")
    before = APP.read_bytes()
    candidate = source.read_bytes()
    if not authorizer_upgrade_allowed(before, candidate):
        block("authorizer_upgrade_digest_not_allowlisted")
    # The old version stays available for explicit guarded rollback.
    backup = home / (".awg_peer_grants.fi217-legacy-" +
                     LEGACY_AUTHORIZER_SHA256[:16] + ".bak")
    if backup.exists() or backup.is_symlink():
        block("authorizer_upgrade_backup_already_exists")
    try:
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(before)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        block("authorizer_upgrade_backup_write_failed")
    if hashlib.sha256(backup.read_bytes()).hexdigest() != LEGACY_AUTHORIZER_SHA256:
        block("authorizer_upgrade_backup_verification_failed")
    try:
        fd, filename = tempfile.mkstemp(prefix=".fi-awg-authorizer-", dir=home)
    except OSError:
        backup.unlink(missing_ok=True)
        block("authorizer_upgrade_temp_write_failed")
    swapped = False
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(candidate)
            handle.flush()
            os.fsync(handle.fileno())
        if (not all(inactive(name) for name in (UNIT, WATCHDOG)) or
            Path("/sys/class/net/awg0").exists() or LEDGER.exists()):
            block("authorizer_upgrade_runtime_changed")
        os.replace(filename, APP)
        swapped = True
        directory_fd = os.open(home, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if (APP.is_symlink() or not APP.is_file() or
            hashlib.sha256(APP.read_bytes()).hexdigest() != CANDIDATE_AUTHORIZER_SHA256):
            block("authorizer_upgrade_postcheck_failed")
    except BaseException:
        if swapped and backup.is_file() and not backup.is_symlink() and (
            not Path("/sys/class/net/awg0").exists() and
            all(inactive(name) for name in (UNIT, WATCHDOG))):
            # Restore the immutable old code if verification of swap fails.
            os.replace(backup, APP)
        raise
    finally:
        Path(filename).unlink(missing_ok=True)
    phase("WATCHDOG_AUTHORIZER_PINNED_MIGRATION_APPLIED")

def install_watchdog()->None:
    from install_awg_watchdog import install, unit, UNIT
    source = Path(__file__).with_name("awg_peer_grants.py")
    # Check existing on-disk assets *without* rewriting either one.
    # Only bounded fixed enum names are printed: no source, paths or hashes.
    source_ready = (source.is_file() and not source.is_symlink() and
                    source.stat().st_uid == 0)
    phase("WATCHDOG_SOURCE_" + ("TRUSTED" if source_ready else "UNTRUSTED"))
    if not source_ready:
        block("watchdog_source_untrusted")
    installed_authorizer = watchdog_file_state(APP, source.read_bytes())
    installed_unit = watchdog_file_state(UNIT, unit().encode())
    phase("WATCHDOG_AUTHORIZER_" + installed_authorizer)
    phase("WATCHDOG_SYSTEMD_UNIT_" + installed_unit)
    if installed_authorizer == "DRIFT":
        # Public code digest only, never source text, certificates or keys.
        # This fingerprint will be pinned before an offline-only migration.
        phase("WATCHDOG_AUTHORIZER_OLD_SHA256_" + hashlib.sha256(APP.read_bytes()).hexdigest())
        phase("WATCHDOG_AUTHORIZER_NEW_SHA256_" + hashlib.sha256(source.read_bytes()).hexdigest())
    if installed_authorizer == "DRIFT":
        migrate_pinned_authorizer(source)
        installed_authorizer = watchdog_file_state(APP, source.read_bytes())
        if installed_authorizer != "MATCH":
            block("watchdog_authorizer_migration_not_verified")
    elif installed_authorizer not in ("MISSING", "MATCH"):
        block("watchdog_authorizer_install_drift")
    if installed_unit not in ("MISSING", "MATCH"):
        block("watchdog_systemd_unit_install_drift")
    install(canary.FI_NODE, source)
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
    # Keep the independent 95-second kill timer armed on ANY unproven cleanup.
    # Never display a peer identifier, user key, signed grant, file content,
    # or untrusted journal line; only fixed state-category markers.
    for label,unit in (("WATCHDOG",WATCHDOG),("AWG",UNIT)):
        result=command(["/usr/bin/systemctl","stop",unit],35)
        phase("CLEANUP_STOP_"+label+("_OK" if result.returncode==0 else "_FAILED"))
    observed={}
    for label,unit in (("WATCHDOG",WATCHDOG),("AWG",UNIT)):
        state=systemd_active_state(unit)
        observed[label]=state
        phase("CLEANUP_"+label+"_STATE_"+state.upper())
        # systemd can mark the oneshot AWG unit FAILED if the watchdog
        # already tore down its interface. Treat this as pending cleanup,
        # never as success, until the interface and ledger are verified.
        if (label=="WATCHDOG" and state!="inactive") or (
            label=="AWG" and state not in ("inactive","failed")):
            return False
    if Path("/sys/class/net/awg0").exists():
        phase("CLEANUP_AWG_INTERFACE_PRESENT")
        return False
    phase("CLEANUP_AWG_INTERFACE_ABSENT")
    if LEDGER.exists() or LEDGER.is_symlink():
        phase("CLEANUP_PEER_LEDGER_PRESENT")
        try:
            from awg_peer_grants import validate_state
            data=validate_state(json.loads(canary.protected(LEDGER,50000)),NODE)
            rows=data["grants"]
            if (set(rows)!={expected["entitlementId"]} or
                rows[expected["entitlementId"]]["peerPublicKey"]!=expected["peerPublicKey"] or
                rows[expected["entitlementId"]]["clientIpv4"]!=CLIENT_IP or
                rows[expected["entitlementId"]]["revision"] != 2 or
                rows[expected["entitlementId"]]["enabled"] is not False or
                rows[expected["entitlementId"]]["expiresAt"] is not None):
                phase("CLEANUP_LEDGER_NOT_EXACT_TEST_ENTITLEMENT")
                return False
            LEDGER.unlink()
            phase("CLEANUP_TEST_LEDGER_REMOVED")
        except (OSError,ValueError,TypeError,KeyError) as exc:
            phase("CLEANUP_LEDGER_ERROR_"+type(exc).__name__.upper())
            return False
    else:
        phase("CLEANUP_PEER_LEDGER_ABSENT")
    if LEDGER.exists() or Path("/sys/class/net/awg0").exists():
        phase("CLEANUP_POSTCONDITION_CHANGED")
        return False
    if observed["AWG"]=="failed":
        if command(["/usr/bin/systemctl","reset-failed",UNIT],9).returncode:
            phase("CLEANUP_AWG_RESET_FAILED")
            return False
        state=systemd_active_state(UNIT)
        phase("CLEANUP_AWG_AFTER_RESET_"+state.upper())
        if state!="inactive":
            return False
    timer=command(["/usr/bin/systemctl","stop",TIMER+".timer"],9)
    phase("CLEANUP_TIMER_STOP_"+("OK" if timer.returncode==0 else "FAILED"))
    state=systemd_active_state(TIMER+".timer")
    phase("CLEANUP_TIMER_STATE_"+state.upper())
    return timer.returncode==0 and state=="inactive"

def real_roundtrip(bundle:Path)->dict:
    data=preflight(bundle)
    phase("WATCHDOG_INSTALL_BEGIN")
    install_watchdog()
    phase("WATCHDOG_INSTALLED")
    # One-shot systemd timer independent of GitHub, SSH, Python and RU188.
    # If a process dies mid-apply, the node is forcibly disconnected.
    call_or_block([
      "/usr/bin/systemd-run","--quiet","--collect",
      "--unit="+TIMER,"--on-active=95s",
      "/usr/bin/systemctl","stop",WATCHDOG,UNIT
    ],"disposable_timeout_not_armed",12)
    phase("INDEPENDENT_KILL_TIMER_ARMED")
    cleaned=False
    output=None
    try:
        call_or_block(["/usr/bin/systemctl","start",UNIT],
                      "temporary_awg_start_failed",48)
        phase("AWG_STARTED")
        call_or_block(["/usr/bin/systemctl","start",WATCHDOG],
                      "offline_expiry_watchdog_start_failed",22)
        if any(inactive(unit) for unit in (UNIT,WATCHDOG)):
            block("watchdog_or_awg_did_not_stay_active")
        phase("WATCHDOG_STARTED")
        with tempfile.TemporaryDirectory(prefix="fi-awg-applied-",dir="/run") as folder:
            root=Path(folder)
            grant=run_apply(data["grant"],root)
            phase("SIGNED_GRANT_APPLIED")
            peer_state=live_peers()
            want=data["grant"]["peerPublicKey"]+"\t"+CLIENT_IP+"/32"
            if peer_state.split()!=want.split():
                block("grant_not_present_in_real_awg_table")
            revoke=run_apply(data["revoke"],root)
            phase("SIGNED_REVOKE_APPLIED")
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
    phase("DISPOSABLE_CLEANUP_VERIFIED")
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
            KeyError,OSError,UnicodeError,subprocess.SubprocessError) as exc:
        # Never expose exception messages: they could contain protected paths,
        # subprocess arguments, or command material. Only the type is public.
        print("FI_AWG_APPLY_FAILURE_CLASS=" + type(exc).__name__,
              file=sys.stderr, flush=True)
        raise SystemExit(2)
