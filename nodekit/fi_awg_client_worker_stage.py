#!/usr/bin/env python3
"""RU188: stage independently pinned FI217 public-key registration worker.

Create a NEW immutable 6-source worker release with the already verified
isolated pg dependency graph. Never change active /current, effective systemd,
feature flags, paid accounts, customer peers, or the running FI217 node.
The existing effective old 5-source worker MUST be inactive and source-pinned.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

import fi_awg_worker_source_stage as trust
import fi_awg_worker_candidate_stage as candidate
import fi_awg_worker_candidate_runtime as runtime
import fi_awg_worker_systemd_cutover as cutover
import fi_awg_worker_isolated_source_stage as isolated

NEW="446c331249085adb6536e3d9913fb4b68abf6cd7"
RELEASES=Path("/opt/mnebyvpn-controller/awg-worker-releases")
RELEASE=RELEASES/NEW
STAGING=re.compile(r"/run/fi-awg-client-worker\.[A-Za-z0-9]{8}\Z")
MANIFEST="awg-client-worker-manifest.json"
FILES={
    "apps/service/src/awg-controller-delivery-worker.ts":
        "a49fb6498f878ade9ac81576c5c0f3c2440b626b",
    "packages/provisioning/src/awg-device-registration-worker.ts":
        "cc7aa1ef483c5b59a83946345fb2209dd34d6533",
    "packages/provisioning/src/awg-trusted-ssh-delivery.ts":
        "516706e898f6e59599172ce3c65d9f2295a4876e",
    "packages/provisioning/src/awg-offline-maintenance.ts":
        "e8829944ca4d27e1d8b8679efa681f6bb3abe373",
    "packages/provisioning/src/awg-controller-grants.ts":
        "9b37bb3e9528e6bab4144d36b4558ca61d544b41",
    "packages/provisioning/src/awg-controller-outbox.ts":
        "0b1c1f0906a0a11be8a1c466fa5eb173bd39906b",
}
WORKER="apps/service/src/awg-controller-delivery-worker.ts"
DEPENDENCY_MANIFEST=runtime.MARKER
LOCK=trust.ROOT/"awg-worker-source-stage.lock"


def independently_pinned(blob:bytes,expected:str)->bool:
    if not isinstance(blob,bytes) or len(blob)<1 or len(blob)>65536:
        return False
    return hashlib.sha1(
        b"blob "+str(len(blob)).encode("ascii")+b"\0"+blob
    ).hexdigest()==expected


def staged_inputs(stage:Path)->dict[str,bytes]:
    if not stage.is_absolute() or not STAGING.fullmatch(str(stage)):
        trust.stop("fi_client_worker_unapproved_stage_path")
    trust.safe_directory(stage)
    if not isinstance(FILES,dict) or len(FILES)!=6:
        trust.stop("fi_client_worker_invalid_pin_manifest")
    blobs={}
    for rel,git_id in FILES.items():
        if not re.fullmatch(r"[a-zA-Z0-9_./-]+\.ts",rel) or ".." in Path(rel).parts:
            trust.stop("fi_client_worker_untrusted_source_path")
        raw=trust.read_file(stage/rel)
        if not independently_pinned(raw,git_id):
            trust.stop("fi_client_worker_source_pin_mismatch")
        blobs[rel]=raw
    isolated.require_source_closure(blobs)
    candidate.verify_nonstandard_imports(blobs)
    # Other four signed-grant modules MUST stay byte-for-byte identical to
    # the previously reviewed and immutable 674338 release.
    for rel in set(FILES)-{WORKER,"packages/provisioning/src/awg-device-registration-worker.ts"}:
        if trust.read_file(candidate.CANDIDATE/rel)!=blobs[rel]:
            trust.stop("fi_client_worker_existing_signed_module_changed")
    return blobs


def expected_manifest(blobs:dict[str,bytes],dependency_manifest:bytes)->bytes:
    body={
        "commit":NEW,
        "reviewed_parent":candidate.CANDIDATE_COMMIT,
        "source_git_blobs":FILES,
        "source_sha256":{p:hashlib.sha256(v).hexdigest() for p,v in sorted(blobs.items())},
        "dependency_manifest_sha256":hashlib.sha256(dependency_manifest).hexdigest(),
    }
    return (json.dumps(body,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")


def reviewed_unit_bytes() -> tuple[bytes,bytes]:
    """Only the old reviewed unit and its verified 6-module cutover are valid."""
    old=cutover.expected_new_dropin()
    existing=str(candidate.CANDIDATE).encode("ascii")
    new_root=str(RELEASE).encode("ascii")
    if existing==new_root or old.count(existing)!=2:
        trust.stop("fi_client_worker_unapproved_cutover_template")
    return old,old.replace(existing,new_root)


def staged_artifacts_locked() -> str:
    """Verify either allowed inactive systemd state without re-locking flock."""
    trust.require_safe_dormant()
    cutover.verify_candidate_artifacts()
    old,new=reviewed_unit_bytes()
    actual=trust.read_file(cutover.systemd.OVERRIDE,8192)
    if actual==old:
        cutover.verified_new_effective_unit(old)
        if trust.read_file(candidate.CANDIDATE/WORKER)!=trust.read_file(
                cutover.ENTRY):
            trust.stop("fi_client_worker_effective_worker_not_baseline")
        return "OLD_INACTIVE"
    if actual==new:
        # Local import avoids a top-level cycle: the verifier imports this stage.
        import fi_awg_client_worker_cutover as clientcut
        clientcut.verify_unit(new)
        if trust.read_file(clientcut.BACKUP,8192)!=old:
            trust.stop("fi_client_worker_cutover_rollback_drift")
        return "NEW_INACTIVE"
    trust.stop("fi_client_worker_unrecognized_effective_unit")


def staged_artifacts() -> str:
    """Full preflight before locking; old or new release must be pinned."""
    old,_=reviewed_unit_bytes()
    if trust.read_file(cutover.systemd.OVERRIDE,8192)==old:
        cutover.verify()
    else:
        import fi_awg_client_worker_cutover as clientcut
        clientcut.verify()
    return staged_artifacts_locked()


def copy_file_exact(target:Path,blob:bytes)->bool:
    if target.exists() or target.is_symlink():
        if trust.read_file(target,max(65536,len(blob)+1))!=blob:
            trust.stop("fi_client_worker_existing_file_drift")
        return False
    isolated.write_new(target,blob)
    if trust.read_file(target,max(65536,len(blob)+1))!=blob:
        trust.stop("fi_client_worker_postwrite_mismatch")
    return True


def make_parents(target:Path)->None:
    base=RELEASE
    for name in target.parent.relative_to(RELEASE).parts:
        base=base/name
        if base.exists() or base.is_symlink():
            trust.safe_directory(base)
        else:
            trust.make_directory(base)


def source_and_runtime_check(blobs:dict[str,bytes]) -> None:
    # Check the new source files independently from the old release's pins.
    for relative,blob in blobs.items():
        if trust.read_file(RELEASE/relative)!=blob:
            trust.stop("fi_client_worker_source_drift")
    # Check the entire copied pg dependency tree against independently
    # verified source hashes; no links into mutable /current.
    dep=json.loads(trust.read_file(DEPENDENCY_MANIFEST,256000))
    for relative,digest in dep["files"].items():
        if not isinstance(relative,str) or not isinstance(digest,str) or ".." in Path(relative).parts:
            trust.stop("fi_client_worker_dependency_manifest_invalid")
        raw=trust.read_file(RELEASE/"node_modules"/relative,runtime.pgstage.MAX_FILE_BYTES)
        if hashlib.sha256(raw).hexdigest()!=digest:
            trust.stop("fi_client_worker_dependency_drift")
    node=runtime.runtime.trusted_node_binary()
    for relative in blobs:
        runtime.runtime.command_ok([
            str(node),"--experimental-strip-types","--check",
            str(RELEASE/relative),
        ],timeout=10)
    # Import only. Production main() is gated by process.argv[1] and does
    # not run. The import must resolve the new sixth module and isolated pg.
    code=(
        "import {pathToFileURL} from 'node:url';"
        "if(process.argv[1]!=='__AWG_IMPORT_ONLY__'||!process.argv[2])"
        "process.exit(9);"
        "await import(pathToFileURL(process.argv[2]).href);"
    )
    runtime.runtime.command_ok([
        str(node),"--experimental-strip-types","--input-type=module",
        "-e",code,"__AWG_IMPORT_ONLY__",str(RELEASE/WORKER),
    ],timeout=18)


def stage(stage_path:Path)->tuple[int,int,str]:
    staged_artifacts()
    blobs=staged_inputs(stage_path)
    deps=trust.read_file(DEPENDENCY_MANIFEST,256000)
    info=json.loads(deps)
    if info.get("commit")!=candidate.CANDIDATE_COMMIT:
        trust.stop("fi_client_worker_dependency_base_mismatch")
    manifest=expected_manifest(blobs,deps)
    fd=os.open(LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or (
                meta.st_mode&0o077) or meta.st_nlink!=1:
            trust.stop("fi_client_worker_untrusted_lock")
        # A previous interrupted stage may still hold this lock. Fail
        # promptly instead of hanging an entire GitHub Actions deployment.
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            trust.stop("fi_client_worker_source_lock_busy")
        current_mode=staged_artifacts_locked()
        if not RELEASE.exists():
            trust.make_directory(RELEASE)
        else:
            trust.safe_directory(RELEASE)
        marker=RELEASE/MANIFEST
        if marker.exists() or marker.is_symlink():
            if trust.read_file(marker,4096)!=manifest:
                trust.stop("fi_client_worker_published_manifest_changed")
        new=matched=0
        for rel,raw in sorted(blobs.items()):
            target=RELEASE/rel
            make_parents(target)
            if copy_file_exact(target,raw): new+=1
            else: matched+=1
        for rel,digest in sorted(info["files"].items()):
            if not isinstance(rel,str) or not re.fullmatch(
                r"(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+",rel):
                trust.stop("fi_client_worker_bad_dependency_path")
            raw=trust.read_file(runtime.MODULES/rel,runtime.pgstage.MAX_FILE_BYTES)
            if hashlib.sha256(raw).hexdigest()!=digest:
                trust.stop("fi_client_worker_unapproved_pg_package")
            target=RELEASE/"node_modules"/rel
            make_parents(target)
            if copy_file_exact(target,raw): new+=1
            else: matched+=1
        source_and_runtime_check(blobs)
        if not (marker.exists() or marker.is_symlink()):
            copy_file_exact(marker,manifest)
        else:
            if trust.read_file(marker,4096)!=manifest:
                trust.stop("fi_client_worker_manifest_drift")
        if staged_artifacts_locked()!=current_mode:
            trust.stop("fi_client_worker_cutover_changed_during_stage")
        return new,matched,current_mode
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)


def main() -> None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--stage",type=Path,required=True)
    args=parser.parse_args()
    new,matched,mode=stage(args.stage)
    print(f"FI_AWG_CLIENT_WORKER=STAGED;COMMIT={NEW};NEW={new};MATCHED={matched};"
          f"IMPORT=VERIFIED;EFFECTIVE_WORKER={mode};"
          "CLIENT_RELEASE=false;REAL_PEERS_MODIFIED=false")


if __name__=="__main__":
    try:
        main()
    except (trust.StageBlocked,OSError,ValueError,TypeError,KeyError,
            UnicodeError,RuntimeError):
        raise SystemExit(2)
