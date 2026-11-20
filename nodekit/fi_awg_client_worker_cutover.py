#!/usr/bin/env python3
"""RU188 atomic cutover of INACTIVE FI AWG worker to pinned 6-module release.

Uses the existing unchanged systemd sandbox, approval marker and isolated
PostgreSQL credentials. Never starts/enables worker, changes client release
flag or touches customer peers. On any failed postcondition restores the
previous verified 674338 worker definition and reloads systemd.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import sys

import fi_awg_worker_source_stage as trust
import fi_awg_worker_candidate_stage as candidate
import fi_awg_worker_systemd_cutover as oldcut
import fi_awg_worker_isolated_systemd_stage as systemd
import fi_awg_worker_isolated_source_stage as isolated
import fi_awg_client_worker_stage as client

BACKUP=oldcut.BACKUP_DIR/("fi217-"+candidate.CANDIDATE_COMMIT+"-client-worker.conf.backup")


def dropins()->tuple[bytes,bytes]:
    old=oldcut.expected_new_dropin()
    base=str(candidate.CANDIDATE)
    upgraded=str(client.RELEASE)
    if base==upgraded or old.count(base)!=2:
        trust.stop("client_cutover_unexpected_old_dropin")
    return old,old.replace(base.encode("ascii"),upgraded.encode("ascii"))


def verified_new_artifacts()->None:
    trust.require_safe_dormant()
    oldcut.verify_candidate_artifacts()
    blobs={}
    for rel,digest in client.FILES.items():
        raw=trust.read_file(client.RELEASE/rel)
        if not client.independently_pinned(raw,digest):
            trust.stop("client_cutover_source_no_longer_pinned")
        blobs[rel]=raw
    client.isolated.require_source_closure(blobs)
    candidate.verify_nonstandard_imports(blobs)
    marker=client.expected_manifest(
        blobs,trust.read_file(client.DEPENDENCY_MANIFEST,256000))
    if trust.read_file(client.RELEASE/client.MANIFEST,4096)!=marker:
        trust.stop("client_cutover_manifest_missing_or_changed")
    client.source_and_runtime_check(blobs)


def verify_unit(expected:bytes)->None:
    systemd.dormant_and_disabled()
    systemd.approved_base_unit()
    if trust.read_file(systemd.OVERRIDE,8192)!=expected:
        trust.stop("client_cutover_dropin_bytes_changed")
    if systemd.show("DropInPaths").split()!=[str(systemd.OVERRIDE)]:
        trust.stop("client_cutover_extra_systemd_dropin")
    if systemd.show("WorkingDirectory")!=str(client.RELEASE):
        trust.stop("client_cutover_effective_workdir_wrong")
    if systemd.show("NeedDaemonReload")!="no" or systemd.show("LoadState")!="loaded":
        trust.stop("client_cutover_systemd_not_loaded")
    details=systemd.show("ExecStart")
    expected_command=(str(trust.CURRENT/"bin/node")+
        " --experimental-strip-types "+str(client.RELEASE/client.WORKER))
    matches=re.findall(r"(?:^|[;{]\s*)argv\[\]=([^;]+)",details)
    if len(matches)!=1 or details.count("argv[]=")!=1 or (
        matches[0].strip()!=expected_command) or (
        "path="+str(trust.CURRENT/"bin/node")) not in details:
        trust.stop("client_cutover_executable_not_exact")
    systemd.dormant_and_disabled()


def save_backup(old:bytes)->None:
    if not oldcut.BACKUP_DIR.exists():
        trust.stop("client_cutover_original_backup_dir_missing")
    trust.safe_directory(oldcut.BACKUP_DIR)
    if BACKUP.exists() or BACKUP.is_symlink():
        if trust.read_file(BACKUP,8192)!=old:
            trust.stop("client_cutover_existing_rollback_changed")
    else:
        isolated.write_new(BACKUP,old)
    if trust.read_file(BACKUP,8192)!=old:
        trust.stop("client_cutover_backup_not_durable")


def rollback(old:bytes)->None:
    try:
        oldcut.atomic_replace(old)
        oldcut.reload_definitions()
        oldcut.verified_new_effective_unit(old)
    except BaseException:
        trust.stop("client_cutover_rollback_failed")


def switch()->str:
    previous,target=dropins()
    # The first run verifies the reviewed currently effective candidate.
    # A repeated run must instead accept ONLY our fully verified NEW unit.
    systemd.dormant_and_disabled()
    if trust.read_file(systemd.OVERRIDE,8192)==previous:
        oldcut.verify()
    elif trust.read_file(systemd.OVERRIDE,8192)==target:
        verify()
    else:
        trust.stop("client_cutover_unapproved_initial_dropin")
    verified_new_artifacts()
    fd=oldcut.acquire_lock()
    try:
        systemd.dormant_and_disabled()
        source=trust.read_file(systemd.OVERRIDE,8192)
        if source==target:
            save_backup(previous)
            verified_new_artifacts()
            verify_unit(target)
            return "UNCHANGED"
        if source!=previous:
            trust.stop("client_cutover_unknown_existing_unit")
        oldcut.verified_new_effective_unit(previous)
        verified_new_artifacts()
        save_backup(previous)
        try:
            oldcut.atomic_replace(target)
            oldcut.reload_definitions()
            verified_new_artifacts()
            verify_unit(target)
        except BaseException:
            rollback(previous)
            trust.stop("client_cutover_rolled_back_after_failed_check")
        return "SWITCHED"
    finally:
        fcntl.flock(fd,fcntl.LOCK_UN)
        os.close(fd)


def verify()->None:
    old,target=dropins()
    verified_new_artifacts()
    if trust.read_file(BACKUP,8192)!=old:
        trust.stop("client_cutover_missing_rollback_backup")
    verify_unit(target)


def main()->None:
    args=argparse.ArgumentParser()
    args.add_argument("--mode",choices=("switch","verify"),required=True)
    a=args.parse_args()
    if a.mode=="switch":
        result=switch()
        print(f"FI_AWG_CLIENT_WORKER_CUTOVER=VERIFIED;CHANGE={result};"
              "UNIT_ACTIVE=false;CLIENT_RELEASE=false;ROLLBACK_READY=true")
    else:
        verify()
        print("FI_AWG_CLIENT_WORKER_CUTOVER=VERIFIED;READONLY=true;"
              "UNIT_ACTIVE=false;CLIENT_RELEASE=false;ROLLBACK_READY=true")


if __name__=="__main__":
    try:
        main()
    except (trust.StageBlocked,OSError,ValueError,TypeError,KeyError,
            UnicodeError,RuntimeError):
        raise SystemExit(2)
