#!/usr/bin/env python3
"""Start a completely disposable PostgreSQL Docker instance on existing RU188.

The existing canonical container, database, roles and unit are NEVER changed.
An ephemeral container reuses the exact locally cached PostgreSQL image,
binds a loopback-only port and is removed on workflow cleanup. This test
must run only with a root-owned /run stage under a previously dormant worker.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

import fi_awg_worker_systemd_cutover as cutover

PORT=55434
CONTAINER="fi217-disposable-awg-e2e"
DB="mnebyvpn_test"
ROLE="fi_awg_e2e"
STAGING=re.compile(r"/run/fi-awg-real-e2e\.[A-Za-z0-9]{8}\Z")
ALLOWED=re.compile(r"\d{4}_[A-Za-z0-9_-]+\.sql\Z")


def safe_stage(path:Path) -> None:
    if not path.is_absolute() or not STAGING.fullmatch(str(path)):
        cutover.trust.stop("e2e_unapproved_staging_path")
    cutover.trust.safe_directory(path)
    if not cutover.trust.is_ru188():
        cutover.trust.stop("e2e_unapproved_host")


def docker(*args:str, input_data:bytes|None=None, timeout=35) -> subprocess.CompletedProcess:
    try:
        result=subprocess.run(["/usr/bin/docker",*args],input=input_data,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              check=False,timeout=timeout)
    except (OSError,subprocess.TimeoutExpired):
        cutover.trust.stop("e2e_docker_unavailable")
    return result


def start(path:Path) -> None:
    safe_stage(path)
    cutover.verify()
    if docker("inspect",CONTAINER).returncode==0:
        cutover.trust.stop("e2e_disposable_container_already_exists")
    # Do not pull an image, depend on any registry, or modify the canonical
    # image. The running canonical DB provides an already present image ID.
    source=docker("inspect","--format","{{.Image}}","mnebyvpn-stage-postgres")
    digest=source.stdout.decode("ascii","ignore").strip()
    if source.returncode or not re.fullmatch(r"sha256:[a-f0-9]{64}",digest):
        cutover.trust.stop("e2e_canonical_pg_image_not_locally_pinned")
    password=secrets.token_hex(24)
    env=path/"pg.env"
    env.write_text("POSTGRES_USER="+ROLE+"\nPOSTGRES_PASSWORD="+password+
                   "\nPOSTGRES_DB="+DB+"\n")
    env.chmod(0o600)
    url=path/"url"
    url.write_text(f"postgresql://{ROLE}:{password}@127.0.0.1:{PORT}/{DB}\n")
    url.chmod(0o600)
    result=docker("run","--rm","-d","--name",CONTAINER,"--pull=never",
        "--network=bridge","--publish",f"127.0.0.1:{PORT}:5432",
        "--env-file",str(env),digest,timeout=35)
    if result.returncode:
        cutover.trust.stop("e2e_disposable_postgres_start_failed")
    for i in range(35):
        healthy=docker("exec",CONTAINER,"pg_isready","-q","-U",ROLE,
                       "-d",DB,timeout=5)
        if healthy.returncode==0:
            print("FI_AWG_E2E_POSTGRES=READY;CANONICAL_DB_CHANGED=false;"
                  "NETWORK=LOOPBACK_ONLY;CUSTOMER_RELEASE=false")
            return
        time.sleep(1)
    cutover.trust.stop("e2e_disposable_postgres_not_ready")


def migrate(path:Path) -> None:
    safe_stage(path)
    cutover.verify()
    src=path/"db"/"migrations"
    cutover.trust.safe_directory(src)
    paths=sorted(src.glob("*.sql"))
    if not 35<=len(paths)<=100:
        cutover.trust.stop("e2e_migration_count_unexpected")
    if not any(x.name.startswith("0135_") for x in paths):
        cutover.trust.stop("e2e_missing_awg_row_lock_gateway")
    for file in paths:
        if not ALLOWED.fullmatch(file.name) or file.is_symlink():
            cutover.trust.stop("e2e_unapproved_sql_filename")
        body=cutover.trust.read_file(file,1_000_000)
        result=docker("exec","-i",CONTAINER,"psql","-X","-q","-v",
                      "ON_ERROR_STOP=1","-U",ROLE,"-d",DB,
                      input_data=body,timeout=35)
        if result.returncode:
            cutover.trust.stop("e2e_migration_failed_"+file.name.split("_")[0])
    print("FI_AWG_E2E_SCHEMA=APPLIED;DATABASE=DISPOSABLE;CANONICAL_DB_CHANGED=false")


def stop(path:Path) -> None:
    safe_stage(path)
    # Delete EXACTLY the dedicated ephemeral container. Never inspect, stop
    # or touch the existing mnebyvpn-stage-postgres container.
    if docker("inspect",CONTAINER).returncode==0:
        if docker("rm","-f",CONTAINER,timeout=30).returncode:
            cutover.trust.stop("e2e_disposable_postgres_cleanup_failed")
    print("FI_AWG_E2E_POSTGRES=REMOVED;CANONICAL_DB_CHANGED=false")


def main() -> None:
    p=argparse.ArgumentParser()
    p.add_argument("--mode",choices=("start","migrate","stop"),required=True)
    p.add_argument("--stage",type=Path,required=True)
    args=p.parse_args()
    {"start":start,"migrate":migrate,"stop":stop}[args.mode](args.stage)


if __name__=="__main__":
    try:
        main()
    except (cutover.trust.StageBlocked, OSError, ValueError, KeyError,
            UnicodeError, TypeError, subprocess.SubprocessError):
        raise SystemExit(2)
