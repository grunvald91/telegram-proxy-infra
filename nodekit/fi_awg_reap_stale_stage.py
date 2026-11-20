#!/usr/bin/env python3
"""One-shot, fail-closed RU188 recovery for TWO proven stale FI217 source stages.

This deliberately does NOT kill ssh, docker, AmneziaWG, site, controller,
systemd or unrelated Python processes. It only sends SIGTERM to two exact,
root-owned, old, immutable-release *staging* Python command lines and then
verifies the lock is free. Subsequent reviewed staging uses normal GitHub
Actions single-writer concurrency. No worker/client activation here.
"""
from __future__ import annotations

import argparse
import fcntl
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

ROOT = Path("/root/mnebyvpn-controller")
LOCK = ROOT / "awg-worker-source-stage.lock"
APPROVAL = ROOT / "approvals/awg-delivery.enable"
OLD_RELEASE = "/opt/mnebyvpn-controller/awg-worker-releases/6743387075102698ab23ec06de364d0d8efd1dca"
NEW_RELEASE = "/opt/mnebyvpn-controller/awg-worker-releases/446c331249085adb6536e3d9913fb4b68abf6cd7"
UNIT = "mnebyvpn-awg-delivery.service"
SCRIPT = re.compile(
    r"(/run/fi-awg-client-worker\.[A-Za-z0-9]{8})/"
    r"fi_awg_client_worker_stage\.py\Z"
)
REQUIRED_STAGE_COUNT = 2
MIN_AGE_SECONDS = 300


class RecoveryBlocked(Exception):
    pass


def reject(condition: bool, reason: str) -> None:
    if not condition:
        raise RecoveryBlocked(reason)


def command(*argv: str, timeout: float = 12) -> str:
    try:
        result = subprocess.run(
            list(argv), capture_output=True, check=False,
            text=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RecoveryBlocked("required_readonly_command_failed") from exc
    reject(result.returncode == 0, "required_readonly_command_nonzero")
    return result.stdout.strip()


def on_ru188() -> None:
    ip = command("ip", "-o", "-4", "addr", "show")
    reject(re.search(r"(?<!\d)188\.120\.254\.223/\d+", ip) is not None,
           "not_ru188")


def gate_checks() -> None:
    reject(os.geteuid() == 0, "not_root")
    on_ru188()
    reject(not APPROVAL.exists() and not APPROVAL.is_symlink(),
           "awg_worker_approval_present")
    systemd = subprocess.run(
        ["systemctl", "is-active", "--quiet", UNIT],
        check=False, timeout=10,
    )
    reject(systemd.returncode != 0, "awg_worker_active")
    # systemctl is-enabled exits zero for static units too.
    # Existing canonical FI AWG guard explicitly permits static or
    # disabled unit states, not enabled. Match that contract exactly.
    file_state = command("systemctl", "show", "-P", "UnitFileState", UNIT)
    reject(file_state in ("disabled", "static"), "awg_worker_not_dormant_static_or_disabled")
    active_state = command("systemctl", "show", "-P", "ActiveState", UNIT)
    reject(active_state == "inactive", "awg_worker_active_state_not_inactive")
    effective = command("systemctl", "show", "-P", "WorkingDirectory", UNIT)
    reject(effective == OLD_RELEASE, "awg_worker_unit_not_pinned_old_inactive")
    reject(not (Path(NEW_RELEASE) / "awg-client-worker-manifest.json").exists(),
           "new_release_already_published")
    state = command(
        "docker", "exec", "mnebyvpn-stage-postgres",
        "psql", "-AtX", "-v", "ON_ERROR_STOP=1",
        "-U", "mnebyvpn_stage", "-d", "mnebyvpn_stage",
        "-c", "SELECT enabled::text FROM public.vpn_release_flags "
              "WHERE feature='vpn_awg_clients';",
    )
    reject(state == "false", "awg_customer_release_not_disabled")


def exact_stage_argv(argv: tuple[str, ...]) -> bool:
    if len(argv) != 4 or argv[0] not in (
        "python3", "/usr/bin/python3", "/usr/local/bin/python3"
    ) or argv[2] != "--stage":
        return False
    found = SCRIPT.fullmatch(argv[1])
    return bool(found and argv[3] == found.group(1))


def process_info(pid: int) -> tuple[tuple[str, ...], int] | None:
    proc = Path("/proc") / str(pid)
    try:
        if proc.stat().st_uid != 0:
            return None
        argv = tuple(
            part.decode("utf-8") for part in
            (proc / "cmdline").read_bytes().split(b"\0") if part
        )
        if not exact_stage_argv(argv):
            return None
        # starttime is /proc/PID/stat field 22; index 19 after field 2.
        after_comm = (proc / "stat").read_text().rsplit(") ", 1)[1].split()
        start_ticks = int(after_comm[19])
    except (FileNotFoundError, ProcessLookupError, UnicodeError, ValueError,
            PermissionError, IndexError):
        return None
    return argv, start_ticks


def exact_stale_processes() -> dict[int, tuple[tuple[str, ...], int]]:
    uptime = float(Path("/proc/uptime").read_text().split()[0])
    clock = os.sysconf("SC_CLK_TCK")
    found = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        details = process_info(pid)
        if details is None:
            continue
        age = uptime - details[1] / clock
        reject(age >= MIN_AGE_SECONDS,
               "new_fi_stage_must_not_be_terminated")
        found[pid] = details
    return found


def checked_lock() -> int:
    try:
        fd = os.open(LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise RecoveryBlocked("source_lock_missing_or_untrusted") from exc
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise RecoveryBlocked("source_lock_permissions_invalid")
    return fd


def locked_by_old_stage(fd: int) -> bool:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return True
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False


def wait_gone(snapshot: dict[int, tuple[tuple[str, ...], int]], seconds: int) -> bool:
    for _ in range(seconds * 5):
        if all(process_info(pid) != details for pid, details in snapshot.items()):
            return True
        time.sleep(0.2)
    return False


def repair() -> None:
    gate_checks()
    snapshot = exact_stale_processes()
    fd = checked_lock()
    try:
        held = locked_by_old_stage(fd)
        if not snapshot and not held:
            print("FI_AWG_STALE_STAGE=ALREADY_CLEAR;WORKER_ACTIVE=false;"
                  "CLIENT_RELEASE=false;PROCESSES_SIGNALED=0")
            return
        reject(held, "source_lock_not_held")
        reject(len(snapshot) == REQUIRED_STAGE_COUNT,
               "unexpected_number_of_stale_stage_processes")
        # Recheck *all* immutable safety gates after capturing PIDs. A new
        # legitimate stage must not sneak in during the repair.
        gate_checks()
        confirm = exact_stale_processes()
        reject(confirm == snapshot, "stage_process_changed_before_repair")
        for pid, details in snapshot.items():
            reject(process_info(pid) == details, "stage_pid_reused")
            os.kill(pid, signal.SIGTERM)
        reject(wait_gone(snapshot, 10), "stale_stage_not_stopped_by_sigterm")
        reject(not exact_stale_processes(), "new_stage_detected_after_termination")
        reject(not locked_by_old_stage(fd), "source_lock_not_freed")
        gate_checks()
        print("FI_AWG_STALE_STAGE=REPAIRED;PROCESSES_SIGNALED=2;"
              "LOCK=FREE;WORKER_ACTIVE=false;CLIENT_RELEASE=false;"
              "CUSTOMER_PEERS_TOUCHED=false")
    finally:
        os.close(fd)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("repair",), required=True)
    args = parser.parse_args()
    if args.mode == "repair":
        repair()


if __name__ == "__main__":
    try:
        main()
    except (RecoveryBlocked, OSError, ValueError, RuntimeError) as exc:
        print("FI_AWG_STALE_STAGE=BLOCKED;REASON=" +
              (str(exc) if isinstance(exc, RecoveryBlocked) else "unexpected_error"))
        raise SystemExit(2)
