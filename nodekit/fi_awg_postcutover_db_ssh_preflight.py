#!/usr/bin/env python3
"""FI217 post-cutover preflight: REAL RU188 readonly DB + forced SSH transport.

This is NOT a real grant/ACK. The production release stays OFF and the
verified FI pool remains STAGED until separately established external E2E.
Only a disposable database may enable its grant gate for integration testing.
No production DB writes, no AWG peer changes and no worker activation here.
"""
from __future__ import annotations

import re
import subprocess
import sys

import fi_awg_worker_systemd_cutover as cutover
import fi_awg_worker_live_db_readonly as legacy
import fi_awg_worker_candidate_stage as candidate
import fi_awg_client_worker_stage as client
import fi_awg_client_worker_cutover as clientcut
import fi_awg_worker_isolated_runtime_preflight as node
import fi_awg_ssh_stage as ssh

OLD_RELEASE = "/opt/mnebyvpn-controller/awg-worker-releases/" + candidate.OLD_COMMIT
NEW_RELEASE = str(client.RELEASE)
OLD_DECLARATION = "const release='" + OLD_RELEASE + "';"
NEW_DECLARATION = "const release='" + NEW_RELEASE + "';"
DB_MARKERS = (
    "FI_AWG_DB_CONNECTION=PASS",
    "FI_AWG_DB_DEDICATED_ROLE=PASS",
    "FI_AWG_DB_RELEASE_DISABLED=PASS",
    "FI_AWG_DB_FI_ENROLLED=PASS",
    "FI_AWG_DB_OUTBOX_READ=PASS",
    "FI_AWG_DB_LOCK_GATEWAYS=PASS",
)
PROOF = {
    "FI_AWG_DB_NODE_PROOF=FRESH",
    "FI_AWG_DB_NODE_PROOF=STALE",
    "FI_AWG_DB_NODE_PROOF=MISSING",
}


def audited_candidate_query() -> str:
    """Re-target the reviewed READ ONLY query to the effective 6-module release.

    Reuse the already installed exact SQL/role/gate assertions from the legacy
    checker; only its immutable Node module-resolution path may change.
    """
    script = legacy.CODE
    if (NEW_RELEASE == str(candidate.CANDIDATE) or
            script.count(OLD_DECLARATION) != 1 or
            NEW_RELEASE == OLD_RELEASE or
            script.count("await client.query('BEGIN READ ONLY')") != 1 or
            script.count("await client.query('ROLLBACK')") != 2 or
            script.count("await pool.end()") != 1 or
            script.count("FI_AWG_DB_RELEASE_DISABLED=PASS") != 1):
        cutover.trust.stop("postcutover_unapproved_db_probe_template")
    return script.replace(OLD_DECLARATION, NEW_DECLARATION)


def validate_report(stdout: str) -> str:
    if not isinstance(stdout, str) or len(stdout) > 1024:
        cutover.trust.stop("postcutover_db_report_oversized")
    rows = stdout.splitlines()
    if (len(rows) != 8 or rows[:6] != list(DB_MARKERS) or
            rows[6] not in PROOF or
            rows[7] != (
                "FI_AWG_DB_PROBE=READONLY_READY;PRODUCTION_NODE_PROOF_FRESH=" +
                ("true" if rows[6] == "FI_AWG_DB_NODE_PROOF=FRESH" else "false") +
                ";WORKER_STARTED=false;CUSTOMER_RELEASE=false")):
        cutover.trust.stop("postcutover_db_report_invalid")
    return rows[6].split("=")[1]


def verify_live_db() -> str:
    clientcut.verify()
    script = audited_candidate_query()
    try:
        result = subprocess.run(
            [str(node.trusted_node_binary()), "--input-type=module", "-e", script],
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
            timeout=23, check=False)
    except (OSError, subprocess.TimeoutExpired):
        cutover.trust.stop("postcutover_db_runner_unavailable")
    if result.returncode:
        phase = re.findall(
            r"^FI_AWG_DB_CHECKPOINT=(HOST|ENV|MODULE|CONNECT|TRANSACTION|ROLE|"
            r"RELEASE|ENROLLED|OUTBOX|GATEWAYS|POOL|ROLLBACK)$",
            result.stderr, re.MULTILINE)
        if phase:
            print("FI_AWG_POSTCUTOVER_DB_BLOCKED_AT=" + phase[-1])
        cutover.trust.stop("postcutover_db_readonly_check_failed")
    proof = validate_report(result.stdout)
    # No passwords, URLs, peer keys, entitlements, SQL or any stderr escape.
    print("FI_AWG_POSTCUTOVER_DB=PASS;ROLE=RESTRICTED;RELEASE=false;"
          "POOL_PROOF=" + proof + ";WRITES=false")
    return proof


def main() -> int:
    proof = verify_live_db()
    # SSH check executes a fixed preflight frame + invalid JSON using the
    # dedicated, root-only controller key and pinned FI host. A hostile frame
    # MUST be rejected by FI's forced-command SSH handler.
    ssh.probe()
    clientcut.verify()
    print("FI_AWG_RU_PG_FI_TRANSPORT=VERIFIED;DATABASE=READONLY;"
          "SSH=FORCED_COMMAND;WORKER_ACTIVE=false;CUSTOMER_RELEASE=false;"
          "PRODUCTION_E2E=false;NODE_ACK_IN_DB=false;POOL_PROOF=" + proof)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (cutover.trust.StageBlocked, ssh.StageBlocked, OSError, ValueError,
            TypeError, KeyError, UnicodeError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit(2)
