#!/usr/bin/env python3
"""Enable the proven FI customer dataplane; preserve existing DE subscriptions."""
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys

import fi_external_customer_e2e as e

RELEASE = Path(__file__).with_name("fi_customer_release_ru.sh")
SAFE_RU_OUTPUT = {
    "FI_RELEASE_BOT_CANARY=PASS", "FI_RELEASE_BOT_LIVE=PASS",
    "FI_RELEASE_GATE_OPEN=true", "FI_RELEASE_RU=COMMITTED",
    "FI_RELEASE_RU_ROLLBACK=READY", "FI_RELEASE_RU_ROLLBACK=UNCONFIRMED",
    "FI_RELEASE_RU_STATE=AMBIGUOUS_OR_COMMITTED",
    "FI_RELEASE_OLD_STOPPED_CONTAINER_RETAINED=true",
}


class RolledBack(e.Blocked):
    """Remote process explicitly completed rollback; safe to close FI marker."""


def promote_ru():
    env = dict(os.environ, SSHPASS=os.environ["RU_PASSWORD"])
    pin = Path("ops/mnebydns-owner-ssh-known_hosts").resolve()
    p = subprocess.run(
        ["sshpass", "-e", "ssh", "-T", *e.COMMON,
         "-o", "UserKnownHostsFile="+str(pin), "root@"+e.RU, "bash -c "+shlex.quote(RELEASE.read_text())],
        stdin=subprocess.DEVNULL, text=True, capture_output=True,
        env=env, timeout=240,
    )
    lines = set(p.stdout.splitlines())
    for line in p.stdout.splitlines():
        if line in SAFE_RU_OUTPUT:
            print(line, flush=True)
    for line in p.stderr.splitlines():
        if __import__("re").fullmatch(r"FI_RELEASE_RU_ERROR=(preflight|prepare|canary|live_bot|commit_gate):[0-9]{1,3}", line):
            print(line, flush=True)
    if p.returncode != 0 and p.returncode != 255 and "FI_RELEASE_RU_ROLLBACK=READY" in lines:
        raise RolledBack("RU_PROMOTION_ROLLED_BACK_"+str(p.returncode))
    e.require(p.returncode == 0 and "FI_RELEASE_RU=COMMITTED" in lines,
              "RU_PROMOTION_UNCONFIRMED_"+str(p.returncode))


def gate_closed():
    return e.sql("SELECT (NOT enabled)::text FROM public.fi_dns_meter_gate WHERE singleton;") == "true"


def activate():
    # Recover only the known, previously retained marker, and only with a
    # closed gate and no live FI credentials (verified by verify_ru_database).
    e.verify_ru_database()
    e.ssh(e.RU, "systemctl is-active --quiet mnebyvpn-fi-dns-meter.service && "
          "systemctl is-active --quiet mnebyvpn-fi-dns-publisher.service")
    e.ssh(e.FI, "systemctl is-active --quiet mnebyvpn-fi-dns-country.service && "
          "systemctl is-active --quiet mnebyvpn-fi-public-dot.socket && "
          "systemctl is-active --quiet mnebyvpn-fi-public-https.socket && "
          "systemctl show -p ExecStart --value mnebyvpn-fi-dns-country.service | grep -q /opt/mnebyvpn-fi-dns-customers-v1/ && "
          "test ! -L "+e.MARKER+" && { test ! -e "+e.MARKER+" || { test -f "+e.MARKER+" && test \"$(cat "+e.MARKER+")\" = fi-dns-customer-v1 && test \"$(stat -c %u:%a "+e.MARKER+")\" = 0:600; }; }")
    unknown = secrets.token_hex(6)+".fi.mnebyvpn.site"
    e.require(e.denied(unknown, "example.com"), "UNKNOWN_PRE_RELEASE")
    created = False
    promotion_started = False
    try:
        marker_state = e.ssh(e.FI, "umask 077; set -eu; test ! -L "+e.MARKER+
              "; if test -e "+e.MARKER+"; then test -f "+e.MARKER+
              " && test \"$(cat "+e.MARKER+")\" = fi-dns-customer-v1"+
              " && test \"$(stat -c %u:%a "+e.MARKER+")\" = 0:600 && echo retained;"+
              " else (set -C; printf 'fi-dns-customer-v1\\n' > "+e.MARKER+"); echo created; fi")
        e.require(marker_state in ("retained", "created"), "FI_MARKER_STATE_UNKNOWN")
        print("FI_RELEASE_MARKER_STATE="+marker_state, flush=True)
        created = True
        print("FI_RELEASE_MARKER=ENABLED", flush=True)
        e.require(e.denied(unknown, "example.com"), "UNKNOWN_MARKER_OPEN")
        promotion_started = True
        promote_ru()
        e.require(e.sql("SELECT enabled::text FROM public.fi_dns_meter_gate WHERE singleton;") == "true",
                  "GATE_COMMIT_NOT_CONFIRMED")
        e.ssh(e.FI, "test -f "+e.MARKER+" && test ! -L "+e.MARKER+
              " && test \"$(cat "+e.MARKER+")\" = fi-dns-customer-v1")
        if not e.denied(unknown, "example.com"):
            # An explicit unauthorized response is a fail-closed condition.
            # Suspend only FI; do not revoke/delete any issued credential.
            e.require(e.sql("UPDATE public.fi_dns_meter_gate SET enabled=false WHERE singleton RETURNING (NOT enabled)::text;") == "true", "FI_EMERGENCY_GATE_CLOSE_UNCONFIRMED")
            raise RolledBack("UNKNOWN_POST_RELEASE_GATE_CLOSED")
        print("FI_CUSTOMER_RELEASE=PASS;PUBLIC_ISSUANCE=true", flush=True)
    except Exception as exc:
        # Do not race a remote shell that may still commit after SSH loss.
        # Never remove the marker for an open or unknown production gate.
        # After activation actual clients may have requested credentials.
        if created and (not promotion_started or isinstance(exc, RolledBack)):
            try:
                if gate_closed():
                    e.ssh(e.FI, "test ! -L "+e.MARKER+
                          " && test \"$(cat "+e.MARKER+")\" = fi-dns-customer-v1 && rm -f "+e.MARKER)
                    print("FI_RELEASE_MARKER=ROLLED_BACK", flush=True)
                else:
                    print("FI_RELEASE_MARKER=RETAINED_GATE_NOT_CLOSED", flush=True)
            except Exception:
                print("FI_RELEASE_MARKER=STATE_UNCONFIRMED", flush=True)
        elif created:
            print("FI_RELEASE_MARKER=RETAINED_REMOTE_OUTCOME_UNCONFIRMED", flush=True)
        raise


if __name__ == "__main__":
    try:
        activate()
    except e.Blocked as exc:
        print("FI_CUSTOMER_RELEASE=BLOCKED:"+str(exc), file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print("FI_CUSTOMER_RELEASE=BLOCKED:"+type(exc).__name__, file=sys.stderr)
        sys.exit(2)
