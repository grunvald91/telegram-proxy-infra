#!/usr/bin/env python3
"""Enable the proven FI customer dataplane; preserve existing DE subscriptions."""
import os
from pathlib import Path
import secrets
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


def promote_ru():
    env = dict(os.environ, SSHPASS=os.environ["RU_PASSWORD"])
    pin = Path("ops/mnebydns-owner-ssh-known_hosts").resolve()
    p = subprocess.run(
        ["sshpass", "-e", "ssh", "-T", *e.COMMON,
         "-o", "UserKnownHostsFile="+str(pin), "root@"+e.RU, "bash -s"],
        input=RELEASE.read_text(), text=True, capture_output=True,
        env=env, timeout=240,
    )
    lines = set(p.stdout.splitlines())
    for line in p.stdout.splitlines():
        if line in SAFE_RU_OUTPUT:
            print(line, flush=True)
    e.require(p.returncode == 0 and "FI_RELEASE_RU=COMMITTED" in lines,
              "RU_PROMOTION_EXIT_"+str(p.returncode))


def gate_closed():
    return e.sql("SELECT (NOT enabled)::text FROM public.fi_dns_meter_gate WHERE singleton;") == "true"


def activate():
    e.verify_ru_database()
    e.ssh(e.RU, "systemctl is-active --quiet mnebyvpn-fi-dns-meter.service && "
          "systemctl is-active --quiet mnebyvpn-fi-dns-publisher.service")
    e.ssh(e.FI, "systemctl is-active --quiet mnebyvpn-fi-dns-country.service && "
          "systemctl is-active --quiet mnebyvpn-fi-public-dot.socket && "
          "systemctl is-active --quiet mnebyvpn-fi-public-https.socket && "
          "systemctl show -p ExecStart --value mnebyvpn-fi-dns-country.service | grep -q /opt/mnebyvpn-fi-dns-customers-v1/ && "
          "test ! -e "+e.MARKER+" && test ! -L "+e.MARKER)
    unknown = secrets.token_hex(6)+".fi.mnebyvpn.site"
    e.require(e.denied(unknown, "example.com"), "UNKNOWN_PRE_RELEASE")
    created = False
    try:
        e.ssh(e.FI, "umask 077; set -eu; test ! -e "+e.MARKER+
              "; test ! -L "+e.MARKER+
              "; (set -C; printf 'fi-dns-customer-v1\\n' > "+e.MARKER+")")
        created = True
        print("FI_RELEASE_MARKER=ENABLED", flush=True)
        promote_ru()
        e.require(e.sql("SELECT enabled::text FROM public.fi_dns_meter_gate WHERE singleton;") == "true",
                  "GATE_COMMIT_NOT_CONFIRMED")
        e.ssh(e.FI, "test -f "+e.MARKER+" && test ! -L "+e.MARKER+
              " && test \"$(cat "+e.MARKER+")\" = fi-dns-customer-v1")
        e.require(e.denied(unknown, "example.com"), "UNKNOWN_POST_RELEASE")
        print("FI_CUSTOMER_RELEASE=PASS;PUBLIC_ISSUANCE=true", flush=True)
    except Exception:
        # Never remove the marker for an open or unknown production gate.
        # After activation actual clients may have requested credentials.
        if created:
            try:
                if gate_closed():
                    e.ssh(e.FI, "test ! -L "+e.MARKER+
                          " && test \"$(cat "+e.MARKER+")\" = fi-dns-customer-v1 && rm -f "+e.MARKER)
                    print("FI_RELEASE_MARKER=ROLLED_BACK", flush=True)
                else:
                    print("FI_RELEASE_MARKER=RETAINED_GATE_NOT_CLOSED", flush=True)
            except Exception:
                print("FI_RELEASE_MARKER=STATE_UNCONFIRMED", flush=True)
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
