"""Install the FI customer-capable runtime while both release gates are closed."""

import asyncio
import os
from pathlib import Path
import re
import subprocess
import sys

from fi_country_stage import active, ctl, deny_unknown, enabled, listeners, meter_closed, wait_local
from fi_dns_customer_policy import RELEASE
from fi_dns_guarded_ingress import CONTROLLER, SNAPSHOT
from fi_dns_origin_canary import HOSTS
from fi_dns_signed_grants import load
from fi_dns_ssh_stage import CONTROLLER_PIN, FI, host, immutable, private_dir, read, require

DNS = "mnebyvpn-fi-dns-country.service"
PUBLIC = "mnebyvpn-fi-public-dot.socket"
GUARD = "mnebyvpn-fi-sni-egress-guard.service"
ROUTED_HTTPS = "mnebyvpn-fi-sni-routed-v3.service"
BASE = Path("/opt/mnebyvpn-fi-dns-country-v2")
CANDIDATE = Path("/opt/mnebyvpn-fi-dns-customers-v1")
DROP_DIR = Path("/etc/systemd/system") / (DNS + ".d")
DROP = DROP_DIR / "20-customer-runtime.conf"
DROP_CONTENT = (
    "[Service]\n"
    f"WorkingDirectory={CANDIDATE}\n"
    "ExecStart=\n"
    f"ExecStart=/usr/bin/python3 {CANDIDATE}/fi_routed_runtime.py\n"
).encode()
ATTEMPT = "override-started"


def gates_closed():
    require(not RELEASE.exists() and not RELEASE.is_symlink(), "customer_marker_present")
    require(load(SNAPSHOT, CONTROLLER, CONTROLLER_PIN)["grants"] == [], "unexpected_grants")
    asyncio.run(meter_closed())


def command_is(directory):
    actual = ctl("show", DNS, "-p", "ExecStart", "--value")
    require(str(directory / "fi_routed_runtime.py").encode() in actual, "unexpected_service_entrypoint")


def verify_service(directory):
    command_is(directory)
    wait_local(DNS)
    require(active(GUARD) and active(ROUTED_HTTPS), "https_guard_unavailable")
    require(active(PUBLIC) and enabled(PUBLIC), "public_dns_socket_inactive")
    require(listeners(853) == [FI + ":853"] and not listeners(853, udp=True), "public_dns_socket_drift")
    deny_unknown(HOSTS[0])
    gates_closed()


def restart():
    ctl("daemon-reload")
    ctl("restart", DNS)
    wait_local(DNS)
    ctl("start", PUBLIC)


def rollback(stage):
    if not (stage / ATTEMPT).exists():
        return
    require(read(stage / ATTEMPT, 1) == b"1", "untrusted_rollback_marker")
    if DROP.exists() or DROP.is_symlink():
        require(read(DROP, len(DROP_CONTENT)) == DROP_CONTENT, "untrusted_customer_override")
        DROP.unlink()
    try:
        DROP_DIR.rmdir()
    except FileNotFoundError:
        pass
    restart()
    verify_service(BASE)
    (stage / ATTEMPT).unlink()
    print("FI_DNS_CUSTOMER_STAGE_ROLLBACK_VERIFIED=true", flush=True)


def stage_candidate(stage):
    require(enabled(DNS) and not DROP_DIR.exists() and not DROP_DIR.is_symlink(), "unexpected_dns_unit")
    verify_service(BASE)
    candidate = stage / "runtime"
    base_names = {path.name for path in BASE.glob("*.py")}
    names = {path.name for path in candidate.glob("*.py")}
    require(len(base_names) == 15 and names == base_names | {"fi_dns_customer_policy.py"}, "unexpected_runtime_bundle")
    private_dir(CANDIDATE, create=True)
    for name in sorted(names):
        immutable(CANDIDATE / name, read(candidate / name, 200000))
    require({path.name for path in CANDIDATE.glob("*.py")} == names, "unexpected_customer_runtime_files")

    immutable(stage / ATTEMPT, b"1")
    try:
        DROP_DIR.mkdir(mode=0o755)
        immutable(DROP, DROP_CONTENT)
        subprocess.run(["systemd-analyze", "verify", DNS], check=True, capture_output=True, timeout=15)
        restart()
        verify_service(CANDIDATE)
    except BaseException:
        rollback(stage)
        raise
    print("FI_DNS_CUSTOMER_RUNTIME_STAGED=true;CUSTOMER_GRANTS=false", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    try:
        host(FI)
        require(len(sys.argv) == 3 and re.fullmatch(r"/run/fi-dns-customer-[0-9]+-[0-9]+", sys.argv[2]), "invalid_stage")
        work = Path(sys.argv[2])
        private_dir(work)
        action = {"stage": stage_candidate, "rollback": rollback}.get(sys.argv[1])
        require(action is not None, "invalid_action")
        action(work)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        reason = str(error)
        print("FI_DNS_CUSTOMER_RUNTIME_BLOCKED=" + (reason if re.fullmatch(r"[a-z0-9_]+", reason) else type(error).__name__),
              file=sys.stderr, flush=True)
        raise SystemExit(2)
