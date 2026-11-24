#!/usr/bin/env python3
"""Create one additive Smart DNS release from the existing research queue."""

import base64
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "research_bulk", ROOT / "scripts/mnebydns-108-bulk-deploy-20261112.py"
)
assert spec and spec.loader
bulk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bulk)
prepare, batch, owner = bulk.prepare, bulk.batch, bulk.owner
INTAKE = ROOT / "scripts/mnebydns-geoblock-research-queue-20261110.sql"
MAX_QUEUE = 600

PIN_ORIGINS = """
import concurrent.futures
import json
import types

render = types.ModuleType("owner_domain_render")
exec(compile(renderer_source, "<repo-renderer>", "exec"), render.__dict__)

def probe(host):
    try:
        return host, render.origin_ip(host)
    except (OSError, ValueError, RuntimeError):
        return host, None

with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
    for result in pool.map(probe, hostnames):
        print(json.dumps(result), flush=True)
"""


def source_names():
    names = re.findall(r"(?m)^  \('([a-z0-9.-]+)'\),?;?$", INTAKE.read_text())
    if not names or len(names) != len(set(names)) or len(names) > MAX_QUEUE:
        raise RuntimeError("Unexpected source inventory")
    return frozenset(owner._render.validate_domain(name) for name in names)


def select_pending(names, rows):
    return sorted(name for name in names
                  if rows.get(name, ("", "", ""))[:2] == ("PENDING", batch.PRODUCT))


def pinned_origins(names):
    renderer = Path(owner._render.__file__).read_text()
    program = ("renderer_source = " + repr(renderer) + "\n"
               + "hostnames = " + repr(names) + "\n" + PIN_ORIGINS)
    token = base64.b64encode(program.encode()).decode()
    command = "printf %s " + shlex.quote(token) + " | base64 -d | python3 -"
    records = [json.loads(line) for line in owner.ssh("de", command, 600).splitlines()]
    if [row[0] for row in records] != names:
        raise RuntimeError("Incomplete origin inventory")
    return records


def live_config(path):
    command = "od -An -v -tx1 " + shlex.quote(path)
    return bytes.fromhex(owner.ssh("de", command)).decode()


def make_plan(names, rows):
    pending = select_pending(names, rows)
    print("RESEARCH_QUEUE_PENDING=" + str(len(pending)), flush=True)
    if not pending:
        return None
    candidates, exclusions = [], []
    for name, ip in pinned_origins(pending):
        if ip is None:
            exclusions.append({"domain": name, "reason": "ORIGIN_TLS_UNVERIFIED"})
        else:
            candidates.append({"domain": name, "ip": owner._render.validated_public_ip(ip)})
    dns = live_config("/opt/mnebydns-dot/Corefile")
    nginx = live_config("/etc/nginx/nginx.conf")
    selected, rejected, next_dns, next_nginx = prepare.render(candidates, dns, nginx)
    exclusions.extend(rejected)
    for item in exclusions:
        print("RESEARCH_QUEUE_DEFERRED " + item["domain"] + "|" + item["reason"], flush=True)
    print("RESEARCH_QUEUE_PREPARED " + json.dumps({
        "selected": len(selected), "deferred": dict(Counter(item["reason"] for item in exclusions))
    }, sort_keys=True), flush=True)
    if not selected:
        return None
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("The live route checkpoint changed during preparation")
    bulk.OUTPUT.mkdir(mode=0o700)
    plan = {"deploy_count": len(selected), "selected": selected, "excluded": exclusions}
    for key, value in (("dns.before", dns), ("nginx.before", nginx),
                       ("dns.pilot", next_dns), ("nginx.pilot", next_nginx)):
        (bulk.OUTPUT / key).write_text(value)
        plan[key.replace(".", "_") + "_sha256"] = prepare.sha(value)
    (bulk.OUTPUT / "plan.json").write_text(json.dumps(plan, sort_keys=True) + "\n")
    return plan


def sync_personal(selected):
    if not bulk.states_are(selected, "ACTIVE"):
        raise RuntimeError("Bulk route activation could not be verified before personal sync")
    target = "/opt/mnebydns-personal-research-" + bulk.RUNID
    helper = "mnebydns-sync-personal-nvidia.py"
    domains = [item["domain"] for item in selected]
    owner.ssh("ru", "install -d -m 700 " + target)
    owner.cmd(["sshpass", "-e", "scp", "-q", "-o", "ConnectTimeout=12",
               *owner.SSH_TRUST, "-o", "LogLevel=ERROR", str(ROOT / "scripts" / helper),
               "root@" + owner.RU + ":" + target + "/"], os.environ["RU_PASS"])
    command = "python3 " + target + "/" + helper + " " + bulk.RUNID + " --research-queue "
    print(owner.ssh("ru", command + " ".join(map(shlex.quote, domains)), 340), flush=True)


def main():
    names = source_names()
    if sys.argv[1:] == ["self-test"]:
        a, b = sorted(names)[:2]
        assert select_pending(names, {
            a: ("PENDING", batch.PRODUCT, ""), b: ("ACTIVE", batch.PRODUCT, "")
        }) == [a]
        assert select_pending(names, {a: ("PENDING", "Oracle", "")}) == []
        print(f"RESEARCH_QUEUE_SOURCE_SELF_TEST=PASS names={len(names)}")
        return
    if sys.argv[1:]:
        raise SystemExit("Usage: mnebydns-research-queue-bulk.py [self-test]")
    batch.ensure_quiet()
    bulk.capacity(research_queue=True)
    plan = make_plan(names, batch.table())
    if plan is None:
        print("RESEARCH_QUEUE_NO_APPLICABLE_CHANGES=true")
        return
    bulk.deploy(research_inventory=names)
    sync_personal(plan["selected"])


if __name__ == "__main__":
    main()
