#!/usr/bin/env python3
"""Read-only bulk MNEBYDNS release preflight: one inventory, one dry-run render.

Not a deployer: never mutates CoreDNS, Nginx, PostgreSQL, timers or routes.
A working HTTPS root is not proof that a full application works.
"""
from __future__ import annotations
import argparse
import base64
import collections
import datetime as dt
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "bulk-108-preflight-results"
def load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / file)
    if spec is None or spec.loader is None:
        raise RuntimeError("Missing checked-in dependency " + file)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m

batch = load("batch_108_for_bulk_plan", "mnebydns-batch-108-canary-20261112.py")
scanner = load("mass_108_for_bulk_plan", "mnebydns-108-mass-readonly-20261112.py")
owner = batch.owner
renderer = owner._render

def evaluate(names, rows, de, ru, core, nginx):
    if len(names) != 108 or len(set(names)) != 108:
        raise RuntimeError("ATTESTED_108_INVENTORY_DRIFT")
    if set(de) != set(names) or set(ru) != set(names):
        raise RuntimeError("INCOMPLETE_REMOTE_MEASUREMENTS")
    current_core, current_nginx = core, nginx
    verdicts = []
    selected = []
    for host in names:
        record = rows.get(host)
        if record is None:
            raise RuntimeError("MISSING_CANONICAL_DB_ROW: " + host)
        status, product, error = record
        entry = dict(domain=host, db_status=status, product=product,
                     de_state=de[host]["state"], de_code=de[host].get("http_status"),
                     ru_state=ru[host]["state"], ru_code=ru[host].get("http_status"),
                     decision="", reason="")
        if product != batch.PRODUCT:
            entry["decision"] = "EXCLUDE_OTHER_OWNER"
        elif status == "ACTIVE":
            entry["decision"] = "PRESERVE_ACTIVE"
        elif status != "PENDING":
            entry["decision"] = "EXCLUDE_NOT_PENDING"
            entry["reason"] = "DB state: " + status
        elif not (de[host].get("certificate_verified") and
                  200 <= (de[host].get("http_status") or 0) < 400 and
                  ru[host].get("certificate_verified") and
                  ru[host].get("http_status") in (403, 451) and
                  de[host].get("origin_ipv4") == ru[host].get("origin_ipv4")):
            entry["decision"] = "EXCLUDE_UNVERIFIED_DIFFERENTIAL"
            entry["reason"] = scanner.verdict(de[host], ru[host])
        else:
            ip = renderer.validated_public_ip(de[host]["origin_ipv4"])
            try:
                new_core = renderer.core_add(current_core, host)
                new_nginx = renderer.nginx_add(current_nginx, host, ip)
                if new_core == current_core or new_nginx == current_nginx:
                    raise RuntimeError("NON_ADDITIVE_RENDER")
                current_core, current_nginx = new_core, new_nginx
                selected.append((host, ip))
                entry["decision"] = "RENDERED_FOR_REVIEW"
            except (ValueError, AssertionError, RuntimeError) as exc:
                entry["decision"] = "EXCLUDE_ROUTE_COLLISION"
                entry["reason"] = type(exc).__name__ + ": " + str(exc)[:140]
        verdicts.append(entry)
    if current_core == core and selected:
        raise RuntimeError("MISSING_CORE_MUTATION")
    if current_nginx == nginx and selected:
        raise RuntimeError("MISSING_NGINX_MUTATION")
    for host, _ in selected:
        if current_core.count(renderer.mark(host)) != 2:
            raise RuntimeError("INVALID_CORE_MARKER_COUNT")
        if current_nginx.count(renderer.mark(host)) != 2:
            raise RuntimeError("INVALID_NGINX_MARKER_COUNT")
    return verdicts, selected, current_core, current_nginx

def self_test():
    names = batch.inventory()
    assert len(names) == 108
    core = ("tls://.:853 {\n"
            "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
            "    cache 30\n}\n")
    nginx = ("stream {\nmap $ssl_preread_server_name $direct_mtproxy_backend {\n"
             " default 127.0.0.1:9443;\n}\nserver { proxy_pass $direct_mtproxy_backend; }\n}\n")
    rows = {h: ("PENDING", batch.PRODUCT, "") for h in names}
    de = {h: dict(host=h, state="TLS_AND_HTTP", certificate_verified=True,
                  http_status=200, origin_ipv4="93.184.215.14") for h in names}
    ru = {h: dict(host=h, state="TLS_AND_HTTP", certificate_verified=True,
                  http_status=403, origin_ipv4="93.184.215.14") for h in names}
    rows["cloud.oracle.com"] = ("PENDING", "Oracle", "")
    rows["copilot.microsoft.com"] = ("ACTIVE", "Microsoft", "")
    ru["codebrowser.dev"]["certificate_verified"] = False
    ru["codebrowser.dev"]["state"] = "TCP_ERROR"
    ru["codebrowser.dev"]["http_status"] = None
    v, selected, c, n = evaluate(names, rows, de, ru, core, nginx)
    assert len(selected) == 105, len(selected)  # 108 - 2 foreign - 1 timeout
    assert all(x["decision"] != "RENDERED_FOR_REVIEW" for x in v if
               x["domain"] in ("cloud.oracle.com", "copilot.microsoft.com", "codebrowser.dev"))
    assert all(c.count(renderer.mark(x)) == 2 for x, _ in selected)
    assert all(n.count(renderer.mark(x)) == 2 for x, _ in selected)
    # Repeating the same render on a changed configuration must not overwrite routes.
    try:
        renderer.core_add(c, selected[0][0])
    except ValueError:
        pass
    else:
        raise AssertionError("Duplicate route did not fail closed")
    print("MNEBYDNS_BULK_PREFLIGHT_OFFLINE=PASS selected=" + str(len(selected)))

def read_exact_remote(role: str, path: str) -> str:
    # The shared SSH wrapper .strip()s stdout; base64 preserves the EXACT source
    # bytes, including the trailing newline required by byte-for-byte rollback.
    encoded = owner.ssh(role, "base64 -w0 " + path, 40)
    return base64.b64decode(encoded, validate=True).decode("utf-8")

def live_plan():
    names = batch.inventory()
    batch.ensure_quiet()
    batch.capacity()
    rows = batch.table()
    batch.preexisting_failure(rows, names)
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("CHECKPOINT_NOT_CLEAN")
    core = read_exact_remote("de", "/opt/mnebydns-dot/Corefile")
    nginx = read_exact_remote("de", "/etc/nginx/nginx.conf")
    targets = [{"host": h} for h in names]
    de = scanner.via_ssh("DE", targets)
    ru = scanner.via_ssh("RU", [{"host": h, "origin_ipv4": de[h].get("origin_ipv4")}
                               for h in names])
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("CONFIG_CHANGED_DURING_MEASUREMENT")
    if batch.table() != rows:
        raise RuntimeError("OWNER_DB_CHANGED_DURING_MEASUREMENT")
    verdicts, selected, generated_core, generated_nginx = evaluate(
        names, rows, de, ru, core, nginx)
    # Fail closed if an external job replaced the exact source files.
    if read_exact_remote("de", "/opt/mnebydns-dot/Corefile") != core or (
        read_exact_remote("de", "/etc/nginx/nginx.conf") != nginx):
        raise RuntimeError("SHARED_SOURCE_CHANGED_DURING_DRY_RENDER")
    OUTPUT.mkdir(parents=True, exist_ok=True)
    counts = dict(collections.Counter(x["decision"] for x in verdicts))
    summary = dict(checked_at_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                   candidates=len(names), decisions=counts,
                   eligible=len(selected), additive_render=True,
                   checkpoint_unchanged=True, owner_queue_quiet=True,
                   source_sha256=dict(core=hashlib.sha256(core.encode()).hexdigest(),
                                      nginx=hashlib.sha256(nginx.encode()).hexdigest()),
                   target_sha256=dict(core=hashlib.sha256(generated_core.encode()).hexdigest(),
                                      nginx=hashlib.sha256(generated_nginx.encode()).hexdigest()),
                   no_live_mutations=True)
    (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    (OUTPUT / "decisions.json").write_text(json.dumps(verdicts, indent=2, ensure_ascii=False) + "\n")
    # Only public selected origin IPs and hostnames; not raw production configs.
    (OUTPUT / "eligible-manifest.tsv").write_text("".join(h + "\t" + ip + "\n"
                                                       for h, ip in selected))
    report = ["# MNEBYDNS one-pass 108-host production dry run", "",
              "No live CoreDNS/Nginx/PostgreSQL changes.", "",
              "Candidates: **108**; rendered candidates: **" + str(len(selected)) + "**.",
              "Category totals: " + json.dumps(counts, ensure_ascii=False, sort_keys=True),
              "The actual same-origin RU 403/451 vs DE HTTP 2xx/3xx is a server-level test,",
              "not an Android/iOS application test and not proof of an app unlock.", "",
              "| Domain | Decision | DE | RU | Reason |",
              "|---|---|---|---|---|"]
    for x in verdicts:
        report.append("| " + x["domain"] + " | " + x["decision"] + " | " +
                      str(x["de_code"] or x["de_state"]) + " | " +
                      str(x["ru_code"] or x["ru_state"]) + " | " +
                      x["reason"].replace("|", "/") + " |")
    (OUTPUT / "report.md").write_text("\n".join(report) + "\n")
    print("MNEBYDNS_BULK_LIVE_DRYRUN=" + json.dumps(summary, sort_keys=True), flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("self-test", "plan"))
    args = parser.parse_args()
    self_test() if args.mode == "self-test" else live_plan()
