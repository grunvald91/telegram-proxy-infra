#!/usr/bin/env python3
"""One-shot, owner-authorized Antigravity live activation via existing guarded controller.

Does not bypass CoreDNS/Nginx stage, TLS validation, independent rollback timer,
stable-service regression checks, checkpoint promotion or active health.
Never touches unrelated database records and never overwrites existing routes.
"""
from __future__ import annotations

import importlib.util
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROLLER = HERE / "mnebydns-owner-domain-controller-20261110.py"
DOMAINS = (
    "antigravity.google",
    "daily-cloudcode-pa.googleapis.com",
    "aicode.googleapis.com",
    "accounts.google.com",
    "oauth2.googleapis.com",
    "generativelanguage.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "antigravity-pa.googleapis.com",
    "antigravity.googleapis.com",
    "businessaicode.googleapis.com",
    "aiplatform.googleapis.com",
    "discoveryengine.googleapis.com",
)
spec = importlib.util.spec_from_file_location("owner_domain_controller", CONTROLLER)
if spec is None or spec.loader is None:
    raise RuntimeError("Guarded owner-domain controller is unavailable")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)


def run_id(base: str, index: int) -> str:
    """Distinct 13-digit, GitHub-run-derived ID for each independent rollback timer."""
    if not re.fullmatch(r"[1-9][0-9]{8,10}", base):
        raise ValueError("Unexpected GitHub run ID")
    if not 1 <= index <= 12:
        raise ValueError("Invalid hostname index")
    result = str(int(base) * 100 + index)
    if not re.fullmatch(r"[1-9][0-9]{8,12}", result):
        raise ValueError("Invalid owner rollback timer ID")
    return result


def record(domain: str) -> dict[str, str]:
    owner._render.validate_domain(domain)
    result = owner.sql(
        "SELECT id||'|'||status||'|'||revision||'|'||"
        "coalesce(canary_run_id::text,'')||'|'||"
        "coalesce(extract(epoch from canary_expires_at)::bigint::text,'')"
        " FROM dns_admin_domains WHERE domain='" + domain + "'"
    ).strip()
    parts = result.split("|")
    if len(parts) != 5 or not re.fullmatch(r"[1-9][0-9]{0,14}", parts[0]) or not re.fullmatch(r"[1-9][0-9]{0,14}", parts[2]):
        raise RuntimeError("Missing or corrupted canonical domain row: " + domain)
    return dict(zip(("id", "status", "revision", "run", "expires"), parts))


def request_apply(domain: str, prior: dict[str, str]) -> dict[str, str]:
    result = owner.sql(
        "UPDATE dns_admin_domains SET status='APPLY_REQUESTED',"
        "revision=revision+1, updated_at=now(),last_error_code=NULL"
        " WHERE id=" + prior["id"] + " AND revision=" + prior["revision"] +
        " AND domain='" + domain + "' AND status IN ('PENDING','FAILED')"
        " RETURNING id"
    ).strip()
    if result != prior["id"]:
        raise RuntimeError("Domain row changed during activation: " + domain)
    return record(domain)


def request_confirm(domain: str, prior: dict[str, str]) -> dict[str, str]:
    result = owner.sql(
        "UPDATE dns_admin_domains SET status='CONFIRM_REQUESTED',"
        "revision=revision+1,updated_at=now()"
        " WHERE id=" + prior["id"] + " AND revision=" + prior["revision"] +
        " AND domain='" + domain + "' AND status='CANARY'"
        " AND canary_expires_at>now()+interval '10 minutes'"
        " RETURNING id"
    ).strip()
    if result != prior["id"]:
        raise RuntimeError("Canary was not available for owner-authorized confirmation")
    return record(domain)


def make_item(domain: str, state: dict[str, str]) -> dict[str, str]:
    return {**state, "domain": domain, "updated": str(int(time.time()))}


def live_activate() -> None:
    parent_run = os.environ.get("GITHUB_RUN_ID", "")
    if not parent_run:
        raise RuntimeError("This operation must run in a guarded GitHub Actions release")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Existing live DNS/Nginx differs from verified checkpoint: no changes permitted")
    busy = owner.sql(
        "SELECT count(*) FROM dns_admin_domains WHERE status IN "
        "('PROBING','CANARY','CONFIRM_REQUESTED','CONFIRMING',"
        "'ROLLBACK_REQUESTED','REMOVING')"
    ).strip()
    if busy != "0":
        raise RuntimeError("Another active DNS canary or removal is running: no changes permitted")

    result: dict[str, str] = {}
    for index, domain in enumerate(DOMAINS, 1):
        state = record(domain)
        if state["status"] == "ACTIVE":
            try:
                owner.oracle_canary_check(domain, True)
                owner.tls_public_route(domain)
                result[domain] = "ALREADY_ACTIVE_HEALTH_VERIFIED"
            except Exception:
                result[domain] = "ALREADY_ACTIVE_HEALTH_FAILED"
            print("antigravity_domain=" + domain + " result=" + result[domain], flush=True)
            continue
        if state["status"] not in ("PENDING", "FAILED"):
            result[domain] = "NOT_CHANGED_" + state["status"]
            print("antigravity_domain=" + domain + " result=" + result[domain], flush=True)
            continue
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("Production checkpoint drift: stop instead of risking existing routes")
        instance = run_id(parent_run, index)
        owner.RUNID = instance
        owner.WORK = "/tmp/mnebydns-owner-domain-" + instance
        print("antigravity_activation_begin=" + domain, flush=True)
        updated = request_apply(domain, state)
        if updated["status"] != "APPLY_REQUESTED":
            raise RuntimeError("Owner activation request not persisted")
        try:
            owner.apply(make_item(domain, updated))
        except Exception as exc:
            after = record(domain)
            # Only continue when the controller conclusively FAILED closed,
            # rollback is verified and production is byte-identical to checkpoint.
            if after["status"] != "FAILED" or not owner.live_checkpoint_unchanged():
                raise
            result[domain] = "FAILED_PREFLIGHT_" + type(exc).__name__
            print("antigravity_domain=" + domain + " result=" + result[domain], flush=True)
            continue
        after = record(domain)
        if after["status"] != "CANARY" or after["run"] != instance:
            raise RuntimeError("Canary did not reach a verifiable active state for " + domain)

        # This explicit user-authorized workflow substitutes confirmation in Telegram;
        # all live route checks and checkpoint promotion still use the existing controller.
        confirm_state = request_confirm(domain, after)
        owner.confirm(make_item(domain, confirm_state))
        verified = record(domain)
        if verified["status"] != "ACTIVE" or verified["run"] != instance:
            raise RuntimeError("Production route confirmation did not persist for " + domain)
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("Final live configuration differs from stable checkpoint")
        result[domain] = "ACTIVE_LIVE_VERIFIED"
        print("antigravity_domain=" + domain + " result=" + result[domain], flush=True)

    print("antigravity_activation_summary_begin", flush=True)
    for domain in DOMAINS:
        print(domain + " " + result.get(domain, "UNPROCESSED"), flush=True)
    print("antigravity_activation_summary_end", flush=True)
    count = sum(v in ("ACTIVE_LIVE_VERIFIED","ALREADY_ACTIVE_HEALTH_VERIFIED") for v in result.values())
    print("antigravity_verified_active_count=" + str(count), flush=True)
    # Nonzero for incomplete groups. Already-confirmed routes remain committed;
    # failed routes stay FAILED and must not affect the five stable services.
    if count != len(DOMAINS):
        raise SystemExit(2)


def self_test() -> None:
    assert len(DOMAINS) == len(set(DOMAINS)) == 12
    assert all(owner._render.validate_domain(d) == d for d in DOMAINS)
    assert len({run_id("42871045861", i) for i in range(1, 13)}) == 12
    assert run_id("42871045861", 12) == "4287104586112"
    print("antigravity_live_owner_batch_offline=PASS")


if __name__ == "__main__":
    if sys.argv[1:] == ["self-test"]:
        self_test()
    elif sys.argv[1:] == ["run"]:
        live_activate()
    else:
        raise SystemExit("usage: antigravity-batch self-test|run")
