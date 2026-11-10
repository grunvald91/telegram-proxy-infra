#!/usr/bin/env python3
"""One-shot, intentionally production-scoped exact-host E2E on a low-traffic test site.

Actions main-only gated. No arbitrary domain input. Runs same controller APIs as
owner queue, but SQL transitions simulate the Telegram button presses; Telegram
identity enforcement is covered separately by the Mnebyvpn application CI.
Two phases: add -> confirm -> remove, then add -> independent rollback -> cancel.
Always compare actual live CoreDNS/Nginx hashes against the original checkpoint.
"""
from __future__ import annotations
import importlib.util
import os
import re
import shlex
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location("owner_controller",ROOT/"mnebydns-owner-domain-controller-20261110.py")
assert SPEC is not None and SPEC.loader is not None
owner=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owner)
TARGET="www.rfc-editor.org"

def db(query):
    return owner.sql(query).strip()

def set_phase(phase:int):
    run=int(os.environ["GITHUB_RUN_ID"])*10+phase
    if not 10**9<=run<10**13:raise RuntimeError("E2E run ID outside valid canary range")
    owner.RUNID=str(run)
    owner.WORK="/tmp/mnebydns-owner-domain-"+owner.RUNID
    return owner.RUNID

def row():
    candidate=owner.get_task()
    if candidate is None or candidate["domain"]!=TARGET:
        raise RuntimeError("Owner E2E DB queue does not contain exactly our test host")
    return candidate

def expect_state(state):
    status=db("SELECT status FROM dns_admin_domains WHERE domain='"+TARGET+"'")
    if status!=state:
        raise RuntimeError("E2E expected status="+state+" observed="+status)
    print("owner_e2e_verified_state="+state,flush=True)

def saved_hashes():
    return owner.ssh("de","sha256sum /opt/mnebydns-dot/Corefile /etc/nginx/nginx.conf",40)

def ensure_empty_queue():
    other=db(
        "SELECT count(*) FROM dns_admin_domains WHERE status IN "
        "('APPLY_REQUESTED','PROBING','CANARY','CONFIRM_REQUESTED','CONFIRMING',"
        "'ROLLBACK_REQUESTED','REMOVAL_PENDING','REMOVING')"
        " AND domain<>'"+TARGET+"'")
    if other!="0":raise RuntimeError("E2E skipped: another owner route in progress")

def state_sql(update,expected):
    # Every state change must be a single compare-and-swap DB write.
    changed=db(update+" RETURNING id")
    if changed!=test_id:
        raise RuntimeError("E2E state transition rejected: "+expected)

def recover_only_our_confirmed_test_route():
    """Safely remove an E2E-owned ACTIVE route stranded by the prior crash.

    Never change owner-added domains or unrelated active services; route must
    exist in both current committed configs before scheduling guarded removal.
    """
    global test_id
    status=db("SELECT status FROM dns_admin_domains WHERE domain='"+TARGET+"'")
    product=db("SELECT product FROM dns_admin_domains WHERE domain='"+TARGET+"'")
    if status!="ACTIVE" or product!="e2e-test":
        return
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("E2E recovery refused on drifted live checkpoint")
    test_id=db("SELECT id FROM dns_admin_domains WHERE domain='"+TARGET+"'"
               " AND product='e2e-test' AND status='ACTIVE'")
    if not re.fullmatch(r"[1-9][0-9]{0,14}",test_id):
        raise RuntimeError("Invalid test-route recovery identity")
    mark=owner._render.mark(TARGET)
    proof=("set -Eeuo pipefail; "
           "root=$(cat /opt/mnebydns-stable-checkpoints/current); "
           "(cd \"$root\" && sha256sum -c stable-manifest.sha256 >/dev/null); "
           "cmp -s \"$root/dns.stable\" /opt/mnebydns-dot/Corefile; "
           "cmp -s \"$root/nginx.stable\" /etc/nginx/nginx.conf; "
           "grep -Fq -- "+shlex.quote(mark)+" /opt/mnebydns-dot/Corefile; "
           "grep -Fq -- "+shlex.quote(mark)+" /etc/nginx/nginx.conf; "
           "echo OWN_TEST_ROUTE_EXACTLY_PRESENT")
    if owner.ssh("de",proof,40).strip()!="OWN_TEST_ROUTE_EXACTLY_PRESENT":
        raise RuntimeError("Live route proof missing: refuse recovery")
    state_sql(
        "UPDATE dns_admin_domains SET status='REMOVAL_PENDING',"
        "revision=revision+1,updated_at=now() WHERE id="+test_id+
        " AND status='ACTIVE' AND product='e2e-test'",
        "RECOVER_PREVIOUS_TEST")
    set_phase(9)
    owner.remove(row())
    expect_state("CANCELLED")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("Previous E2E recovery did not commit clean baseline")
    absence=("set -Eeuo pipefail; "
             "! grep -Fq -- "+shlex.quote(mark)+" /opt/mnebydns-dot/Corefile; "
             "! grep -Fq -- "+shlex.quote(mark)+" /etc/nginx/nginx.conf; "
             "systemctl is-active --quiet mnebydns-dot.service; "
             "ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; "
             "echo OWN_TEST_ROUTE_ABSENT_AND_DOT_READY")
    if owner.ssh("de",absence,40).strip()!="OWN_TEST_ROUTE_ABSENT_AND_DOT_READY":
        raise RuntimeError("Recovered E2E test hostname not fully removed")
    print("owner_e2e_previous_confirmed_route_recovered=PASS",flush=True)


def main():
    global test_id
    if os.environ.get("GITHUB_REF")!="refs/heads/main" or \
       os.environ.get("GITHUB_EVENT_NAME")!="push":
        raise RuntimeError("E2E requires a one-off reviewed merge to main")
    assert owner._render.validate_domain(TARGET)==TARGET
    assert owner.PINNED_SSH_HOSTS.is_file()
    ensure_empty_queue()
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("E2E skipped: unrelated live canary or checkpoint drift")
    # On an earlier failed test the *test-only* route was confirmed, then the
    # removal was reverted safely. Remove it first before taking baseline hashes.
    recover_only_our_confirmed_test_route()
    # A failed previous E2E may leave only its own CANCELLED row. Reuse only
    # that exact verified marker; never touch an owner-entered custom domain.
    foreign=db("SELECT count(*) FROM dns_admin_domains WHERE domain='"+TARGET+"'"
               " AND (product<>'e2e-test' OR status<>'CANCELLED')")
    if foreign!="0":
        raise RuntimeError("E2E test host already in use; refusing override")
    previous=db("SELECT id FROM dns_admin_domains WHERE domain='"+TARGET+"'"
                " AND product='e2e-test' AND status='CANCELLED'")
    before=saved_hashes()
    test_id=""
    last_run=""
    passed=False
    try:
        if previous:
            if not re.fullmatch(r"[1-9][0-9]{0,14}",previous):
                raise RuntimeError("Untrusted prior test row ID")
            test_id=db("UPDATE dns_admin_domains SET status='APPLY_REQUESTED',"
                       "revision=revision+1,canary_run_id=NULL,canary_expires_at=NULL,"
                       "last_error_code=NULL,updated_at=now() WHERE id="+previous+
                       " AND status='CANCELLED' AND product='e2e-test' RETURNING id")
        else:
            test_id=db(
                "INSERT INTO dns_admin_domains(domain,product,status) "
                "VALUES ('"+TARGET+"','e2e-test','APPLY_REQUESTED') RETURNING id")
        if not re.fullmatch(r"[1-9][0-9]{0,14}",test_id):
            raise RuntimeError("Cannot create or claim isolated owner E2E row")
        print("owner_e2e_test_db_id="+test_id,flush=True)
        # phase 1: add / verify / confirm / remove
        last_run=set_phase(1)
        ensure_empty_queue()
        owner.apply(row())
        expect_state("CANARY")
        state_sql(
            "UPDATE dns_admin_domains SET status='CONFIRM_REQUESTED',"
            "revision=revision+1,updated_at=now() WHERE id="+test_id+
            " AND status='CANARY' AND canary_expires_at>now()+interval '10 minutes'",
            "CONFIRM_REQUESTED")
        owner.confirm(row())
        expect_state("ACTIVE")
        state_sql(
            "UPDATE dns_admin_domains SET status='REMOVAL_PENDING',"
            "revision=revision+1,updated_at=now() WHERE id="+test_id+
            " AND status='ACTIVE'",
            "REMOVAL_PENDING")
        last_run=set_phase(2)
        owner.remove(row())
        expect_state("CANCELLED")
        if saved_hashes()!=before:
            raise RuntimeError("After confirmed removal, live config differs from pre-E2E")
        if not owner.live_checkpoint_unchanged():
            raise RuntimeError("After confirmed removal, checkpoint is inconsistent")
        print("owner_e2e_confirm_remove_live_restored=PASS",flush=True)
        # phase 2: demonstrate independent systemd rollback before DB cleanup
        state_sql(
            "UPDATE dns_admin_domains SET status='APPLY_REQUESTED',"
            "revision=revision+1,canary_run_id=NULL,canary_expires_at=NULL,"
            "last_error_code=NULL,updated_at=now() WHERE id="+test_id+
            " AND status='CANCELLED'",
            "APPLY_REQUESTED_RETEST")
        last_run=set_phase(3)
        owner.apply(row())
        expect_state("CANARY")
        service="mnebydns-owner-rollback-"+last_run+".service"
        out=owner.ssh("de","systemctl start "+shlex.quote(service)+
                      " && systemctl is-active --quiet nginx"
                      " && systemctl is-active --quiet mnebydns-dot.service"
                      " && echo INDEPENDENT_SYSTEMD_ROLLBACK_OK",90)
        if "INDEPENDENT_SYSTEMD_ROLLBACK_OK" not in out:
            raise RuntimeError("Independent systemd rollback failed")
        print("owner_e2e_independent_systemd_rollback=PASS",flush=True)
        state_sql(
            "UPDATE dns_admin_domains SET status='ROLLBACK_REQUESTED',"
            "revision=revision+1,updated_at=now() WHERE id="+test_id+
            " AND status='CANARY'",
            "ROLLBACK_REQUESTED")
        owner.cancel_canary(row())
        expect_state("CANCELLED")
        if saved_hashes()!=before or not owner.live_checkpoint_unchanged():
            raise RuntimeError("Live CoreDNS/Nginx/checkpoint not restored after timer")
        print("owner_e2e_full_cycle=PASS",flush=True)
        passed=True
    finally:
        if not passed:
            print("owner_e2e_failure_cleanup_started=true",flush=True)
            try:
                state=db("SELECT status FROM dns_admin_domains WHERE domain='"+TARGET+"'")
                canary_id=db("SELECT coalesce(canary_run_id::text,'') FROM dns_admin_domains "
                             "WHERE domain='"+TARGET+"'")
                if state in ("CANARY","PROBING","ROLLBACK_REQUESTED","CONFIRM_REQUESTED") and \
                   re.fullmatch(r"[1-9][0-9]{8,12}",canary_id):
                    owner.rollback_or_unchanged(canary_id)
                    if saved_hashes()==before:
                        db("UPDATE dns_admin_domains SET status='FAILED',"
                           "last_error_code='E2E_ABORT_ROLLED_BACK',canary_expires_at=NULL"
                           " WHERE id="+test_id+" AND status IN ('CANARY','PROBING',"
                           "'ROLLBACK_REQUESTED','CONFIRM_REQUESTED')")
                        print("owner_e2e_cleanup_live_baseline_verified=true",flush=True)
                elif state in ("ACTIVE","REMOVAL_PENDING","REMOVING"):
                    # A previously confirmed add cannot use its old rollback
                    # script. Instead run the same guarded *removal* transition.
                    if state=="ACTIVE":
                        changed=db("UPDATE dns_admin_domains SET status='REMOVAL_PENDING',"
                                   "revision=revision+1,updated_at=now() WHERE id="+test_id+
                                   " AND status='ACTIVE' RETURNING id")
                        if changed!=test_id:raise RuntimeError("Cannot queue cleanup removal")
                    if state=="REMOVING":
                        owner.remove(row())  # recover old removal safely
                        state=db("SELECT status FROM dns_admin_domains WHERE id="+test_id)
                        if state=="ACTIVE":
                            changed=db("UPDATE dns_admin_domains SET status='REMOVAL_PENDING',"
                                       "revision=revision+1,updated_at=now() WHERE id="+test_id+
                                       " AND status='ACTIVE' RETURNING id")
                            if changed!=test_id:raise RuntimeError("Cannot retry removal")
                    if db("SELECT status FROM dns_admin_domains WHERE id="+test_id)=="REMOVAL_PENDING":
                        set_phase(4)
                        owner.remove(row())
                    if saved_hashes()!=before or not owner.live_checkpoint_unchanged():
                        raise RuntimeError("E2E cleanup removed row but live baseline differs")
                    print("owner_e2e_confirmed_route_cleanup_verified=true",flush=True)
                else:
                    print("owner_e2e_manual_recovery_required_state="+state,flush=True)
            except Exception as exc:
                print("owner_e2e_cleanup_UNVERIFIED="+type(exc).__name__,flush=True)


if __name__=="__main__":
    main()
