#!/usr/bin/env python3
"""Prepare ONE bounded, read-only, source-attested mass route pilot.

No production writes here. Only exact Research 2026-11 PENDING hosts with
fresh DE 2xx/3xx, RU 403/451, verified TLS on the SAME origin IP qualify.
The separate guarded controller is the only component allowed to stage it.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "bulk-108-work"
SCAN = ROOT / "mass-108-results" / "differential.json"
BATCH = ROOT / "scripts" / "mnebydns-batch-108-canary-20261112.py"
spec = importlib.util.spec_from_file_location("bounded_batch", BATCH)
assert spec is not None and spec.loader is not None
batch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)
owner = batch.owner
# Actual live evidence, not a claim that these sites are universally blocked.
# id.cisco.com: mass public-edge HTTPS TCP timeout, live rollback verified:
# https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43303272458
# codebrowser.dev: RU direct TCP timeout in the 108-host mass differential:
# https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43297171379
LIVE_EXCLUSIONS = {
    "id.cisco.com": "PUBLIC_EDGE_TCP_TIMEOUT_43303272458",
    "codebrowser.dev": "INTERMITTENT_RU_TCP_TIMEOUT_43297171379",
    # Independent bulk rollout also returned EDGE HTTPS failures, then
    # successfully rolled back: run #43303737663.
    "manus.im": "PUBLIC_EDGE_HTTPS_FAILED_43303737663",
    "www.support.xerox.com": "PUBLIC_EDGE_HTTPS_FAILED_43303737663",
}

def sha(b: str) -> str:
    return hashlib.sha256(b.encode("utf-8")).hexdigest()

def qualify(names: list[str], rows: dict, observations: list[dict]):
    """Fail closed on malformed evidence; foreign-owned or ACTIVE are excluded."""
    if len(names) != 108 or len(observations) != 108:
        raise RuntimeError("Exact 108 inventory and fresh scan required")
    evidence = {}
    for item in observations:
        host = owner._render.validate_domain(item["host"])
        if host in evidence or host not in names:
            raise RuntimeError("Unexpected/duplicate scan hostname")
        evidence[host] = item
    if set(evidence) != set(names):
        raise RuntimeError("Incomplete 108-host scan")
    selected, exclusions = [], []
    for host in names:
        if host not in rows:
            raise RuntimeError("Missing DB hostname: " + host)
        state, product, error = rows[host]
        if product != batch.PRODUCT:
            exclusions.append(dict(domain=host, reason="OTHER_PRODUCT", state=state))
            continue
        if state == "ACTIVE":
            if error:
                raise RuntimeError("Existing research ACTIVE has unresolved health error")
            exclusions.append(dict(domain=host, reason="ALREADY_ACTIVE", state=state))
            continue
        if state != "PENDING":
            raise RuntimeError("Unresolved research status on " + host + ": " + state)
        if host in LIVE_EXCLUSIONS:
            exclusions.append(dict(domain=host, reason=LIVE_EXCLUSIONS[host], state=state))
            continue
        item = evidence[host]
        de, ru = item["de"], item["ru"]
        ip = de.get("origin_ipv4")
        if (de.get("certificate_verified") is not True or
            ru.get("certificate_verified") is not True or
            ru.get("origin_ipv4") != ip or
            type(de.get("http_status")) is not int or
            type(ru.get("http_status")) is not int or
            not (200 <= de["http_status"] < 400) or
            ru["http_status"] not in (403, 451)):
            exclusions.append(dict(domain=host, reason="NOT_CONFIRMED_RU403_DE_SUCCESS", state=state))
            continue
        selected.append(dict(domain=host, ip=owner._render.validated_public_ip(ip),
                             de_http=de["http_status"], ru_http=ru["http_status"]))
    return selected, exclusions

def render(candidates: list[dict], dns: str, nginx: str):
    accepted, rejected = [], []
    for item in candidates:
        host, ip = item["domain"], item["ip"]
        try:
            new_dns = owner._render.core_add(dns, host)
            new_nginx = owner._render.nginx_add(nginx, host, ip)
        except (ValueError, AssertionError) as exc:
            rejected.append(dict(domain=host, reason="EXISTING_ROUTE_OVERLAP_OR_RENDER_INVALID",
                                 error_type=type(exc).__name__))
            continue
        dns, nginx = new_dns, new_nginx
        accepted.append(item)
    return accepted, rejected, dns, nginx

def self_test():
    names = batch.inventory()
    assert len(names) == 108
    fake = {n: ("PENDING", batch.PRODUCT, "") for n in names}
    fake[names[0]] = ("ACTIVE", batch.PRODUCT, "")
    fake[names[1]] = ("PENDING", "Oracle", "")
    ev = [dict(host=n, de=dict(origin_ipv4="93.184.215.14",certificate_verified=True,http_status=200),
            ru=dict(origin_ipv4="93.184.215.14",certificate_verified=True,http_status=403)) for n in names]
    ev[2]["ru"]["certificate_verified"] = False
    selected, exclusions = qualify(names, fake, ev)
    assert len(selected) == 101 and len(exclusions) == 7
    base_dns = ("tls://.:853 {\n"
                "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
                "    cache 30\n}\n")
    base_nginx = ("stream {\nmap $ssl_preread_server_name $direct_mtproxy_backend {\n"
                  " default 127.0.0.1:9443;\n}\n"
                  "server { proxy_pass $direct_mtproxy_backend; }\n}\n")
    a, rejected, core, proxy = render([selected[0], selected[1]], base_dns, base_nginx)
    assert len(a) == 2 and not rejected
    assert owner._render.mark(a[0]["domain"]) in core
    assert owner._render.mark(a[1]["domain"]) in proxy
    assert sha(core) != sha(base_dns)
    print("BULK_108_PREPARE_SELF_TEST=PASS",flush=True)

def plan():
    names = batch.inventory()
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("LIVE_CHECKPOINT_DRIFT")
    batch.ensure_quiet()
    batch.capacity()
    rows = batch.table()
    batch.preexisting_failure(rows, names)
    raw = json.loads(SCAN.read_text())
    if not isinstance(raw, dict) or not isinstance(raw.get("observations"), list):
        raise RuntimeError("Fresh mass scan JSON missing")
    candidates, exclusions = qualify(names, rows, raw["observations"])
    if not candidates:
        raise RuntimeError("NO_ELIGIBLE_EXACT_HOSTS")
    dns = owner.ssh("de", "cat /opt/mnebydns-dot/Corefile", 45)
    nginx = owner.ssh("de", "cat /etc/nginx/nginx.conf", 45)
    # SSH strips the final newline. Reconstitute exactly only when present
    # in the actual source, otherwise byte hashes would not match.
    def exact_read(path):
        cmd = "python3 -c 'import sys;sys.stdout.buffer.write(open(sys.argv[1],\"rb\").read().hex().encode())' " + path
        return bytes.fromhex(owner.ssh("de", cmd, 60)).decode("utf-8")
    dns = exact_read("/opt/mnebydns-dot/Corefile")
    nginx = exact_read("/etc/nginx/nginx.conf")
    selected, rejected, next_dns, next_nginx = render(candidates, dns, nginx)
    if not selected:
        raise RuntimeError("All routes collide with existing policy")
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError("LIVE_CHANGED_DURING_BULK_RENDER")
    OUTPUT.mkdir(mode=0o700, exist_ok=True)
    for filename, value in (("dns.before",dns),("nginx.before",nginx),
                            ("dns.pilot",next_dns),("nginx.pilot",next_nginx)):
        f = OUTPUT / filename
        if f.exists():raise RuntimeError("Refuse to overwrite existing plan")
        f.write_text(value,encoding="utf-8")
        f.chmod(0o600)
    result = dict(total_reviewed=108, requested_count=len(candidates),
                  deploy_count=len(selected), selected=selected,
                  excluded=exclusions + rejected,
                  dns_before_sha256=sha(dns), nginx_before_sha256=sha(nginx),
                  dns_pilot_sha256=sha(next_dns), nginx_pilot_sha256=sha(next_nginx))
    (OUTPUT / "plan.json").write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n")
    (OUTPUT / "report.md").write_text(
      "# MNEBYDNS one-pass guarded preparation\n\n"
      + "- Reviewed: 108\n- Eligible for exact bulk stage: "+str(len(selected))
      +"\n- Excluded: "+str(len(result["excluded"]))
      +"\n- Production routes changed: NO\n"
      +"\n## Exclusions\n" + "\n".join("- `"+x["domain"]+"`: "+x["reason"] for x in result["excluded"])+"\n")
    print("BULK_108_PLAN="+json.dumps({k:result[k] for k in ("total_reviewed","requested_count","deploy_count")},sort_keys=True),flush=True)
    print("BULK_108_EXCLUSIONS="+json.dumps(result["excluded"],ensure_ascii=False),flush=True)
    print("BULK_108_LIVE_MUTATIONS=NONE",flush=True)

if __name__ == "__main__":
    a=argparse.ArgumentParser()
    a.add_argument("command",choices=("self-test","plan"))
    args=a.parse_args()
    if args.command=="self-test":self_test()
    else:plan()
