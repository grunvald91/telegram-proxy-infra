#!/usr/bin/env python3
"""Bounded, read-only inspection of all 523 named FQDNs from the user research.

This is a catalog of HTTP/TLS differences, NOT a verified blocklist or a
CoreDNS/NGINX deployment plan. Never modifies live DNS, proxies, or PostgreSQL.
"""
from __future__ import annotations
import argparse
import csv
import datetime as dt
import importlib.util
import json
import pathlib
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent
CATALOG = ROOT / "data/mnebydns-geoblock-research-20261110.tsv"
PROBE_PATH = ROOT / "scripts/mnebydns-geoblock-stage2-probe-20261111.py"
MODULE = importlib.util.spec_from_file_location("paired_probe", PROBE_PATH)
if MODULE is None or MODULE.loader is None:
    raise RuntimeError("Existing strict RU/DE probe cannot be imported")
probe = importlib.util.module_from_spec(MODULE)
MODULE.loader.exec_module(probe)

BATCH = 40
EXPECTED = 523
ROUTE_CANDIDATES = 506
BATCHES = (EXPECTED + BATCH - 1) // BATCH
OUT = ROOT / "full-catalog-results"

def rows():
    values = []
    with CATALOG.open(newline="") as f:
        reader = csv.DictReader((line for line in f if not line.startswith("#")), delimiter="\t")
        if reader.fieldnames != ["domain", "sections", "mentions", "kind", "status"]:
            raise ValueError("Unexpected research TSV schema")
        for record in reader:
            host = probe.domain(record["domain"])
            if host != record["domain"]:
                raise ValueError("Catalog domains must be lowercase")
            values.append(record)
    if len(values) != EXPECTED or len(set(r["domain"] for r in values)) != EXPECTED:
        raise ValueError("523-entry catalog mismatch")
    if sum(x["status"] == "PENDING_RESEARCH" for x in values) != ROUTE_CANDIDATES:
        raise ValueError("Research-only status count changed")
    if sum(x["status"] != "PENDING_RESEARCH" for x in values) != 17:
        raise ValueError("17 contextual-only entries missing")
    return sorted(values, key=lambda r: r["domain"])

def batches():
    return [rows()[n:n+BATCH] for n in range(BATCHES)]

def run_batch(n):
    if not 0 <= n < BATCHES:
        raise ValueError("Batch out of bounds")
    batch = batches()[n]
    names = [r["domain"] for r in batch]
    de = probe.via_ssh("DE", [{"host": name} for name in names])
    ru = probe.via_ssh("RU", [{"host": name, "origin_ipv4": de[name].get("origin_ipv4")} for name in names])
    records = [{**meta, "de": de[meta["domain"]], "ru": ru[meta["domain"]]} for meta in batch]
    for row in records:
        if row["de"]["host"] != row["domain"] or row["ru"]["host"] != row["domain"]:
            raise ValueError("Host identity changed")
        dip = row["de"].get("origin_ipv4")
        rip = row["ru"].get("origin_ipv4")
        if dip and rip and dip != rip:
            raise ValueError("Comparison IP mismatch")
    OUT.mkdir(mode=0o700, exist_ok=True)
    path = OUT / f"batch-{n:02d}.json"
    path.write_text(json.dumps({"batch": n, "records": records}, ensure_ascii=True, indent=2) + "\n")
    print(f"catalog_batch_{n:02d}=VERIFIED host_count={len(records)}")
    print("catalog_live_changes=false")

def status(row, region):
    obj = row[region]
    if not obj.get("certificate_verified"):
        return None
    x = obj.get("http_status")
    return x if isinstance(x, int) and 100 <= x <= 599 else None

def classify(row):
    ru, de = status(row, "ru"), status(row, "de")
    if ru in (403, 451):
        if de is not None and 200 <= de < 400:
            return "RU_403_451_DE_2XX_3XX"
        if de in (403, 451):
            return "RU_403_451_DE_ALSO_DENIED"
        return "RU_403_451_DE_INCONCLUSIVE"
    if not row["de"].get("certificate_verified"):
        return "DE_ORIGIN_TLS_UNVERIFIED"
    if not row["ru"].get("certificate_verified"):
        return "RU_TCP_OR_TLS_DIFFERENCE"
    if de == ru and ru is not None:
        return "SAME_HTTP_STATUS"
    if de is not None and ru is not None:
        return "OTHER_HTTP_STATUS_DIFFERENCE"
    return "HTTP_STATUS_INCONCLUSIVE"

def process(input_dir):
    expected = rows()
    actual = {}
    for n in range(BATCHES):
        file = input_dir / f"batch-{n:02d}.json"
        if not file.is_file():
            raise ValueError(f"Missing batch {n}")
        parsed = json.loads(file.read_text())
        if parsed.get("batch") != n:
            raise ValueError(f"Misidentified batch {n}")
        batch_records = parsed.get("records")
        expected_batch = expected[n*BATCH:(n+1)*BATCH]
        if not isinstance(batch_records, list) or len(batch_records) != len(expected_batch):
            raise ValueError(f"Incomplete batch {n}")
        if [x["domain"] for x in batch_records] != [x["domain"] for x in expected_batch]:
            raise ValueError(f"Mismatch batch {n}")
        for item in batch_records:
            host = item["domain"]
            if host in actual:
                raise ValueError("Duplicate result: " + host)
            if not all(item.get(k) == meta.get(k) for k,meta in (("domain", next(r for r in expected_batch if r["domain"]==host)),("status", next(r for r in expected_batch if r["domain"]==host)))):
                raise ValueError("Metadata changed for host " + host)
            if item["de"].get("host") != host or item["ru"].get("host") != host:
                raise ValueError("Probe host mismatch for " + host)
            dip, rip = item["de"].get("origin_ipv4"), item["ru"].get("origin_ipv4")
            if dip and rip and dip != rip:
                raise ValueError("Different IP in same-origin comparison")
            actual[host] = item
    if set(actual) != {x["domain"] for x in expected}:
        raise ValueError("Full 523-host coverage not achieved")

    enriched = [{**actual[row["domain"]], "classification": classify(actual[row["domain"]])}
                for row in expected]
    flagged = [r for r in enriched if status(r, "ru") in (403,451)]
    likely = [r for r in flagged if r["classification"] == "RU_403_451_DE_2XX_3XX"]
    pending = [r for r in likely if r["status"] == "PENDING_RESEARCH"]
    exceptions = [r for r in enriched if r["status"] != "PENDING_RESEARCH"]
    counts = Counter(r["classification"] for r in enriched)
    OUT.mkdir(mode=0o700, exist_ok=True)
    def save_csv(filename, records):
        with (OUT / filename).open("w", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("domain","source_status","classification","ru_http_status","de_http_status",
                             "ru_probe_state","de_probe_state","fixed_origin_ipv4"))
            for r in records:
                writer.writerow((r["domain"], r["status"], r["classification"],
                    status(r, "ru") or "", status(r, "de") or "",
                    r["ru"].get("state",""), r["de"].get("state",""),
                    r["de"].get("origin_ipv4") or ""))
    save_csv("all-523-results.csv", enriched)
    save_csv("ru-http-403-451.csv", flagged)
    save_csv("ru-403-451-de-success.csv", likely)
    save_csv("context-only-17.csv", exceptions)
    for filename, items in [
        ("ru-http-403-451.txt", flagged),
        ("ru-403-451-de-success.txt", likely),
        ("pending-review-not-active.txt", pending)
    ]:
        (OUT / filename).write_text("\n".join(x["domain"] for x in items) + ("\n" if items else ""))
    (OUT / "all-523-results.json").write_text(json.dumps(enriched, ensure_ascii=False, indent=2) + "\n")

    ts = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    lines = [
        "# MNEBYDNS — full 523-host HTTPS screen",
        "",
        f"Date (UTC): {ts}. Full research inventory: {EXPECTED} exact FQDNs, including "
        f"{ROUTE_CANDIDATES} potential routing candidates and {len(exceptions)} context-only names.",
        "",
        "**This is NOT a confirmed geopolitical blocklist and it makes NO live DNS, proxy, server or database changes.**",
        "Each location requests GET / to the same DE-resolved public origin IPv4, using the "
        "original SNI/Host and trusted CA certificate validation. Login, redirects, application features, "
        "dynamic CDN hosts, ECH, QUIC and mobile client compatibility are not tested.",
        "",
        f"- Verified RU HTTP 403 or 451: **{len(flagged)}** (both statuses combined, any DE result).",
        f"- Of those, DE HTTP 2xx/3xx: **{len(likely)}** (more useful access difference evidence, still not proof of policy).",
        f"- Within those, names eligible for further individual review based on source status: **{len(pending)}**.",
        f"- Unroutable / context-only entries: **{len(exceptions)}** (included in scan, excluded from proposed routes).",
        "",
        "## All status categories",
        "",
    ]
    lines.extend(f"- {k}: {counts[k]}" for k in sorted(counts))
    lines += ["", "## RU HTTP 403 / 451 (full list)", "",
              "| Domain | RU | DE | Source status | Evidence category |",
              "|---|---:|---:|---|---|"]
    for r in flagged:
        lines.append(f"| {r['domain']} | {status(r,'ru')} | {status(r,'de') or '—'} | "
                     f"{r['status']} | {r['classification']} |")
    lines += ["", "## Already routed hosts and exclusions", "",
              "This report does NOT assert a hostname is absent from the live CoreDNS or Nginx SNI map. "
              "Already-active hosts (including ChatGPT per owner) must be **excluded** from route activation "
              "after a separate live database and route-map cross-check. A 403 on a direct RU origin does "
              "not indicate that an existing Smart DNS route is broken.",
              "",
              "The seventeen context-only domains are included in the raw results but deliberately not "
              "promoted to any route candidate list. Every additional host requires an origin, "
              "RU→DE public ingress, DNS RR, and client-level canary before approval.",
              ""]
    (OUT / "report.md").write_text("\n".join(lines))
    print(f"CATALOG_SCAN_COMPLETE={len(enriched)}")
    print(f"CATALOG_RU_403_451_COUNT={len(flagged)}")
    print(f"CATALOG_RU_403_451_DE_SUCCESS_COUNT={len(likely)}")
    print(f"CATALOG_PENDING_REVIEW_COUNT={len(pending)}")
    print(f"CATALOG_CONTEXT_ONLY_COUNT={len(exceptions)}")
    print("CATALOG_403_451_BEGIN")
    print("domain,ru_code,de_code,source_status,evidence")
    for r in flagged:
        print(",".join([r["domain"],str(status(r,"ru")),
                        str(status(r,"de") or ""),r["status"],r["classification"]]))
    print("CATALOG_403_451_END")
    print("CATALOG_LIVE_DNS_CONFIG_CHANGED=false")

def self_test():
    records = rows()
    if len(batches()) != 14 or len(batches()[13]) != 3:
        raise AssertionError("Batched 523-record coverage failed")
    fake = lambda region, code, tls=True: dict(host="test.org",origin_ipv4="1.1.1.1",
            http_status=code,certificate_verified=tls,state="TLS_AND_HTTP" if tls else "TLS_ERROR")
    base = dict(domain="test.org",de=fake("de",200),ru=fake("ru",403))
    assert classify(base)=="RU_403_451_DE_2XX_3XX"
    base["ru"]["http_status"]=451
    assert classify(base)=="RU_403_451_DE_2XX_3XX"
    base["de"]["http_status"]=403
    assert classify(base)=="RU_403_451_DE_ALSO_DENIED"
    base["ru"]["http_status"]=200
    base["de"]["http_status"]=200
    assert classify(base)=="SAME_HTTP_STATUS"
    assert len(records)==EXPECTED
    print("CATALOG_OFFLINE_CONTRACT=PASS")
    print(f"CATALOG_EXPECTED_BATCH_COUNT={BATCHES}")

def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--self-test",action="store_true")
    group.add_argument("--batch",type=int)
    group.add_argument("--summarize",type=pathlib.Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.batch is not None:
        run_batch(args.batch)
    else:
        process(args.summarize)

if __name__=="__main__":
    main()
