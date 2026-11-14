#!/usr/bin/env python3
"""Synthetic runner, Termux generator, CSV reporter and verdict calculator for MNEBYDNS TZ.

Implements Sections 6, 7, 8 and 13 of the DPI-evasion experiment specification:
- Matrix cells A (control, clamp off), C (i.instagram.com, clamp off),
  B (control, clamp on), D (i.instagram.com, clamp on), E (graph.instagram.com, clamp on)
- Post-failure control probe after failed Cell C attempts (Section 7.2)
- Server PCAP evidence matching (phone-sni.json -> first TCP segment length)
- Validity criteria V1-V3, network verdict (7.2), and overall verdict (7.3)
- Stage 2 throughput & PMTU checks (Section 8)
- Section 13 CSV output
"""
from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import datetime as dt
import json
import math
from pathlib import Path
import shlex
import subprocess
import sys
import time

RU_EDGE = "188.120.254.223"
DEFAULT_CONTROL_SNI = "gemini.google.com"
DEFAULT_CELL_ORDER = ("A", "C", "B", "D", "E")

CSV_HEADER = (
    "run_id",
    "дата_время",
    "оператор",
    "тип_сети",
    "внешний_IP",
    "ячейка",
    "попытка",
    "SNI",
    "clamp",
    "результат",
    "http",
    "time_connect",
    "time_appconnect",
    "длина_первого_сегмента",
    "комментарий",
)

CELL_SPECS = {
    "A": {"sni": None, "clamp": "выкл", "role": "control_baseline"},
    "B": {"sni": None, "clamp": "вкл", "role": "control_clamped"},
    "C": {"sni": "i.instagram.com", "clamp": "выкл", "role": "target_baseline"},
    "D": {"sni": "i.instagram.com", "clamp": "вкл", "role": "target_clamped"},
    "E": {"sni": "graph.instagram.com", "clamp": "вкл", "role": "target_secondary_clamped"},
}


@dataclass(frozen=True)
class AttemptSpec:
    cell: str
    attempt: int
    sni: str
    clamp: str


def build_schedule(
    cells: tuple[str, ...] = DEFAULT_CELL_ORDER,
    attempts: int = 20,
    *,
    control_sni: str = DEFAULT_CONTROL_SNI,
    interleave: bool = False,
    sequential_blocks: bool = False,
) -> list[AttemptSpec]:
    """Build experiment schedule.

    By default interleaves attempts within each clamp phase (`A, C` for выкл,
    then `B, D, E` for вкл) per Section 6 without overlapping phases. Use
    `sequential_blocks=True` for one cell at a time or `interleave=True` to
    interleave all requested cells together across rounds.
    """
    for cell in cells:
        if cell not in CELL_SPECS:
            raise ValueError(f"Unknown experiment cell: {cell}")
    if attempts < 1:
        raise ValueError("attempts must be >= 1")

    def spec_for(cell: str, idx: int) -> AttemptSpec:
        meta = CELL_SPECS[cell]
        sni = control_sni if meta["sni"] is None else meta["sni"]
        return AttemptSpec(cell=cell, attempt=idx, sni=sni, clamp=meta["clamp"])

    schedule: list[AttemptSpec] = []
    if interleave:
        for idx in range(1, attempts + 1):
            for cell in cells:
                schedule.append(spec_for(cell, idx))
    elif sequential_blocks:
        for cell in cells:
            for idx in range(1, attempts + 1):
                schedule.append(spec_for(cell, idx))
    else:
        unclamped = [c for c in cells if CELL_SPECS[c]["clamp"] == "выкл"]
        clamped = [c for c in cells if CELL_SPECS[c]["clamp"] == "вкл"]
        for group in (unclamped, clamped):
            for idx in range(1, attempts + 1):
                for cell in group:
                    schedule.append(spec_for(cell, idx))
    return schedule


def is_http_success(http_code: int) -> bool:
    """Section 6: any 2xx-4xx HTTP status from target counts as a valid server reply."""
    return 200 <= http_code <= 499


def probe_curl(
    sni: str,
    *,
    edge_ip: str = RU_EDGE,
    timeout: int = 10,
    url_path: str = "/",
) -> dict[str, object]:
    """Execute one synthetic curl probe against edge_ip with exact SNI override."""
    cmd = [
        "curl", "-sS", "-o", "/dev/null",
        "-w", "%{http_code} %{time_connect} %{time_appconnect}",
        "--max-time", str(timeout),
        "--resolve", f"{sni}:443:{edge_ip}",
        f"https://{sni}{url_path}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    parts = proc.stdout.strip().split()
    http_code = int(parts[0]) if parts and parts[0].isdigit() else 0
    time_connect = parts[1] if len(parts) > 1 else "0"
    time_appconnect = parts[2] if len(parts) > 2 else "0"
    ok = proc.returncode == 0 and is_http_success(http_code)
    comment = "" if ok else (proc.stderr.strip().replace("\n", " ")[:180] or f"curl_rc={proc.returncode}")
    return {
        "ok": ok,
        "http": http_code,
        "time_connect": time_connect,
        "time_appconnect": time_appconnect,
        "comment": comment,
    }


def measure_download_bps(
    sni: str,
    url_path: str,
    *,
    edge_ip: str = RU_EDGE,
    timeout: int = 45,
) -> dict[str, object]:
    """Measure 10 MB payload download speed (bytes/sec) for V3 or Stage 2."""
    cmd = [
        "curl", "-sS", "-o", "/dev/null",
        "-w", "%{http_code} %{size_download} %{speed_download} %{time_total}",
        "--max-time", str(timeout),
        "--resolve", f"{sni}:443:{edge_ip}",
        f"https://{sni}{url_path}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    parts = proc.stdout.strip().split()
    http_code = int(parts[0]) if parts and parts[0].isdigit() else 0
    size_bytes = int(float(parts[1])) if len(parts) > 1 else 0
    speed_bps = float(parts[2]) if len(parts) > 2 else 0.0
    time_total = float(parts[3]) if len(parts) > 3 else 0.0
    ok = proc.returncode == 0 and is_http_success(http_code) and size_bytes > 0
    return {
        "ok": ok,
        "http": http_code,
        "size_bytes": size_bytes,
        "speed_bps": speed_bps,
        "time_total": time_total,
    }


def _parse_utc_epoch(value: str) -> int | None:
    if not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return int(parsed.timestamp())
    except ValueError:
        return None


def _flow_matches_clamp(flow: dict, clamp_state: str) -> bool:
    first_len = flow.get("first_segment_len")
    is_clamped = bool(flow.get("split")) or (first_len is not None and int(first_len) <= 8)
    if clamp_state == "вкл":
        return is_clamped
    if clamp_state == "выкл":
        return not is_clamped
    return True


def _apply_flow(row: dict[str, str], flow: dict) -> None:
    first_len = flow.get("first_segment_len")
    if first_len is not None:
        row["длина_первого_сегмента"] = str(first_len)
    split_flag = flow.get("split")
    if split_flag is not None:
        note = f"sni_split={str(split_flag).lower()}"
        existing = row.get("комментарий", "")
        if note not in existing:
            row["комментарий"] = f"{existing}; {note}".strip("; ")


def attach_evidence_to_rows(rows: list[dict[str, str]], evidence: dict) -> list[dict[str, str]]:
    """Match server-side flow_details from phone-sni.json into CSV rows."""
    details = evidence.get("flow_details")
    if not isinstance(details, list):
        details = evidence.get("tz_segment_metrics", {}).get("flow_details", [])
    by_host: dict[str, list[dict]] = {}
    for item in details:
        host = item.get("host")
        if isinstance(host, str):
            by_host.setdefault(host, []).append(item)

    control_sni = next(
        (r.get("SNI") for r in rows if r.get("ячейка") in ("A", "B") and r.get("SNI")),
        DEFAULT_CONTROL_SNI,
    )
    used: dict[str, set[int]] = {}
    updated = [dict(r) for r in rows]
    matched_idx: set[int] = set()

    # Pass 1: timestamp-aligned matching within [-2s, +15s], preferring clamp compatibility.
    for row_idx, copy in enumerate(updated):
        host = copy.get("SNI", "")
        flows = by_host.get(host, [])
        if copy.get("длина_первого_сегмента") or not flows:
            continue
        row_ts = _parse_utc_epoch(copy.get("дата_время", ""))
        if row_ts is None:
            continue
        clamp_state = copy.get("clamp") or CELL_SPECS.get(copy.get("ячейка", ""), {}).get("clamp", "")
        is_success = copy.get("результат") == "УСПЕХ"
        host_used = used.setdefault(host, set())

        best_key = None
        best_flow_idx = None
        for i, fl in enumerate(flows):
            if i in host_used:
                continue
            fl_ts = int(fl.get("utc_epoch") or 0)
            if fl_ts <= 0:
                continue
            delta = fl_ts - row_ts
            if not (-2 <= delta <= 15):
                continue
            if not is_success and not _flow_matches_clamp(fl, clamp_state):
                # Failed Cell C rows must never consume a clamped Cell D flow.
                continue
            key = (0 if _flow_matches_clamp(fl, clamp_state) else 1, abs(delta), i)
            if best_key is None or key < best_key:
                best_key = key
                best_flow_idx = i

        if best_flow_idx is not None:
            host_used.add(best_flow_idx)
            matched_idx.add(row_idx)
            _apply_flow(copy, flows[best_flow_idx])

    # Reserve timed ip_punish_check flows (control_sni, clamp=выкл) triggered after failed Cell C rows.
    ctrl_flows = by_host.get(control_sni, [])
    ctrl_used = used.setdefault(control_sni, set())
    punish_reserved: set[int] = set()
    if ctrl_flows:
        for row_idx, copy in enumerate(updated):
            if copy.get("ячейка") != "C" or "ip_punish_check=" not in copy.get("комментарий", ""):
                continue
            row_ts = _parse_utc_epoch(copy.get("дата_время", ""))
            if row_ts is None:
                continue
            best_key = None
            best_flow_idx = None
            for i, fl in enumerate(ctrl_flows):
                if i in ctrl_used:
                    continue
                fl_ts = int(fl.get("utc_epoch") or 0)
                if fl_ts <= 0 or not _flow_matches_clamp(fl, "выкл"):
                    continue
                delta = fl_ts - row_ts
                if -2 <= delta <= 25:
                    key = (abs(delta), i)
                    if best_key is None or key < best_key:
                        best_key = key
                        best_flow_idx = i
            if best_flow_idx is not None:
                ctrl_used.add(best_flow_idx)
                punish_reserved.add(row_idx)

    # Pass 2: sequential fallback in row order for successful attempts + untimed punish reservations.
    for row_idx, copy in enumerate(updated):
        if (
            copy.get("ячейка") == "C"
            and "ip_punish_check=" in copy.get("комментарий", "")
            and row_idx not in punish_reserved
            and ctrl_flows
        ):
            for i, fl in enumerate(ctrl_flows):
                if i not in ctrl_used and _flow_matches_clamp(fl, "выкл"):
                    ctrl_used.add(i)
                    punish_reserved.add(row_idx)
                    break

        if row_idx in matched_idx or copy.get("длина_первого_сегмента") or copy.get("результат") != "УСПЕХ":
            continue
        host = copy.get("SNI", "")
        flows = by_host.get(host, [])
        if not flows:
            continue
        clamp_state = copy.get("clamp") or CELL_SPECS.get(copy.get("ячейка", ""), {}).get("clamp", "")
        host_used = used.setdefault(host, set())

        chosen_idx = None
        for want_clamp_match in (True, False):
            for i, fl in enumerate(flows):
                if i in host_used:
                    continue
                if want_clamp_match and not _flow_matches_clamp(fl, clamp_state):
                    continue
                chosen_idx = i
                break
            if chosen_idx is not None:
                break

        if chosen_idx is not None:
            host_used.add(chosen_idx)
            _apply_flow(copy, flows[chosen_idx])

    return updated


def _threshold_19(total: int) -> int:
    return math.ceil(0.95 * total)


def _threshold_18(total: int) -> int:
    return math.ceil(0.90 * total)


def _threshold_2(total: int) -> int:
    return math.floor(0.10 * total)


def evaluate_validity(
    rows: list[dict[str, str]],
    *,
    speed_a_bps: float | None = None,
    speed_b_bps: float | None = None,
    evidence: dict | None = None,
) -> dict[str, object]:
    """Evaluate V1, V2 and V3 run validity rules (Section 7.1)."""
    by_cell: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_cell.setdefault(row["ячейка"], []).append(row)

    def ok_count(cell: str) -> tuple[int, int]:
        items = by_cell.get(cell, [])
        return sum(1 for r in items if r.get("результат") == "УСПЕХ"), len(items)

    a_ok, a_n = ok_count("A")
    v1_pass = a_n > 0 and a_ok >= _threshold_19(a_n)

    b_items = by_cell.get("B", [])
    b_n = len(b_items)
    b_ok, _ = ok_count("B")

    # V2: first TCP segment length <= 4 bytes for >= 19/20 in Cell B.
    b_measured = [
        int(r["длина_первого_сегмента"])
        for r in b_items
        if str(r.get("длина_первого_сегмента", "")).isdigit()
    ]
    if b_measured:
        le4_count = sum(1 for v in b_measured if v <= 4)
        v2_status = "PASS" if b_n > 0 and le4_count >= _threshold_19(b_n) else "FAIL"
    elif evidence is not None:
        tz = evidence.get("tz_segment_metrics", {})
        other_sni = tz.get("other_sni", 0)
        other_le4 = tz.get("other_first_segment_le4", 0)
        if other_sni > 0:
            v2_status = "PASS" if other_le4 >= _threshold_19(b_n if b_n > 0 else other_sni) else "FAIL"
            le4_count = other_le4
        else:
            v2_status = "UNKNOWN"
            le4_count = 0
    else:
        v2_status = "UNKNOWN"
        le4_count = 0

    speed_ratio = (speed_b_bps / speed_a_bps) if (speed_a_bps and speed_a_bps > 0 and speed_b_bps is not None) else None
    v3_ok = b_n > 0 and b_ok >= _threshold_19(b_n)
    if speed_ratio is not None:
        v3_pass = v3_ok and speed_ratio >= 0.80
        v3_status = "PASS" if v3_pass else "FAIL"
    else:
        v3_status = "PASS_HTTP_ONLY_SPEED_PENDING" if v3_ok else "FAIL"

    return {
        "V1": {"status": "PASS" if v1_pass else "FAIL", "ok": a_ok, "total": a_n,
               "action": "" if v1_pass else "прогон повторить позже, канал нестабилен"},
        "V2": {"status": v2_status, "le4": le4_count, "total": b_n,
               "action": "" if v2_status != "FAIL" else "сегментация не срабатывает, способ непригоден на этом клиенте, дальше не идти"},
        "V3": {"status": v3_status, "ok": b_ok, "total": b_n, "speed_ratio": speed_ratio,
               "action": "" if not v3_status.startswith("FAIL") else "clamp ломает передачу, править обработчик"},
        "valid_for_verdict": v1_pass and v2_status != "FAIL" and not v3_status.startswith("FAIL"),
    }


def verdict_network(cell_c_ok: int, cell_d_ok: int, *, total: int = 20) -> str:
    """Compute Section 7.2 network verdict from Cell C and Cell D success counts."""
    if total <= 0:
        raise ValueError("total must be positive")
    lo = _threshold_2(total)
    hi = _threshold_18(total)
    if cell_c_ok <= lo and cell_d_ok >= hi:
        return "РАБОТАЕТ"
    if cell_c_ok <= lo and cell_d_ok <= lo:
        return "НЕ РАБОТАЕТ: ТСПУ собирает поток"
    if cell_c_ok <= lo:
        return "НЕСТАБИЛЬНО: повторить, до 90% считается как «не работает»"
    if cell_c_ok >= hi and cell_d_ok >= hi:
        return "ФИЛЬТРА НА УЧАСТКЕ НЕТ: клиент → RU VPS чист, clamp не нужен"
    if lo < cell_c_ok < hi:
        return "ФИЛЬТР ПЛАВАЮЩИЙ: повторить в другое время"
    return "ДЕГРАДАЦИЯ ПРИ CLAMP: без clamp проходит, с clamp падает"


def is_positive_network_verdict(verdict: str) -> bool:
    return verdict == "РАБОТАЕТ" or verdict.startswith("ФИЛЬТРА НА УЧАСТКЕ НЕТ")


def network_repeatability_verdict(run_verdicts: list[str]) -> str:
    """Section 7.2: 6 runs across 2 days; verdict holds if >= 5 of 6 are positive."""
    positives = sum(1 for v in run_verdicts if is_positive_network_verdict(v))
    if len(run_verdicts) >= 6 and positives >= 5:
        return "УСТОЙЧИВО РАБОТАЕТ"
    if len(run_verdicts) >= 6:
        return f"НЕУСТОЙЧИВО ({positives}/{len(run_verdicts)} положительных)"
    return f"НЕДОСТАТОЧНО ПРОГОНОВ ({len(run_verdicts)}/6, положительных {positives})"


def overall_verdict(network_results: list[dict[str, str]]) -> str:
    """Compute Section 7.3 overall verdict across >=3 networks."""
    positives = [n for n in network_results if is_positive_network_verdict(n["verdict"])]
    has_mobile = any(n.get("network_type") == "mobile" for n in positives)
    if len(positives) >= 2 and has_mobile:
        return "СПОСОБ РАБОЧИЙ: переходить к разделам 8–10"
    if len(positives) >= 1:
        return "НЕОБЯЗАТЕЛЬНЫЙ ПРОФИЛЬ: допустимо только как профиль, не как основное решение"
    return "ЧИСТО СЕРВЕРНОГО РЕШЕНИЯ НЕТ: переход к разделу 12"


def evaluate_stage2(
    *,
    instagram_ok: int,
    instagram_total: int,
    cdn_speed_bps: float,
    de_baseline_bps: float,
    zero_bytes_200_count: int,
    total_200_count: int,
    wg_max_packet_bytes: int,
) -> dict[str, object]:
    """Evaluate Section 8 end-to-end chain criteria."""
    speed_ratio = (cdn_speed_bps / de_baseline_bps) if de_baseline_bps > 0 else 0.0
    pmtu_zero_ratio = (zero_bytes_200_count / total_200_count) if total_200_count > 0 else 0.0
    checks = {
        "http_20_of_20": instagram_total > 0 and instagram_ok == instagram_total,
        "cdn_speed_ge_70pct": speed_ratio >= 0.70,
        "sni_log_zero_bytes_le_1pct": pmtu_zero_ratio <= 0.01,
        "wg0_mtu_le_1360": wg_max_packet_bytes <= 1360,
    }
    return {
        "pass": all(checks.values()),
        "checks": checks,
        "speed_ratio": speed_ratio,
        "pmtu_zero_ratio": pmtu_zero_ratio,
    }


def evaluate_rows(
    rows: list[dict[str, str]],
    *,
    speed_a_bps: float | None = None,
    speed_b_bps: float | None = None,
    evidence: dict | None = None,
) -> dict[str, object]:
    """Compute full validity + Section 7.2 verdict summary from CSV rows."""
    if evidence is not None:
        rows = attach_evidence_to_rows(rows, evidence)
    validity = evaluate_validity(rows, speed_a_bps=speed_a_bps, speed_b_bps=speed_b_bps, evidence=evidence)
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        cell = row["ячейка"]
        entry = counts.setdefault(cell, {"ok": 0, "total": 0})
        entry["total"] += 1
        if row.get("результат") == "УСПЕХ":
            entry["ok"] += 1
    c_stats = counts.get("C", {"ok": 0, "total": 0})
    d_stats = counts.get("D", {"ok": 0, "total": 0})
    net_verdict = (
        verdict_network(c_stats["ok"], d_stats["ok"], total=max(c_stats["total"], d_stats["total"], 1))
        if c_stats["total"] and d_stats["total"]
        else "НЕПОЛНЫЙ ПРОГОН (нужны ячейки C и D)"
    )
    ip_punished = any("ip_punish_check=FAIL" in r.get("комментарий", "") for r in rows)
    return {
        "counts": counts,
        "validity": validity,
        "network_verdict": net_verdict,
        "ip_punishment_observed": ip_punished,
    }


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_HEADER)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in CSV_HEADER})


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def run_experiment(args: argparse.Namespace) -> int:
    cells = tuple(args.cells)
    schedule = build_schedule(
        cells=cells,
        attempts=args.attempts,
        control_sni=args.control_sni,
        interleave=args.interleave,
        sequential_blocks=getattr(args, "sequential_blocks", False),
    )
    rows: list[dict[str, str]] = []
    for idx, item in enumerate(schedule):
        ts = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        res = probe_curl(item.sni, edge_ip=args.edge_ip, timeout=args.timeout)
        comment = str(res["comment"])
        if item.cell == "C" and not res["ok"] and not args.skip_punish_check:
            punish = probe_curl(args.control_sni, edge_ip=args.edge_ip, timeout=min(10, args.timeout))
            tag = "ip_punish_check=PASS" if punish["ok"] else f"ip_punish_check=FAIL(http={punish['http']})"
            comment = f"{comment}; {tag}".strip("; ")
        rows.append({
            "run_id": args.run_id,
            "дата_время": ts,
            "оператор": args.operator,
            "тип_сети": args.network_type,
            "внешний_IP": args.client_ip,
            "ячейка": item.cell,
            "попытка": str(item.attempt),
            "SNI": item.sni,
            "clamp": item.clamp,
            "результат": "УСПЕХ" if res["ok"] else "СБОЙ",
            "http": str(res["http"]),
            "time_connect": str(res["time_connect"]),
            "time_appconnect": str(res["time_appconnect"]),
            "длина_первого_сегмента": "",
            "комментарий": comment,
        })
        if idx + 1 < len(schedule) and args.pause > 0:
            time.sleep(args.pause)

    evidence = json.loads(Path(args.evidence_json).read_text(encoding="utf-8")) if args.evidence_json else None
    if evidence is not None:
        rows = attach_evidence_to_rows(rows, evidence)
    summary = evaluate_rows(rows, evidence=evidence)
    if args.out_csv:
        write_csv(Path(args.out_csv), rows)
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return 0


def generate_termux_script(args: argparse.Namespace) -> str:
    """Return a standalone POSIX/bash script for Termux requiring only curl."""
    control = shlex.quote(args.control_sni)
    edge = shlex.quote(args.edge_ip)
    run_id = shlex.quote(args.run_id)
    operator = shlex.quote(args.operator)
    net_type = shlex.quote(args.network_type)
    attempts = int(args.attempts)
    pause = int(args.pause)
    return f"""#!/usr/bin/env bash
set -u
RUN_ID={run_id}
OPERATOR={operator}
NET_TYPE={net_type}
CONTROL_SNI={control}
EDGE_IP={edge}
ATTEMPTS={attempts}
PAUSE_S={pause}
PHASE="${{1:-all}}"
OUT_CSV="${{2:-mneby_tz_${{RUN_ID}}_${{PHASE}}.csv}}"

CLIENT_IP="$(curl -sS --max-time 6 https://api.ipify.org || echo unknown)"
echo "External IP: $CLIENT_IP (verify matches allowed RU canary peer)" >&2

if [ ! -f "$OUT_CSV" ]; then
  echo 'run_id,дата_время,оператор,тип_сети,внешний_IP,ячейка,попытка,SNI,clamp,результат,http,time_connect,time_appconnect,длина_первого_сегмента,комментарий' > "$OUT_CSV"
fi

run_one() {{
  local cell="$1" sni="$2" clamp="$3" i="$4"
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  out="$(curl -sS -o /dev/null -w '%{{http_code}} %{{time_connect}} %{{time_appconnect}}' --max-time 10 --resolve "$sni:443:$EDGE_IP" "https://$sni/" 2>/dev/null || echo '000 0 0')"
  read -r code tc ta <<< "$out"
  res="СБОЙ"
  if [ "${{code:-0}}" -ge 200 ] 2>/dev/null && [ "${{code:-0}}" -le 499 ] 2>/dev/null; then
    res="УСПЕХ"
  fi
  comment=""
  if [ "$cell" = "C" ] && [ "$res" = "СБОЙ" ]; then
    p_out="$(curl -sS -o /dev/null -w '%{{http_code}}' --max-time 8 --resolve "$CONTROL_SNI:443:$EDGE_IP" "https://$CONTROL_SNI/" 2>/dev/null || echo '000')"
    if [ "${{p_out:-0}}" -ge 200 ] 2>/dev/null && [ "${{p_out:-0}}" -le 499 ] 2>/dev/null; then
      comment="ip_punish_check=PASS"
    else
      comment="ip_punish_check=FAIL(http=${{p_out:-0}})"
    fi
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,,%s\\n' \\
    "$RUN_ID" "$ts" "$OPERATOR" "$NET_TYPE" "$CLIENT_IP" "$cell" "$i" "$sni" "$clamp" "$res" "${{code:-0}}" "${{tc:-0}}" "${{ta:-0}}" "$comment" >> "$OUT_CSV"
  printf '[%s %2d/%d] %s -> %s http=%s tc=%s ta=%s %s\\n' "$cell" "$i" "$ATTEMPTS" "$sni" "$res" "${{code:-0}}" "${{tc:-0}}" "${{ta:-0}}" "$comment"
  sleep "$PAUSE_S"
}}

if [ "$PHASE" = "unclamped" ] || [ "$PHASE" = "all" ]; then
  for i in $(seq 1 "$ATTEMPTS"); do
    run_one A "$CONTROL_SNI" "выкл" "$i"
    run_one C "i.instagram.com" "выкл" "$i"
  done
fi
if [ "$PHASE" = "all" ]; then
  echo "=== Фаза unclamped (A, C) завершена. Дождитесь meta_v30_clamp_phase=ON_FOR_CELLS_B_D_E на сервере ===" >&2
  if [ -t 0 ]; then
    printf 'Нажмите Enter для запуска фазы clamped (B, D, E)... ' >&2
    read -r _
  fi
fi
if [ "$PHASE" = "clamped" ] || [ "$PHASE" = "all" ]; then
  for i in $(seq 1 "$ATTEMPTS"); do
    run_one B "$CONTROL_SNI" "вкл" "$i"
    run_one D "i.instagram.com" "вкл" "$i"
    run_one E "graph.instagram.com" "вкл" "$i"
  done
fi
echo "Saved CSV: $OUT_CSV"
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run synthetic curl cells locally/in Termux")
    p_run.add_argument("--run-id", required=True)
    p_run.add_argument("--operator", required=True)
    p_run.add_argument("--network-type", choices=("mobile", "wifi"), required=True)
    p_run.add_argument("--client-ip", default="unknown")
    p_run.add_argument("--edge-ip", default=RU_EDGE)
    p_run.add_argument("--control-sni", default=DEFAULT_CONTROL_SNI)
    p_run.add_argument("--cells", nargs="+", default=list(DEFAULT_CELL_ORDER))
    p_run.add_argument("--attempts", type=int, default=20)
    p_run.add_argument("--pause", type=float, default=5.0)
    p_run.add_argument("--timeout", type=int, default=10)
    p_run.add_argument("--interleave", action="store_true")
    p_run.add_argument("--sequential-blocks", action="store_true")
    p_run.add_argument("--skip-punish-check", action="store_true")
    p_run.add_argument("--evidence-json")
    p_run.add_argument("--out-csv")
    p_run.add_argument("--out-json")

    p_eval = sub.add_parser("evaluate", help="Evaluate CSV + optional phone-sni.json")
    p_eval.add_argument("--csv", required=True)
    p_eval.add_argument("--evidence-json")
    p_eval.add_argument("--speed-a-bps", type=float)
    p_eval.add_argument("--speed-b-bps", type=float)
    p_eval.add_argument("--out-csv")

    p_termux = sub.add_parser("generate-termux-script", help="Print standalone Termux bash script")
    p_termux.add_argument("--run-id", default="run1")
    p_termux.add_argument("--operator", default="unknown")
    p_termux.add_argument("--network-type", choices=("mobile", "wifi"), default="mobile")
    p_termux.add_argument("--edge-ip", default=RU_EDGE)
    p_termux.add_argument("--control-sni", default=DEFAULT_CONTROL_SNI)
    p_termux.add_argument("--attempts", type=int, default=20)
    p_termux.add_argument("--pause", type=int, default=5)
    p_termux.add_argument("--out")

    p_overall = sub.add_parser("overall", help="Evaluate Section 7.3 verdict across network JSONs")
    p_overall.add_argument("--network", action="append", nargs=2, metavar=("TYPE", "VERDICT"), required=True)

    p_stage2 = sub.add_parser("stage2", help="Evaluate Section 8 end-to-end chain criteria")
    p_stage2.add_argument("--instagram-ok", type=int, required=True)
    p_stage2.add_argument("--instagram-total", type=int, default=20)
    p_stage2.add_argument("--cdn-speed-bps", type=float, required=True)
    p_stage2.add_argument("--de-baseline-bps", type=float, required=True)
    p_stage2.add_argument("--zero-bytes-200", type=int, required=True)
    p_stage2.add_argument("--total-200", type=int, required=True)
    p_stage2.add_argument("--wg-max-packet", type=int, required=True)

    args = parser.parse_args(argv)
    if args.command == "run":
        return run_experiment(args)
    if args.command == "evaluate":
        rows = read_csv(Path(args.csv))
        evidence = json.loads(Path(args.evidence_json).read_text(encoding="utf-8")) if args.evidence_json else None
        if evidence is not None:
            rows = attach_evidence_to_rows(rows, evidence)
            if args.out_csv:
                write_csv(Path(args.out_csv), rows)
        summary = evaluate_rows(
            rows,
            speed_a_bps=args.speed_a_bps,
            speed_b_bps=args.speed_b_bps,
            evidence=evidence,
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
        return 0
    if args.command == "generate-termux-script":
        script = generate_termux_script(args)
        if args.out:
            out_path = Path(args.out)
            out_path.write_text(script, encoding="utf-8")
            out_path.chmod(0o755)
        else:
            print(script, end="")
        return 0
    if args.command == "overall":
        items = [{"network_type": t, "verdict": v} for t, v in args.network]
        print(overall_verdict(items), flush=True)
        return 0
    if args.command == "stage2":
        res = evaluate_stage2(
            instagram_ok=args.instagram_ok,
            instagram_total=args.instagram_total,
            cdn_speed_bps=args.cdn_speed_bps,
            de_baseline_bps=args.de_baseline_bps,
            zero_bytes_200_count=args.zero_bytes_200,
            total_200_count=args.total_200,
            wg_max_packet_bytes=args.wg_max_packet,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2), flush=True)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
