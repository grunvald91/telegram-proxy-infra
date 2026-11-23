#!/usr/bin/env python3
"""Validate one-shot, nonpublishing fleet operations from reviewed Git commits."""
from __future__ import annotations
import json
from pathlib import Path
import re
import sys
from fleet_plan import inventory

OPERATIONS = re.compile(r"nodekit/fleet-operations/([a-z]{2})-telemt-stage-([0-9]{8})\.json\Z")
FIELDS = {
    "schema_version", "operation", "country_code", "node_id",
    "advertise_host", "ssh_ipv4", "approved", "subscriber_publication_allowed",
}
class OperationError(ValueError):
    pass

def plan(path: str, root: Path) -> tuple[str,str]:
    match = OPERATIONS.fullmatch(path)
    if not match:
        raise OperationError("Unapproved fleet operation path")
    country = match.group(1)
    source = root / path
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 4096:
        raise OperationError("Missing, symlinked or oversized operation")
    op = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(op, dict) or set(op) != FIELDS:
        raise OperationError("Unexpected operation contract fields")
    if (type(op["schema_version"]) is not int or op["schema_version"] != 1
            or op["operation"] != "stage_telemt"
            or op["country_code"] != country.upper()
            or op["approved"] is not True
            or op["subscriber_publication_allowed"] is not False):
        raise OperationError("Unapproved or publishing operation")
    existing, _ = inventory(root / "nodekit" / "fleet", country)
    for field in ("country_code", "node_id", "advertise_host", "ssh_ipv4"):
        if op[field] != existing[field]:
            raise OperationError("Fleet identity or target differs from approved inventory")
    if existing["status"] not in ("testing", "approved"):
        raise OperationError("Cannot stage on unapproved fleet node")
    return country, "telemt-stage"

def select(paths: list[str], root: Path) -> list[tuple[str,str]]:
    if len(paths) > 8:
        raise OperationError("Too many changed fleet operation files")
    out = []
    for path in paths:
        out.append(plan(path, root))
    if len(out) != len(set(out)):
        raise OperationError("Duplicate country and operation in same push")
    return sorted(out)

if __name__ == "__main__":
    try:
        pairs = select(sys.argv[1:], Path.cwd())
        print(json.dumps({"selected": pairs}))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print("NODEKIT_OPERATION_INVALID=" + type(error).__name__, file=sys.stderr)
        raise SystemExit(2)
