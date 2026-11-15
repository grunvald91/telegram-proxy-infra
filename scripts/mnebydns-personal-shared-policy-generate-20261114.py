#!/usr/bin/env python3
"""Safely derive personalized premium policy from the live common DE CoreDNS.

Inputs are read-only snapshots exported by GitHub Actions, no secrets.
Accept at least 264 mapped CoreDNS A templates and 2 anchored domain families;
never allow a broad/unreviewed regex to expand a subscriber's paid routing.
The old personal policy is a regression fixture only, never an independent source.\nOutput immutable sorted JSON plus SHA.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

DOMAIN = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+\Z")
POLICY = re.compile(r"(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+\Z")
TEMPLATE = re.compile(r"(?ms)^\s*template\s+IN\s+A\s+(\S+)\s*\{(.*?)^\s*\}")
MATCH = re.compile(r"(?m)^\s*match\s+(.+)$")
ANSWER = re.compile(r'(?m)^\s*answer\s+"\{\{ \.Name \}\}\s+\d+\s+IN\s+A\s+([0-9.]+)"')

# The approved anchored family format accepted by the existing CoreDNS 2026-11-14
FAMILY_START = "(?i)^(?:[a-z0-9-]+[.])*(?:"
FAMILY_END = ")[.]$"


def decode_family(raw: str) -> list[str]:
    if not (raw.startswith(FAMILY_START) and raw.endswith(FAMILY_END)):
        raise ValueError("Unsafe/noncanonical CoreDNS family regexp")
    items = raw[len(FAMILY_START) : -len(FAMILY_END)].split("|")
    if not items:
        raise ValueError("Empty CoreDNS family regexp")
    roots = [n.replace(r"\.", ".").replace(r"\-", "-") for n in items]
    if len(roots) != len(set(roots)) or any(not DOMAIN.fullmatch(x) for x in roots):
        raise ValueError("Invalid/duplicate CoreDNS family roots")
    regex = re.compile(raw)
    for root in roots:
        for sample in (root + ".", "www." + root + ".", "r1---sn-test." + root + "."):
            if regex.fullmatch(sample) is None:
                raise ValueError("CoreDNS family sample does not match " + sample)
    return roots


def parse(core: str) -> tuple[set[str], set[str]]:
    blocks = TEMPLATE.findall(core)
    if len(blocks) < 264:
        raise ValueError("Unexpected CoreDNS A template count " + str(len(blocks)))
    exact: set[str] = set()
    groups: list[list[str]] = []
    for header, block in blocks:
        match = MATCH.findall(block)
        answer = ANSWER.findall(block)
        if len(match) != 1 or len(answer) != 1:
            raise ValueError("Unreviewed CoreDNS template structure " + header)
        if answer[0] != "89.125.90.101":
            raise ValueError("CoreDNS is not fully routed through DE89")
        expression = match[0]
        compiled = re.compile(expression)
        if header != ".":
            if not DOMAIN.fullmatch(header) or compiled.fullmatch(header + ".") is None:
                raise ValueError("Bad exact CoreDNS rule " + header)
            exact.add(header)
            continue
        simple = (
            expression.removeprefix("(?i)")
            .strip("^$")
            .replace("[.]", ".")
            .replace(r"\-", "-")
            .rstrip(".")
        )
        if DOMAIN.fullmatch(simple):
            if compiled.fullmatch(simple + ".") is None:
                raise ValueError("Bad generic CoreDNS exact match")
            exact.add(simple)
        else:
            groups.append(decode_family(expression))
    if len(exact) < 262 or len(groups) != 2 or sum(map(len, groups)) != 75:
        raise ValueError(
            f"CoreDNS exact/family drift {len(exact)} / {list(map(len, groups))}"
        )
    roots = set().union(*groups)
    if len(roots) != 75:
        raise ValueError("Shared CoreDNS family root collision")
    return exact, roots


def classify(policy: set[str], hostname: str) -> bool:
    return hostname in policy or any(
        hostname.endswith("." + n[2:]) for n in policy if n.startswith("*.")
    )


def generate(core_path: Path, old_path: Path, output: Path) -> dict:
    old = json.loads(old_path.read_text())
    if (
        not isinstance(old, list)
        or len(old) != 158
        or len(set(old)) != 158
        or any(not isinstance(s, str) or POLICY.fullmatch(s) is None for s in old)
    ):
        raise ValueError("Existing personal policy drifted from 158 approved entries")
    assert "*.chatgpt.com" in old and "auth.openai.com" in old
    core = core_path.read_text()
    exact, roots = parse(core)
    # Do not union with the old personal list: that would perpetuate a second
    # independent domain source and could retain stale paid routes forever.
    new = exact | roots | {"*." + root for root in roots}
    missing_old = sorted(s for s in exact if not classify(set(old), s))
    # No pre-existing personal-only domain may silently disappear. A wildcard
    # from old must still exist as a wildcard in the derived shared policy.
    unsupported_old = sorted(
        s for s in old
        if (s not in new if s.startswith("*.") else not classify(new, s))
    )
    if unsupported_old:
        raise ValueError("Old personal rules not backed by shared CoreDNS: " +
                         repr(unsupported_old[:30]))
    if any(not POLICY.fullmatch(s) for s in new):
        raise ValueError("Malformed generated personal rules")
    if len(missing_old) < 111:
        raise ValueError("Unexpected missing exact rule count " + str(len(missing_old)))
    samples = set(exact) | roots
    for root in roots:
        samples.add("www." + root)
        samples.add("r1---sn-test." + root)
    mismatches = sorted(s for s in samples if not classify(new, s))
    if mismatches:
        raise ValueError("Generated personal policy cannot cover common CoreDNS " + repr(mismatches[:5]))
    # Keep harmless control domains out of the billable mapped policy.
    if classify(new, "example.org") or classify(new, "api.telegram.org"):
        raise ValueError("Unrelated domain accidentally classified premium")
    output.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(sorted(new), separators=(",", ":"), ensure_ascii=True) + "\n"
    output.write_text(serialized)
    digest = hashlib.sha256(serialized.encode("utf8")).hexdigest()
    manifest = {
        "original_policy_count": len(old),
        "new_policy_count": len(new),
        "added_entries": len(new) - len(old),
        "core_a_templates": len(exact) + len(groups),
        "core_exact_domains": len(exact),
        "core_family_roots": len(roots),
        "previous_unmapped_exact": len(missing_old),
        "obsolete_personal_only_entries": len(unsupported_old),
        "covered_samples": len(samples),
        "sha256": digest,
    }
    (output.parent / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: generator.py <live-DE-Corefile> <live-RU-policy> <output.json>")
    result = generate(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
    for name, value in result.items():
        print("POLICY_SYNC_" + name.upper() + "=" + str(value), flush=True)
    print("POLICY_SYNC_BUILD_AND_FULL_PARITY=PASS")
