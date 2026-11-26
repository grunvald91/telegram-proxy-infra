#!/usr/bin/env python3
"""Build the opt-in pilot bundle beside the installed country runtime."""

from pathlib import Path
import py_compile
import sys

from fi_country_build import build as build_country, once


def build(source: Path, destination: Path):
    build_country(source, destination)
    pilot = destination / "fi_dns_pilot.py"
    pilot.write_bytes((source / pilot.name).read_bytes())
    pilot.chmod(0o600)

    routed = destination / "fi_routed_runtime.py"
    text = once(routed.read_text(), "STATE=FI_ROOT", "from fi_dns_pilot import PilotAuthorizer, PilotGrant\n\nSTATE=FI_ROOT")
    text = once(
        text,
        '# Separate later public release required. Fail closed even if another\n'
        '    # operator accidentally enables the controller gate while still staging.\n'
        '    require(policy["grants"]==[],"private_stage_requires_empty_grants")',
        '# Admit at most the single locally approved digest after signature verification.\n'
        '    require(PilotGrant().accepts_snapshot(policy["grants"]),"unapproved_pilot_grant")',
    )
    text = once(
        text,
        "authorizer=SignedFiGrantAuthorizer(CONTROLLER_PIN)",
        "authorizer=PilotAuthorizer(SignedFiGrantAuthorizer(CONTROLLER_PIN),PilotGrant())",
    )
    routed.write_text(text)

    metered = destination / "fi_dns_metered_dot.py"
    text = once(
        metered.read_text(),
        "        valid_answer(query, result)\n        settled",
        "        valid_answer(query, result)\n"
        "        if await asyncio.wait_for(authorizer.allowed(hostname), timeout=METER_TIMEOUT_SECONDS) is not True:\n"
        '            raise MeteredDnsError("FI DNS pilot revoked before settlement")\n'
        "        settled",
    )
    text = once(
        text,
        "        return result\n    finally:",
        "        if await asyncio.wait_for(authorizer.allowed(hostname), timeout=METER_TIMEOUT_SECONDS) is not True:\n"
        '            raise MeteredDnsError("FI DNS pilot revoked before reply")\n'
        "        return result\n    finally:",
    )
    metered.write_text(text)
    for file in (pilot, routed, metered):
        py_compile.compile(str(file), doraise=True)


if __name__ == "__main__":
    build(Path(sys.argv[1]), Path(sys.argv[2]))
