#!/usr/bin/env python3
"""Build a release-gated FI runtime beside the installed pilot runtime."""

from pathlib import Path
import py_compile
import sys

from fi_country_build import build as build_country, once


def build(source: Path, destination: Path):
    build_country(source, destination)
    policy = destination / "fi_dns_customer_policy.py"
    policy.write_bytes((source / policy.name).read_bytes())
    policy.chmod(0o600)
    routed = destination / "fi_routed_runtime.py"
    text = once(
        routed.read_text(),
        "STATE=FI_ROOT",
        "from fi_dns_customer_policy import CustomerAuthorizer, chargeable_questions, customer_enabled\n\nSTATE=FI_ROOT",
    )
    text = once(
        text,
        'require(policy["grants"]==[],"private_stage_requires_empty_grants")',
        'require(not policy["grants"] or customer_enabled(),"customer_release_closed")',
    )
    text = once(
        text,
        "authorizer=SignedFiGrantAuthorizer(CONTROLLER_PIN)",
        "authorizer=CustomerAuthorizer(SignedFiGrantAuthorizer(CONTROLLER_PIN))",
    )
    text = once(
        text,
        "resolver=LoopbackTlsResolver(HOSTS[0]))",
        "resolver=LoopbackTlsResolver(HOSTS[0]),chargeable=chargeable_questions(policy))",
    )
    routed.write_text(text)
    for file in (policy, routed):
        py_compile.compile(str(file), doraise=True)


if __name__ == "__main__":
    build(Path(sys.argv[1]), Path(sys.argv[2]))
