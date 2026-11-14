#!/usr/bin/env python3
"""Deterministic one-block, fail-closed change for the existing CoreDNS DoT relay.

Never changes an exact SmartDNS hostname or a TLS/SNI route. The currently
deployed forward stanza must match byte-for-byte. A changed baseline aborts.
"""
from __future__ import annotations
import argparse
import pathlib

OLD = (
    "    cache 30\n"
    "    forward . tls://9.9.9.9 {\n"
    "        tls_servername dns.quad9.net\n"
    "        health_check 5s\n"
    "        max_concurrent 16\n"
    "        max_connect_attempts 2\n"
    "    }\n"
)
NEW = (
    "    cache 30 {\n"
    "        servfail 0\n"
    "    }\n"
    "    reload 5s 1s\n"
    "    forward . tls://9.9.9.9 tls://149.112.112.112 {\n"
    "        tls_servername dns.quad9.net\n"
    "        policy sequential\n"
    "        health_check 5s\n"
    "        max_concurrent 64\n"
    "        max_connect_attempts 4\n"
    "        failover SERVFAIL REFUSED\n"
    "    }\n"
)


def render(source: str) -> str:
    if source.count(NEW) == 1 and OLD not in source:
        return source
    if source.count(OLD) != 1 or source.count("    forward . ") != 1:
        raise ValueError("Unrecognized or ambiguous production CoreDNS baseline")
    if "    reload " in source or "    servfail " in source:
        raise ValueError("Unexpected pre-existing resilience controls")
    result = source.replace(OLD, NEW, 1)
    if result.replace(NEW, OLD, 1) != source:
        raise AssertionError("Non-additive or destructive change")
    return result


def self_test() -> None:
    base = (
        "tls://.:853 {\n"
        "    bind 89.125.90.101\n"
        "    template IN A claude.ai {\n"
        "        match ^claude[.]ai[.]$\n"
        '        answer "{{ .Name }} 20 IN A 89.125.90.101"\n'
        "    }\n" + OLD + "}\n"
    )
    out = render(base)
    assert render(out) == out
    assert out.replace(NEW, OLD, 1) == base
    assert out.count("reload 5s 1s") == 1
    assert out.count("failover SERVFAIL REFUSED") == 1
    assert "template IN A claude.ai" in out
    try:
        render(base.replace("9.9.9.9", "1.1.1.1"))
    except ValueError:
        pass
    else:
        raise AssertionError("Unknown baseline was silently modified")
    print("mnebydns_resilience_strict_render=PASS", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("self-test", "render", "verify"))
    parser.add_argument("--input")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return
    if not args.input:
        parser.error("--input is required")
    path = pathlib.Path(args.input)
    original = path.read_text()
    new = render(original)
    if args.command == "verify":
        if original != new or NEW not in original:
            raise SystemExit("MNEBYDNS_RESILIENCE_NOT_YET_APPLIED")
        print("mnebydns_resilience_config_verified=PASS", flush=True)
        return
    if not args.output:
        parser.error("--output is required")
    pathlib.Path(args.output).write_text(new)
    print("mnebydns_resilience_candidate_rendered=PASS", flush=True)


if __name__ == "__main__":
    main()
