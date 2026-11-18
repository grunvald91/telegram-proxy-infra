#!/usr/bin/env python3
"""Read-only service release readiness for a reviewed FI Nodekit VPS.

Staged binaries, a successful CI job, and a valid certificate do not by
themselves authorize personal DNS, a public SNI proxy, or VPN clients.
This module deliberately has NO release or service-start operation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from awg_controller_readiness import inspect as awg_controller_inspect
from awg_controller_readiness import HOST_REVIEWED, NODE_REVIEWED
from install_components import node_ready, safe_manifest, safe_dir
from awg_peer_grants import protected_file

ROOT = Path("/var/lib/mnebyvpn-nodekit")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")


class ServiceReadinessError(ValueError):
    pass


def checked_file(path: Path, expected_digest: str) -> None:
    if not isinstance(expected_digest, str) or not SHA256.fullmatch(expected_digest):
        raise ServiceReadinessError("Invalid staged component digest")
    data = protected_file(path, max_bytes=50000)
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ServiceReadinessError("Staged DNS/proxy config integrity mismatch")


def dns_proxy_stage(node: Path) -> dict:
    """Verify the immutable candidate, not a public listener or subscription."""
    stage_dir = node / "dns-proxy"
    if not stage_dir.exists() and not stage_dir.is_symlink():
        return {"staged": False, "route_count": 0, "personal_access_verified": False,
                "external_e2e_verified": False, "ready": False,
                "blockers": ["dns_proxy_stage_missing"]}
    safe_dir(stage_dir)
    meta = safe_manifest(stage_dir / "manifest.json")
    if (meta.get("node_id") != node.name or meta.get("state") != "staged" or
            meta.get("activation_enabled") is not False or
            meta.get("personal_dns_enabled") is not False or
            meta.get("open_proxy_enabled") is not False or
            meta.get("open_resolver_enabled") is not False or
            meta.get("external_e2e_verified") is not False or
            not isinstance(meta.get("route_count"), int) or
            isinstance(meta.get("route_count"), bool) or
            not 0 <= meta["route_count"] <= 200 or
            not isinstance(meta.get("config_sha256"), dict) or
            set(meta["config_sha256"]) != {"Corefile", "nginx.conf"}):
        raise ServiceReadinessError("DNS/proxy candidate has unsafe or changed state")
    checked_file(stage_dir / "Corefile", meta["config_sha256"]["Corefile"])
    checked_file(stage_dir / "nginx.conf", meta["config_sha256"]["nginx.conf"])
    # Candidate is explicitly not a signed, subscription-bound production policy.
    return {"staged": True, "route_count": meta["route_count"],
            "personal_access_verified": False, "external_e2e_verified": False,
            "ready": False,
            "blockers": ["personal_dns_authorization_missing",
                         "signed_proxy_policy_missing",
                         "independent_client_e2e_missing"]}


def tls_stage(node: Path, host: str) -> dict:
    """Inspect staged TLS metadata; NOT wildcard coverage or external CA trust."""
    tls = node / "tls"
    if not tls.exists() and not tls.is_symlink():
        return {"staged": False, "personal_fqdn_tls_verified": False,
                "blockers": ["tls_stage_missing"]}
    safe_dir(tls)
    meta = safe_manifest(tls / "manifest.json")
    if (meta.get("node_id") != node.name or meta.get("hostname") != host or
            meta.get("state") != "certificate_staged" or
            meta.get("activation_enabled") is not False or
            meta.get("personal_dns_enabled") is not False or
            meta.get("published") is not False or
            not isinstance(meta.get("certificate_sha256"), str) or
            not SHA256.fullmatch(meta["certificate_sha256"])):
        raise ServiceReadinessError("Unapproved staged TLS state")
    # A certificate for fi.mnebyvpn.site does not prove TLS for every
    # <token>.dns.mnebyvpn.site personal Android Private DNS hostname.
    checked_file(tls / "fullchain.pem", meta["certificate_sha256"])
    protected_file(tls / "privkey.pem", max_bytes=50000)
    return {"staged": True, "personal_fqdn_tls_verified": False,
            "blockers": ["personal_dns_wildcard_and_external_tls_e2e_missing"]}


def assess(node: Path, host: str, identity_sha: str, controller_sha: str = "") -> dict:
    if os.geteuid() != 0 or node.name != NODE_REVIEWED or host != HOST_REVIEWED:
        raise ServiceReadinessError("Only reviewed, isolated FI Nodekit supported")
    if not isinstance(identity_sha, str) or not SHA256.fullmatch(identity_sha):
        raise ServiceReadinessError("Independent node public-key pin is required")

    manifest = safe_manifest(node / "manifest.json")
    if (manifest.get("node_id") != node.name or
            manifest.get("advertise_host") != host or
            manifest.get("activation_enabled") is not False or
            manifest.get("registration_enabled") is not False):
        raise ServiceReadinessError("Release audit target differs from reviewed stage")

    identity = protected_file(node / "identity" / "node-public.spki", max_bytes=100)
    if (len(identity) != 44 or
            not identity.startswith(bytes.fromhex("302a300506032b6570032100")) or
            hashlib.sha256(identity).hexdigest() != identity_sha):
        raise ServiceReadinessError("Node Ed25519 identity pin mismatch")

    candidate = dns_proxy_stage(node)
    tls = tls_stage(node, host)
    awg = awg_controller_inspect(node, host, identity_sha, controller_sha)

    # AWG readiness is a controller enrollment *candidate*, not a release.
    enroll_candidate = bool(awg["control_plane_prerequisites_met"])
    result = {
        "schema_version": 1,
        "node_id": node.name,
        "hostname": host,
        "node_identity_pinned": True,
        "controller_enrollment_candidate": enroll_candidate,
        "controller_enrollment_verified": False,  # must query trusted DB
        "services": {
            "personal_dns": {
                "local_candidate_verified": candidate["staged"] and tls["staged"],
                "personal_fqdn_tls_verified": tls["personal_fqdn_tls_verified"],
                "entitlement_enforcement_verified": False,
                "independent_external_e2e_verified": False,
                "ready": False,
                "blockers": list(candidate["blockers"]) + list(tls["blockers"]),
            },
            "sni_proxy": {
                "local_candidate_verified": candidate["staged"],
                "route_count": candidate["route_count"],
                "signed_policy_verified": False,
                "independent_external_e2e_verified": False,
                "ready": False,
                "blockers": ["signed_proxy_policy_missing",
                             "external_sni_allow_and_deny_tests_missing"],
            },
            "amneziawg": {
                "local_stage_integrity_verified": True,
                "watchdog_staged": awg["watchdog_unit_installed"],
                "egress_staged": awg["egress_unit_installed"],
                "controller_key_independently_pinned": awg[
                    "controller_public_key_independently_pinned"],
                "external_transport_canary_verified_in_this_audit": False,
                "signed_grant_expiry_revoke_e2e_verified": False,
                "mobile_client_e2e_verified": False,
                "ready": False,
                "blockers": ["controller_enrollment_and_signed_grant_e2e_missing",
                             "independent_mobile_and_expiry_e2e_missing"],
            },
        },
        "automatic_publication_authorized": False,
        "existing_clients_changed": False,
        "note": "Staging checks are not authorization; independent trusted controller E2E and explicit release are required.",
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--expected-identity-sha256", required=True)
    parser.add_argument("--expected-controller-sha256", default="")
    parser.add_argument("--stage-root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        node = node_ready(args.stage_root, args.node_id)
        report = assess(node, args.host, args.expected_identity_sha256,
                        args.expected_controller_sha256)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print("NODEKIT_SERVICE_READINESS_ERROR=" + type(exc).__name__,
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
