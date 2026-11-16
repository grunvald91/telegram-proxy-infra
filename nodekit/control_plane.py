#!/usr/bin/env python3
"""MNEBYVPN central operations contracts (offline by default).

This module is safe to import from the control plane. It does not create VPS,
touch the existing 89/188 servers, restart services, or publish subscriptions.
Publication requires a separate authenticated control-plane integration.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import ipaddress
import json
import re
from typing import Any
from urllib.parse import parse_qs, quote, urlparse
import uuid

NODE_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,39}\Z")
COUNTRY = re.compile(r"[A-Z]{2}\Z")
HEX_SHA = re.compile(r"[a-f0-9]{64}\Z")
ALLOWED_SERVICES = frozenset({"dns", "vpn", "sni-proxy", "tunnel"})
STATES = frozenset({"planned", "testing", "canary", "verified",
                    "enabled", "degraded", "draining", "disabled"})
REQUIRED_CHECKS = frozenset({
    "vpn_client_e2e", "revoke_and_expiry", "dns_tls", "proxy_tls",
    "data_flow", "external_probe", "egress_country",
})
CRITICAL_KINDS = frozenset({
    "cross_node_outage", "tunnel_degraded", "subscription_corruption",
    "credential_leak", "config_drift", "control_plane_failure",
    "billing_inconsistency", "unrecognized_change",
})
MINOR_KINDS = frozenset({"owned_sidecar_down"})
LOW_RISK_RUNBOOKS = frozenset({"restart-owned-sidecar"})
MAX_CHECK_AGE = timedelta(hours=1)
MAX_GRANT_AGE = timedelta(minutes=15)


class ContractError(ValueError):
    pass


def utc_time(raw: str) -> datetime:
    if not isinstance(raw, str):
        raise ContractError("Expected timestamp")
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("Invalid timestamp") from exc
    if value.tzinfo is None:
        raise ContractError("Timezone is required")
    return value.astimezone(timezone.utc)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class VerifiedNode:
    node_id: str
    role: str
    services: tuple[str, ...]
    country_code: str
    country_name_ru: str
    address: str
    vpn_port: int
    state: str
    checks: dict[str, dict[str, Any]]
    country_evidence_sha256: str

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> "VerifiedNode":
        if not isinstance(raw, dict):
            raise ContractError("Node must be an object")
        if set(raw) != {
            "node_id", "role", "services", "country_code", "country_name_ru",
            "address", "vpn_port", "state", "checks", "country_evidence_sha256",
        }:
            raise ContractError("Node has missing or unexpected fields")
        if not isinstance(raw["node_id"], str) or not NODE_ID.fullmatch(raw["node_id"]):
            raise ContractError("Invalid node ID")
        if raw["role"] not in {"edge", "egress", "combined"}:
            raise ContractError("Invalid role")
        services = raw["services"]
        if (not isinstance(services, list) or not services or
                not all(isinstance(s, str) and s in ALLOWED_SERVICES for s in services) or
                len(set(services)) != len(services)):
            raise ContractError("Invalid services")
        if raw["role"] == "edge" and "vpn" in services:
            raise ContractError("Edge cannot advertise egress VPN")
        country = raw["country_code"]
        if not isinstance(country, str) or not COUNTRY.fullmatch(country):
            raise ContractError("Use uppercase ISO 3166-1 alpha-2 country code")
        name = raw["country_name_ru"]
        if (not isinstance(name, str) or not 2 <= len(name) <= 70 or
                not re.fullmatch(r"[А-Яа-яЁёA-Za-z ()-]+", name)):
            raise ContractError("Country display label must be a safe verified name")
        host = raw["address"]
        if (not isinstance(host, str) or len(host) > 253 or
                not re.fullmatch(r"[A-Za-z0-9.-]+", host) or
                "." not in host or ".." in host):
            raise ContractError("Node address must be a registered FQDN")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ContractError("Use stable node FQDN, not a bare IP")
        if (type(raw["vpn_port"]) is not int or
                not 1 <= raw["vpn_port"] <= 65535):
            raise ContractError("Invalid VPN port")
        if not isinstance(raw["state"], str) or raw["state"] not in STATES:
            raise ContractError("Invalid node state")
        evidence = raw["country_evidence_sha256"]
        if not isinstance(evidence, str) or not HEX_SHA.fullmatch(evidence):
            raise ContractError("Missing country egress evidence reference")
        checks = raw["checks"]
        if not isinstance(checks, dict):
            raise ContractError("Invalid check records")
        return cls(raw["node_id"], raw["role"], tuple(services), country,
                   name, host.lower(), raw["vpn_port"], raw["state"], checks, evidence)

    def eligible(self, at: datetime) -> bool:
        if self.state != "enabled" or self.role == "edge" or "vpn" not in self.services:
            return False
        if not REQUIRED_CHECKS.issubset(self.checks):
            return False
        for name in REQUIRED_CHECKS:
            entry = self.checks[name]
            if not isinstance(entry, dict) or set(entry) != {"ok", "at", "report_sha256"}:
                return False
            if entry["ok"] is not True:
                return False
            if not isinstance(entry["report_sha256"], str) or not HEX_SHA.fullmatch(entry["report_sha256"]):
                return False
            try:
                observed = utc_time(entry["at"])
            except ContractError:
                return False
            if observed > at + timedelta(minutes=2) or at - observed > MAX_CHECK_AGE:
                return False
        return True


def country_flag(code: str) -> str:
    if not COUNTRY.fullmatch(code):
        raise ContractError("Bad country")
    return "".join(chr(127397 + ord(char)) for char in code)


def verify_receipt(receipt: dict[str, Any], node: VerifiedNode,
                   signing_key: bytes, entitlement_id: str, revision: int,
                   expiry: datetime, at: datetime) -> str | None:
    """Receipt proves this SAME subscriber's node-side access; not just node uptime.

    Signing key belongs to an independent authenticated node provisioning
    control channel and must be supplied from a secret store, never Git/API.
    """
    expected = {"node_id", "entitlement_id", "revision", "expires_at",
                "observed_at", "profile_uri", "mac"}
    if not isinstance(receipt, dict) or set(receipt) != expected:
        return None
    unsigned = {k: v for k, v in receipt.items() if k != "mac"}
    if not isinstance(signing_key, bytes) or len(signing_key) < 32:
        raise ContractError("Missing private node HMAC secret")
    mac = receipt["mac"]
    if not isinstance(mac, str) or not HEX_SHA.fullmatch(mac):
        return None
    expected_mac = hmac.new(signing_key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected_mac):
        return None
    try:
        until = utc_time(receipt["expires_at"])
        checked = utc_time(receipt["observed_at"])
        if (receipt["node_id"] != node.node_id or
                receipt["entitlement_id"] != entitlement_id or
                type(receipt["revision"]) is not int or receipt["revision"] != revision or
                abs((until - expiry).total_seconds()) > 1 or
                expiry <= at or checked > at + timedelta(minutes=2) or
                at - checked > MAX_GRANT_AGE):
            return None
        uri = receipt["profile_uri"]
        if not isinstance(uri, str) or len(uri) > 2048 or any(ord(c) < 32 for c in uri):
            return None
        parsed = urlparse(uri)
        if (parsed.scheme != "vless" or parsed.hostname != node.address or
                parsed.port != node.vpn_port or parsed.password is not None):
            return None
        if str(uuid.UUID(parsed.username or "")) != parsed.username:
            return None
        if parsed.fragment or parsed.params:
            return None
        query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
        if any(len(v) != 1 for v in query.values()):
            return None
        if (query.get("security") != ["reality"] or
                query.get("type") != ["tcp"] or
                query.get("encryption") != ["none"] or
                query.get("flow") != ["xtls-rprx-vision"] or
                query.get("fp") not in (["chrome"], ["firefox"]) or
                not re.fullmatch(r"[A-Za-z0-9_-]{43}", query.get("pbk", [""])[0]) or
                not re.fullmatch(r"[0-9a-f]{16}", query.get("sid", [""])[0])):
            return None
        # No change of SNI/upstream security through unvetted query parameters.
        if set(query) != {"security", "type", "encryption", "flow",
                          "fp", "pbk", "sid", "sni", "spx"}:
            return None
        if not re.fullmatch(r"[A-Za-z0-9.-]{4,253}", query["sni"][0]):
            return None
        if query["spx"] != ["/"]:
            return None
        label = f"{country_flag(node.country_code)} MNEBYVPN · {node.country_name_ru} · {node.node_id}"
        # URI and UUID remain private; do not log receipts or returned profiles.
        return uri + "#" + quote(label, safe="")
    except (ContractError, ValueError, TypeError, KeyError):
        return None


def render_subscription(existing: str, nodes: list[VerifiedNode],
                        receipts: list[dict[str, Any]], keys: dict[str, bytes],
                        entitlement_id: str, revision: int, expiry: datetime,
                        at: datetime) -> str:
    """Side-effect-free subscription projection; preserve existing live entries.

    Caller MUST already authenticate bearer subscription and verify active
    entitlement in PostgreSQL. Never accept receipts from browser requests.
    """
    if (not isinstance(existing, str) or not existing.strip() or
            any(not line.startswith("vless://") for line in existing.splitlines() if line)):
        raise ContractError("Existing node profile is invalid")
    if (not isinstance(entitlement_id, str) or
            str(uuid.UUID(entitlement_id)) != entitlement_id or
            type(revision) is not int or revision < 1 or expiry <= at):
        raise ContractError("Entitlement not currently active")
    lines = existing.strip().splitlines()
    seen = set(lines)
    receipts_by_node: dict[str, dict[str, Any]] = {}
    for receipt in receipts:
        if isinstance(receipt, dict) and isinstance(receipt.get("node_id"), str):
            # Duplicate, conflicting receipts cannot silently choose a winner.
            key = receipt["node_id"]
            if key in receipts_by_node:
                raise ContractError("Conflicting node receipts")
            receipts_by_node[key] = receipt
    for node in sorted(nodes, key=lambda n: (n.country_code, n.node_id)):
        if not node.eligible(at):
            continue
        receipt = receipts_by_node.get(node.node_id)
        key = keys.get(node.node_id)
        if receipt is None or key is None:
            continue
        profile = verify_receipt(receipt, node, key, entitlement_id, revision, expiry, at)
        if profile and profile not in seen:
            lines.append(profile)
            seen.add(profile)
    return "\n".join(lines)


@dataclass(frozen=True)
class Incident:
    incident_id: str
    kind: str
    nodes: tuple[str, ...]
    services: tuple[str, ...]
    independent_probes: int
    repeated_failures: int
    detail_code: str

    @classmethod
    def parse(cls, data: dict[str, Any]) -> "Incident":
        fields = {"incident_id", "kind", "nodes", "services",
                  "independent_probes", "repeated_failures", "detail_code"}
        if not isinstance(data, dict) or set(data) != fields:
            raise ContractError("Invalid incident shape")
        try:
            iid = str(uuid.UUID(data["incident_id"]))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ContractError("Invalid incident id") from exc
        nodes, services = data["nodes"], data["services"]
        if (not isinstance(nodes, list) or not nodes or
                not all(isinstance(x, str) and NODE_ID.fullmatch(x) for x in nodes) or
                len(nodes) != len(set(nodes)) or
                not isinstance(services, list) or not services or
                not all(isinstance(x, str) and x in ALLOWED_SERVICES for x in services) or
                len(services) != len(set(services))):
            raise ContractError("Invalid affected nodes/services")
        if any(type(data[k]) is not int or not 0 <= data[k] <= 10000 for k in
               ("independent_probes", "repeated_failures")):
            raise ContractError("Invalid probe counts")
        if not isinstance(data["kind"], str) or not re.fullmatch(r"[a-z_]{3,64}", data["kind"]):
            raise ContractError("Invalid incident kind")
        if not isinstance(data["detail_code"], str) or not re.fullmatch(r"[A-Z0-9_]{1,64}", data["detail_code"]):
            raise ContractError("Incident detail_code must be pre-normalized, no raw logs")
        return cls(iid, data["kind"], tuple(nodes), tuple(services),
                   data["independent_probes"], data["repeated_failures"],
                   data["detail_code"])


def route_incident(incident: Incident, enrolled_owned_services: set[str]) -> dict[str, Any]:
    """Deterministic permission boundary; agent text never overrides this."""
    broad = len(incident.nodes) > 1 or len(incident.services) > 1
    critical = broad or incident.kind in CRITICAL_KINDS or incident.kind not in MINOR_KINDS
    if critical:
        return {"classification": "global_or_unknown", "action": "escalate_read_only",
                "auto_execute": False, "notify_owner": True}
    # Only if a single newly deployed nodekit-owned sidecar is affected, and
    # at least two independent observers saw two repeated data-path failures.
    observed = incident.independent_probes >= 2 and incident.repeated_failures >= 2
    owned = incident.nodes[0] in enrolled_owned_services
    if not observed or not owned:
        return {"classification": "unconfirmed", "action": "collect_evidence",
                "auto_execute": False, "notify_owner": incident.repeated_failures >= 3}
    return {"classification": "local_known", "action": "restart-owned-sidecar",
            # v1 executor is NOT shipped; this is an ALLOWLISTED PROPOSAL.
            "auto_execute": False, "notify_owner": True}


def safe_agent_payload(incident: Incident, decision: dict[str, Any]) -> dict[str, Any]:
    """Only structured and sanitized telemetry crosses into an external AI API."""
    return {
        "schema_version": 1, "incident_id": incident.incident_id,
        "kind": incident.kind, "nodes": list(incident.nodes),
        "services": list(incident.services),
        "detail_code": incident.detail_code,
        "independent_probes": incident.independent_probes,
        "repeated_failures": incident.repeated_failures,
        "classification": decision["classification"],
        "allowed_action": decision["action"],
        "permissions": "advisory_only",
    }


def parse_agent_advice(value: Any, decision: dict[str, Any]) -> dict[str, str]:
    """Never accept commands/URLs, shell code, paths, secrets or action overrides."""
    if not isinstance(value, dict) or set(value) != {"action", "reason_code"}:
        raise ContractError("Agent returned unsupported fields")
    action, reason = value["action"], value["reason_code"]
    if (not isinstance(action, str) or action not in {"collect_evidence", "escalate_read_only",
                                                       "restart-owned-sidecar"} or
            action != decision["action"] or
            not isinstance(reason, str) or
            not re.fullmatch(r"[A-Z0-9_]{1,64}", reason)):
        raise ContractError("Agent attempted unauthorized action")
    return {"action": action, "reason_code": reason}
