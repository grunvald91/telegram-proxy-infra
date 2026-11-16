#!/usr/bin/env python3
"""Non-destructive MNEBYVPN node bootstrap: validate, preflight, stage inventory.

No software installation, firewall changes, service activation, or node publication.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import tempfile
from typing import Any

VALID_ROLES = {"edge", "egress", "combined"}
VALID_SERVICES = {"dns", "vpn", "sni-proxy", "tunnel"}
SERVICE_LISTENERS = {
    "dns": "dot_tcp", "vpn": "vpn_tcp",
    "sni-proxy": "sni_tcp", "tunnel": "tunnel_udp",
}
REQUIRED_KEYS = {"schema_version", "node_id", "role", "services",
                 "advertise_host", "listeners"}
OPTIONAL_KEYS = {"region", "provider", "bootstrap_notes"}


def _promote_stage_noreplace(source: Path, destination: Path) -> None:
    """Linux atomic rename that never replaces a concurrently created node."""
    if sys.platform != "linux":
        raise OSError("Atomic no-replace staging requires Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as exc:
        raise OSError("renameat2 unavailable; refusing unsafe staging") from exc
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    result = renameat2(-100, os.fsencode(source), -100,
                       os.fsencode(destination), 1)
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), str(destination))


class SpecError(ValueError):
    pass


def validate_spec(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise SpecError("Spec must be a JSON object")
    unknown = set(data) - REQUIRED_KEYS - OPTIONAL_KEYS
    missing = REQUIRED_KEYS - set(data)
    if unknown or missing:
        raise SpecError(f"Unexpected keys: {sorted(unknown)}; missing: {sorted(missing)}")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise SpecError("schema_version must be 1")
    node_id = data["node_id"]
    if (not isinstance(node_id, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,39}", node_id)
            or node_id.endswith("-")):
        raise SpecError("Invalid node_id")
    if not isinstance(data["role"], str) or data["role"] not in VALID_ROLES:
        raise SpecError("Invalid role")
    services = data["services"]
    if (not isinstance(services, list) or not services
            or not all(isinstance(x, str) for x in services)
            or len(services) != len(set(services))
            or not set(services) <= VALID_SERVICES):
        raise SpecError("services must be a nonempty unique known role list")
    if data["role"] == "edge" and "vpn" in services:
        raise SpecError("An edge must not enable VPN egress by accident")
    host = data["advertise_host"]
    if not isinstance(host, str) or len(host) > 253 or not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
        raise SpecError("advertise_host must be an explicit DNS hostname")
    labels = host.split(".")
    if (len(labels) < 2 or any(
            not x or len(x) > 63 or x.startswith("-") or x.endswith("-")
            for x in labels)):
        raise SpecError("Invalid DNS hostname")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise SpecError("advertise_host must not be an IP literal")
    listeners = data["listeners"]
    required_ports = {SERVICE_LISTENERS[s] for s in services}
    if not isinstance(listeners, dict) or set(listeners) != required_ports:
        raise SpecError(f"listeners must exactly match services: {sorted(required_ports)}")
    for name, port in listeners.items():
        if type(port) is not int or not 1 <= port <= 65535:
            raise SpecError(f"Invalid port for {name}")
    tcp = [port for name, port in listeners.items() if name.endswith("_tcp")]
    if len(set(tcp)) != len(tcp):
        raise SpecError("TCP listener port collision")
    for field in OPTIONAL_KEYS:
        if field in data and (not isinstance(data[field], str) or len(data[field]) > 200):
            raise SpecError(f"Invalid {field}")
    return data


def load_spec(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise SpecError("Spec must be a regular file, not a symlink")
    if path.stat().st_size > 16384:
        raise SpecError("Spec is too large")
    return validate_spec(json.loads(path.read_text(encoding="utf-8")))


def check_ports(listeners: dict[str, int]) -> dict[str, str]:
    results: dict[str, str] = {}
    for name, port in listeners.items():
        proto = socket.SOCK_DGRAM if name.endswith("_udp") else socket.SOCK_STREAM
        try:
            with socket.socket(socket.AF_INET, proto) as s:
                s.bind(("0.0.0.0", port))
            results[name] = "free_ipv4"
        except PermissionError:
            results[name] = "requires_privilege"
        except OSError:
            results[name] = "occupied_or_unavailable"
    return results


def system_facts() -> dict[str, Any]:
    os_info = {}
    release = Path("/etc/os-release")
    if release.is_file():
        for line in release.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                os_info[k] = v.strip('"')
    return {
        "os_id": os_info.get("ID", "unknown"),
        "os_version": os_info.get("VERSION_ID", "unknown"),
        "architecture": os.uname().machine,
        "cpu_count": os.cpu_count(),
        "disk_free_gib": round(shutil.disk_usage("/").free / (1024 ** 3), 2),
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
        "has_systemd": shutil.which("systemctl") is not None,
        "has_nginx": shutil.which("nginx") is not None,
        "has_coredns": shutil.which("coredns") is not None,
        "has_xray": shutil.which("xray") is not None,
        "has_wg": shutil.which("wg") is not None,
    }


def compute_report(spec: dict[str, Any]) -> dict[str, Any]:
    facts = system_facts()
    ports = check_ports(spec["listeners"])
    supported_os = (
        (facts["os_id"] == "debian" and facts["os_version"] in ("12", "13"))
        or (facts["os_id"] == "ubuntu" and facts["os_version"] == "24.04")
    )
    gates = {
        "supported_os": supported_os,
        "architecture_amd64_or_arm64": facts["architecture"] in ("x86_64", "aarch64"),
        "min_disk_5gib": facts["disk_free_gib"] >= 5,
        "all_listeners_free": all(v == "free_ipv4" for v in ports.values()),
        "has_systemd": facts["has_systemd"],
    }
    return {
        "node_id": spec["node_id"],
        "role": spec["role"],
        "services_requested": spec["services"],
        "listeners": spec["listeners"],
        "facts": facts,
        "port_checks": ports,
        "preflight_gates": gates,
        "can_stage": all(gates.values()),
        "activation_enabled": False,
        "registration_enabled": False,
        "reason": (
            "Bootstrap v1 stages inventory only; DNS policy, TLS certs, Xray "
            "credentials, tunnel peers, controller enrollment and E2E tests remain separate"
        ),
    }


def stage(spec: dict[str, Any], report: dict[str, Any], root: Path) -> Path:
    if not report["can_stage"]:
        raise SpecError("Preflight failed: refusing to stage")
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise SpecError("Stage root must be a real directory")
    node = root / spec["node_id"]
    if node.exists() or node.is_symlink():
        raise SpecError("Node already staged: refusing to overwrite")
    if root.exists() and root.stat().st_mode & 0o022:
        raise SpecError("Stage root must not be group/world writable")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    stage_tmp = Path(tempfile.mkdtemp(prefix=".nodekit-", dir=root))
    try:
        stage_tmp.chmod(0o700)
        canonical = json.dumps(spec, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        manifest = {
            "schema_version": 1,
            "node_id": spec["node_id"],
            "state": "testing",
            "spec_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "roles": spec["services"],
            "advertise_host": spec["advertise_host"],
            "listeners": spec["listeners"],
            "activation_enabled": False,
            "registration_enabled": False,
            "pending": [
                "signed_config_bundle", "tls_and_dns_policy", "xray_identity",
                "proxy_upstreams", "wg_peering", "health_probe", "canary",
                "controller_registration"
            ],
        }
        (stage_tmp / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        (stage_tmp / "preflight.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        for f in stage_tmp.iterdir():
            f.chmod(0o600)
        _promote_stage_noreplace(stage_tmp, node)
    except Exception:
        shutil.rmtree(stage_tmp)
        raise
    return node


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=("preflight", "stage"))
    ap.add_argument("--spec", type=Path, required=True)
    ap.add_argument("--stage-root", type=Path, default=Path("/var/lib/mnebyvpn-nodekit"))
    args = ap.parse_args()
    try:
        spec = load_spec(args.spec)
        report = compute_report(spec)
        if args.command == "stage":
            if os.geteuid() != 0:
                raise SpecError("Staging requires root")
            output = stage(spec, report, args.stage_root)
            report["staged_at"] = str(output)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["can_stage"] else 2
    except (OSError, ValueError, TypeError) as exc:
        print(f"nodekit_error={exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
