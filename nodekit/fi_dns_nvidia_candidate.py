#!/usr/bin/env python3
"""Prepare a closed NVIDIA DNS/SNI candidate after checking real FI origins."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from dns_proxy_stage import make_corefile, make_nginx_conf, validate_policy
from fi_dns_origin_canary import prepare
from fi_regional_cert_stage import DEST, ROOT, trusted_dir, trusted_file, verify_pair
from nodekit import _promote_stage_noreplace

NIM = "integrate.api.nvidia.com"
FI_IP = "217.11.167.91"


def rollout():
    path = Path(__file__).with_name("mnebydns-nvidia-permanent-20261124.py")
    if not path.is_file():
        path = Path(__file__).resolve().parents[1] / "scripts" / path.name
    spec = importlib.util.spec_from_file_location("nvidia_rollout", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("NVIDIA rollout missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.self_test()
    return module


def make_candidate(routes):
    policy = validate_policy({
        "schema_version": 1,
        "node_id": ROOT.name,
        "external_ipv4": FI_IP,
        "dns_host": "fi.dns.mnebyvpn.site",
        "routes": routes,
    }, ROOT.name)
    core = make_corefile(policy, ROOT).replace(str(ROOT / "tls"), str(DEST))
    # Prevent HTTPS/SVCB hints and explicit CNAME lookups from bypassing the
    # pinned IPv4 route. Keep unrelated queries with the original forwarder.
    extras = []
    for route in policy["routes"]:
        match = "^" + re.escape(route["domain"]) + r"\.$"
        for kind in ("CNAME", "HTTPS", "SVCB"):
            extras.extend([
                f"  template IN {kind} . {{",
                f"    match {match}",
                "    rcode NOERROR",
                "    fallthrough",
                "  }",
            ])
    forward = "  forward . tls://1.1.1.1 tls://1.0.0.1 {"
    if core.count(forward) != 1:
        raise RuntimeError("Unexpected FI forwarder configuration")
    core = core.replace(forward, "\n".join([*extras, forward]))
    nginx = make_nginx_conf(policy)
    return {
        "Corefile": core.encode(),
        "nginx.conf": nginx.encode(),
        "policy.json": (json.dumps(policy, sort_keys=True) + "\n").encode(),
    }


def inspect_origins(module):
    def check(name):
        try:
            ip = module.owner._render.origin_ip(name)
        except (OSError, ValueError, RuntimeError):
            print("fi_nvidia_origin_unverified=" + name, flush=True)
            return None
        print("fi_nvidia_origin_tls_verified=" + name, flush=True)
        return {"domain": name, "upstream_ipv4": ip}

    with ThreadPoolExecutor(max_workers=5) as pool:
        return [route for route in pool.map(check, module.TARGETS) if route]


def verify_nim(routes):
    nim = next((route for route in routes if route["domain"] == NIM), None)
    if nim is None:
        raise RuntimeError("FI NIM TLS origin missing")
    result = subprocess.run([
        "curl", "--silent", "--show-error", "--noproxy", "*", "--max-time", "15",
        "--output", "/dev/null", "--write-out", "%{http_code}",
        "--resolve", f"{NIM}:443:{nim['upstream_ipv4']}",
        f"https://{NIM}/v1/models",
    ], timeout=18, capture_output=True, text=True, check=False)
    code = result.stdout
    if code.isascii() and len(code) == 3 and code.isdigit():
        print("fi_nvidia_models_direct_http=" + code, flush=True)
    if result.returncode or code not in {"200", "401"}:
        raise RuntimeError("FI NIM model-list request failed")


def stage(files):
    parent = ROOT / "dns-auth"
    trusted_dir(parent)
    hash_input = files["policy.json"] + files["Corefile"] + files["nginx.conf"]
    destination = parent / ("nvidia-candidate-" + hashlib.sha256(hash_input).hexdigest())
    with tempfile.TemporaryDirectory(prefix=".nvidia-stage-", dir=parent) as temporary:
        work = Path(temporary)
        for name, data in files.items():
            (work / name).write_bytes(data)
        checked = subprocess.run(["nginx", "-t", "-c", str(work / "nginx.conf")],
                                 capture_output=True, timeout=15, check=False)
        if checked.returncode:
            raise RuntimeError("FI NVIDIA Nginx configuration failed validation")
        try:
            _promote_stage_noreplace(work, destination)
        except FileExistsError:
            trusted_dir(destination)
            for name, data in files.items():
                if trusted_file(destination / name, 120_000) != data:
                    raise RuntimeError("FI NVIDIA staged candidate drift")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("self-test", "stage"))
    args = parser.parse_args()
    module = rollout()
    if args.mode == "self-test":
        routes = [{"domain": h, "upstream_ipv4": "1.1.1.1"} for h in module.TARGETS]
        files = make_candidate(routes)
        for kind in (b"A", b"AAAA", b"CNAME", b"HTTPS", b"SVCB"):
            assert files["Corefile"].count(b"template IN " + kind + b" .") == len(routes)
        assert files["nginx.conf"].count(b" 1.1.1.1:443;") == len(routes)
        assert b"default 127.0.0.1:9;" in files["nginx.conf"]
        print("fi_nvidia_candidate_contract=PASS")
        return
    os.umask(0o077)
    prepare()
    verify_pair(DEST)
    routes = inspect_origins(module)
    verify_nim(routes)
    stage(make_candidate(routes))
    print(f"fi_nvidia_candidate_routes={len(routes)}/{len(module.TARGETS)}")
    print("fi_nvidia_candidate_staged=true;customer_dns_activated=false")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FI NVIDIA staging failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(2) from None
