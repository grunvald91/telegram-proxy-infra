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
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

from dns_proxy_stage import make_corefile, make_nginx_conf, validate_policy
from fi_dns_origin_canary import COREDNS, HOSTS, prepare, read_exact
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


def check_local_path(files):
    """Exercise the staged CoreDNS answer and Nginx TLS route on loopback."""
    dot_port, proxy_port = 28553, 24443
    with tempfile.TemporaryDirectory(prefix="fi-nvidia-e2e-") as temporary:
        work = Path(temporary)
        core_source = files["Corefile"].decode()
        proxy_source = files["nginx.conf"].decode()
        for source, marker in ((core_source, "tls://.:8853 {"),
                               (proxy_source, "listen 0.0.0.0:443;"),
                               (proxy_source, "listen 0.0.0.0:853;"),
                               (proxy_source, "pid /tmp/mnebyvpn-nodekit-nginx-test.pid;")):
            if source.count(marker) != 1:
                raise RuntimeError("FI candidate listener configuration changed")
        # Use only the HTTPS server in the fixture. The staged DoT is
        # independently exercised directly with its regional certificate.
        proxy_config = proxy_source.replace("listen 0.0.0.0:443;",
                                            f"listen 127.0.0.1:{proxy_port};")
        proxy_config = proxy_config.replace("listen 0.0.0.0:853;",
                                            "listen 127.0.0.1:28554;")
        proxy_config = proxy_config.replace("127.0.0.1:8853", f"127.0.0.1:{dot_port}")
        proxy_config = proxy_config.replace("/tmp/mnebyvpn-nodekit-nginx-test.pid",
                                            str(work / "nginx.pid"))
        core_config = core_source.replace("tls://.:8853 {", f"tls://.:{dot_port} {{")
        core_path, proxy_path = work / "Corefile", work / "nginx.conf"
        core_path.write_text(core_config)
        proxy_path.write_text(proxy_config)
        for port in (dot_port, proxy_port, 28554):
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        children = []
        try:
            for command in ([str(COREDNS), "-conf", str(core_path)],
                            ["nginx", "-c", str(proxy_path), "-g", "daemon off;"]):
                children.append(subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL))
            for attempt in range(20):
                if any(child.poll() is not None for child in children):
                    raise RuntimeError("FI loopback fixture exited")
                try:
                    with socket.create_connection(("127.0.0.1", dot_port), timeout=0.3):
                        pass
                    with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.3):
                        pass
                    break
                except OSError:
                    if attempt == 19:
                        raise
                    time.sleep(0.2)
            query = (os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                     + b"".join(bytes([len(label)]) + label.encode() for label in NIM.split("."))
                     + b"\x00\x00\x01\x00\x01")
            with socket.create_connection(("127.0.0.1", dot_port), timeout=5) as tcp:
                with ssl.create_default_context().wrap_socket(tcp, server_hostname=HOSTS[0]) as tls:
                    tls.sendall(struct.pack("!H", len(query)) + query)
                    length = struct.unpack("!H", read_exact(tls, 2))[0]
                    reply = read_exact(tls, length)
            if (len(reply) < 32 or reply[:2] != query[:2] or reply[3] & 15
                    or reply[6:8] != b"\x00\x01" or reply[-4:] != socket.inet_aton(FI_IP)):
                raise RuntimeError("FI candidate DNS did not return the expected routing address")
            print("fi_nvidia_candidate_dot_rewrite_verified=true", flush=True)
            status = subprocess.run([
                "curl", "--silent", "--show-error", "--noproxy", "*", "--max-time", "15",
                "--output", "/dev/null", "--write-out", "%{http_code}",
                "--connect-to", f"{NIM}:443:127.0.0.1:{proxy_port}", f"https://{NIM}/v1/models",
            ], timeout=18, capture_output=True, text=True, check=False)
            if status.stdout.isdigit() and len(status.stdout) == 3:
                print("fi_nvidia_models_via_candidate_proxy_http=" + status.stdout, flush=True)
            if status.returncode or status.stdout not in {"200", "401"}:
                raise RuntimeError("FI candidate HTTPS proxy did not pass the NIM API request")
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()


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
    files = make_candidate(routes)
    check_local_path(files)
    stage(files)
    print(f"fi_nvidia_candidate_routes={len(routes)}/{len(module.TARGETS)}")
    print("fi_nvidia_candidate_staged=true;customer_dns_activated=false")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FI NVIDIA staging failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(2) from None
