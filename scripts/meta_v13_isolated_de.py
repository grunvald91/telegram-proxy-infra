#!/usr/bin/env python3
"""Isolated, exact-host Meta TLS route validation on the DE VPS.

No live DNS/Nginx configuration or firewall is changed. A separate
NGINX stream process listens ONLY on 127.0.0.1 and is removed on exit.
This is NOT an Android, TSPU, QUIC, or public Smart DNS E2E test.
"""
from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

EDGE = "89.125.90.101"
HOSTS = ("i.instagram.com", "iglite-z.instagram.com")
LIVE_CORE = Path("/opt/mnebydns-dot/Corefile")
LIVE_NGINX = Path("/etc/nginx/nginx.conf")
BASE = Path(__file__).resolve().parent
RENDERER = BASE / "mnebydns-owner-domain-render-20261110.py"

def checked_run(args: list[str], timeout: int = 12) -> bool:
    try:
        return subprocess.run(args, timeout=timeout, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False

def load_renderer():
    spec = importlib.util.spec_from_file_location("mneby_route_renderer", RENDERER)
    if spec is None or spec.loader is None:
        raise RuntimeError("route_renderer_missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def synthesize(renderer, core: str, nginx: str, ip_map: dict[str, str]):
    original_core, original_nginx = core, nginx
    for host in HOSTS:
        core = renderer.core_add(core, host)
        nginx = renderer.nginx_add(nginx, host, ip_map[host])
    for host in reversed(HOSTS):
        core = renderer.core_remove(core, host)
        nginx = renderer.nginx_remove(nginx, host)
    if (core, nginx) != (original_core, original_nginx):
        raise RuntimeError("renderer_roundtrip_failed")
    core, nginx = original_core, original_nginx
    for host in HOSTS:
        core = renderer.core_add(core, host)
        nginx = renderer.nginx_add(nginx, host, ip_map[host])
        pattern = "match ^" + re.escape(host).replace(r"\.", "[.]") + "[.]$"
        if core.count(pattern) != 5:
            raise RuntimeError("dns_exact_record_count_invalid")
        if nginx.count("        " + host + " " + ip_map[host] + ":443;") != 1:
            raise RuntimeError("nginx_exact_route_count_invalid")
    if "default " + EDGE not in original_nginx and "default " + EDGE in nginx:
        raise RuntimeError("unsafe_default_route_added")
    return core, nginx

def verify_tls(target: str, port: int, hostname: str, timeout: float = 6) -> str:
    with socket.create_connection((target, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with ssl.create_default_context().wrap_socket(raw, server_hostname=hostname) as tls:
            if not tls.getpeercert():
                raise RuntimeError("no_peer_certificate")
            return str(tls.version())

def choose_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def module_declaration() -> str:
    """Reuse the exact stream-module load syntax from a valid running Nginx.

    Some vendor Nginx builds omit --with-stream from nginx -V even though
    stream is available through a module loaded by the live configuration.
    Only the known stream load directive is borrowed; no live listeners.
    """
    p = subprocess.run(["nginx", "-T"], timeout=12, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError("live_nginx_config_unavailable")
    directives = re.findall(
        r"(?m)^\s*load_module\s+([^;\s]*ngx_stream_module\.so)\s*;",
        p.stdout,
    )
    if len(directives) > 1:
        raise RuntimeError("ambiguous_stream_module")
    if directives:
        candidate = directives[0]
        if '"' in candidate or "'" in candidate or any(c in candidate for c in "{}"):
            raise RuntimeError("untrusted_module_path")
        return "load_module " + candidate + ";\n"
    # The active configuration was parsed successfully by nginx -T, including
    # its stream map. No explicit load_module means stream is built in.
    if "stream {" not in p.stdout:
        raise RuntimeError("live_stream_block_not_found")
    return ""

def isolated_nginx(tmp: Path, port: int, ip_map: dict[str, str]) -> Path:
    if not 1024 < port < 65536:
        raise RuntimeError("bad_loopback_port")
    for name in HOSTS:
        ip = ipaddress.IPv4Address(ip_map[name])
        if not ip.is_global or ip_map[name] == EDGE or ip.is_loopback:
            raise RuntimeError("unapproved_origin_ip")
    mapping = "".join("        " + h + " " + ip_map[h] + ":443;\n" for h in HOSTS)
    conf = (module_declaration()
            + "worker_processes 1;\n"
            + "pid " + str(tmp / "nginx.pid") + ";\n"
            + "error_log stderr warn;\n"
            + "events { worker_connections 64; }\n"
            + "stream {\n"
            + "    map $ssl_preread_server_name $meta_v13_target {\n"
            + "        default 127.0.0.1:1;\n"
            + mapping
            + "    }\n"
            + "    server {\n"
            + "        listen 127.0.0.1:" + str(port) + ";\n"
            + "        ssl_preread on;\n"
            + "        proxy_pass $meta_v13_target;\n"
            + "        proxy_connect_timeout 4s;\n"
            + "        proxy_timeout 12s;\n"
            + "        access_log off;\n"
            + "    }\n"
            + "}\n")
    target = tmp / "nginx-isolated.conf"
    target.write_text(conf, encoding="utf-8")
    target.chmod(0o600)
    return target

def child_die_with_parent() -> None:
    # PR_SET_PDEATHSIG: if SSH/Python stops, the non-daemonized nginx exits.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, int(signal.SIGTERM), 0, 0, 0) != 0:
        os._exit(1)

def run_isolated(config: Path, port: int) -> None:
    if not checked_run(["nginx", "-t", "-c", str(config)], timeout=10):
        raise RuntimeError("nginx_isolated_config_invalid")
    proc = subprocess.Popen(
        ["nginx", "-c", str(config), "-g", "daemon off; master_process off;"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, preexec_fn=child_die_with_parent,
    )
    try:
        ready = False
        for _ in range(50):
            if proc.poll() is not None:
                raise RuntimeError("nginx_isolated_exited")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    ready = True
                    break
            except OSError:
                time.sleep(.08)
        if not ready:
            raise RuntimeError("nginx_isolated_not_ready")
        for host in HOSTS:
            version = verify_tls("127.0.0.1", port, host)
            print("isolated_tls_" + host.replace(".", "_").replace("-", "_")
                  + "=verified_" + version.replace(".", "_"), flush=True)
        try:
            verify_tls("127.0.0.1", port, "not-a-meta-host.example.org", timeout=3)
        except (ssl.SSLError, OSError):
            print("isolated_unknown_sni_denied=true", flush=True)
        else:
            raise RuntimeError("unexpected_unknown_sni_success")
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)

def self_test() -> None:
    renderer = load_renderer()
    core = ("tls://.:853 {\n"
            "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
            "    cache 30\n}\n")
    nginx = ("stream {\n"
             + renderer.NGINX_ANCHOR + "\n"
             + "        default 127.0.0.1:9443;\n"
             + "    }\n"
             + "    server { proxy_pass $direct_mtproxy_backend; }\n}\n")
    ips = {"i.instagram.com": "157.240.0.160",
           "iglite-z.instagram.com": "157.240.0.161"}
    proposed_core, proposed_nginx = synthesize(renderer, core, nginx, ips)
    assert core != proposed_core and nginx != proposed_nginx
    assert core.count("iglite") == 0 and nginx.count("iglite") == 0
    try:
        synthesize(renderer, proposed_core, proposed_nginx, ips)
    except ValueError:
        pass
    else:
        raise AssertionError("existing_route_not_rejected")
    print("isolated_preview_offline_contract=PASS", flush=True)

def de_test() -> None:
    if os.geteuid() != 0:
        raise RuntimeError("requires_root_for_authoritative_read_only_baseline")
    if not checked_run(["nginx", "-t"]):
        raise RuntimeError("production_nginx_baseline_invalid")
    for path in (LIVE_CORE, LIVE_NGINX):
        if not path.is_file():
            raise RuntimeError("baseline_missing")
    before = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (LIVE_CORE, LIVE_NGINX)}
    renderer = load_renderer()
    ips = {}
    for host in HOSTS:
        ips[host] = renderer.origin_ip(host)
        version = verify_tls(ips[host], 443, host)
        print("origin_tls_" + host.replace(".", "_").replace("-", "_")
              + "=verified_" + version.replace(".", "_"), flush=True)
    core, nginx = synthesize(renderer, LIVE_CORE.read_text(), LIVE_NGINX.read_text(), ips)
    assert core and nginx
    print("isolated_dns_nginx_preview=EXACT_REVERSED_IN_MEMORY", flush=True)
    with tempfile.TemporaryDirectory(prefix="mneby-meta-v13-") as name:
        tmp = Path(name)
        os.chmod(tmp, 0o700)
        isolated = isolated_nginx(tmp, choose_port(), ips)
        port = int(re.search(r"listen 127[.]0[.]0[.]1:(\d+);", isolated.read_text()).group(1))
        run_isolated(isolated, port)
    after = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in before}
    if after != before:
        raise RuntimeError("PRODUCTION_CONFIG_HASH_DRIFT")
    print("production_configs_unchanged=true", flush=True)
    print("public_dns_unchanged=true", flush=True)
    print("android_e2e=NOT_TESTED", flush=True)
    print("client_sni_split=NOT_IMPLEMENTED", flush=True)

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("self-test", "de-test"):
        raise SystemExit("usage: meta_v13_isolated_de.py self-test|de-test")
    if sys.argv[1] == "self-test":
        self_test()
    else:
        de_test()
