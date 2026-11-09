#!/usr/bin/env python3
"""Prepare an isolated Instagram/Threads-only MNEBYDNS experiment.

This renderer DOES NOT change the running five-service checkpoint.
It renders a separate private-WireGuard Nginx sidecar plus an additive
CoreDNS overlay, both suitable for preflight/diff/explicitly timed canaries.
"""
from __future__ import annotations
import importlib.util
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mnebydns_existing_renderer", HERE / "mnebydns-four-google-canary.py")
assert _spec and _spec.loader
old = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(old)

RU = "188.120.254.223"
WG_PRIVATE = "10.66.77.1:19443"
EXACT = (
    "instagram.com", "www.instagram.com", "i.instagram.com",
    "graph.instagram.com", "api.instagram.com",
    "threads.com", "www.threads.com", "threads.net",
    "www.threads.net", "graph.threads.net",
    "edge-mqtt.facebook.com", "mqtt-ig-p4.facebook.com",
    "graph.facebook.com", "b-graph.facebook.com",
    "meta.com", "meta.ai", "instagramstatic-a.akamaihd.net",
)
SUFFIXES = tuple(old.META_SUFFIXES)
assert len(SUFFIXES) == 17
assert len(set(EXACT)) == len(EXACT)
assert set(SUFFIXES).isdisjoint(set(old.TELEGRAM_SUFFIXES)) if hasattr(old, "TELEGRAM_SUFFIXES") else True

META_DNS_PATTERN = r"(?i)^(?:[a-z0-9-]+[.])*(?:" + "|".join(
    re.escape(zone) for zone in SUFFIXES) + r")[.]$"
META_NGINX_PATTERN = r"~*^(?:[a-z0-9-]+\.)*(?:" + "|".join(
    re.escape(zone) for zone in SUFFIXES) + r")$"

def render_dns(stable: str) -> str:
    marker = "    cache 30\n"
    if stable.count(marker) != 1 or stable.count("template IN A gemini.google.com {") != 1:
        raise ValueError("Unknown five-service CoreDNS baseline")
    for name in EXACT:
        if re.search(r"template IN (?:A|AAAA|HTTPS|SVCB|CNAME)\s+"+re.escape(name)+r"\s*\{",stable):
            raise ValueError("Existing owner of Meta DNS name: "+name)
    if RU in stable or "mnebydns-meta-isolated-20261109" in stable:
        raise ValueError("Unexpected pre-existing Meta route")
    addition = "\n    # mnebydns-meta-isolated-20261109: temporary reversible Meta only\n"
    for host in EXACT:
        for kind in old.RR:
            addition += old.rr_template(host,kind,ip=RU)
    for kind in old.RR:
        addition += old.rr_template(".",kind,META_DNS_PATTERN,ip=RU)
    result = stable.replace(marker, addition+marker,1)
    if result.replace(addition,"",1) != stable:
        raise AssertionError("DNS patch was not purely additive")
    for name in ("api.telegram.org","t.me","web.telegram.org"):
        if name in addition:
            raise AssertionError("Telegram must never be rewritten by Meta policy")
    return result

def render_proxy() -> str:
    map_entries = "".join("        "+host+" "+host+":443;\n" for host in EXACT)
    return (
        "# MNEBYDNS Meta-only WireGuard SNI TLS passthrough; no public listener\n"
        "load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n"
        "worker_processes 1;\n"
        "pid /run/mnebydns-meta-pilot/nginx.pid;\n"
        "error_log stderr warn;\n"
        "events { worker_connections 128; }\n"
        "stream {\n"
        "  resolver 9.9.9.9 ipv6=off valid=30s;\n"
        "  resolver_timeout 5s;\n"
        "  # Aggregate-only experiment telemetry: no SNI, IP or packet contents\n"
        "  log_format meta_stage 'META_DE status=$status sent_to_ru=$bytes_sent recv_from_ru=$bytes_received sent_to_origin=$upstream_bytes_sent recv_from_origin=$upstream_bytes_received connect=$upstream_connect_time duration=$session_time';\n"
        "  map $ssl_preread_server_name $meta_origin {\n"
        "    default 127.0.0.1:1;\n"
        + map_entries +
        "    "+META_NGINX_PATTERN+" $ssl_preread_server_name:443;\n"
        "  }\n"
        "  server {\n"
        "    listen "+WG_PRIVATE+";\n"
        "    ssl_preread on;\n"
        "    proxy_pass $meta_origin;\n"
        "    proxy_connect_timeout 7s;\n"
        "    proxy_timeout 90s;\n"
        "    proxy_buffer_size 16k;\n"
        "    access_log /dev/stdout meta_stage;\n"
        "  }\n"
        "}\n"
    )

def self_test() -> None:
    assert len(EXACT) == 17 and len(SUFFIXES) == 17
    assert all(re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+",name) for name in EXACT)
    core = ("tls://.:853 {\n"
            "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
            "    cache 30\n"
            "    forward . tls://9.9.9.9 {}\n}\n")
    modified = render_dns(core)
    assert modified.count("mnebydns-meta-isolated-20261109") == 1
    assert modified.endswith("    cache 30\n"+core.split("    cache 30\n",1)[1])
    assert core.split("    cache 30\n",1)[0] in modified
    assert modified.count("20 IN A "+RU) == len(EXACT)+1
    for host in ("www.instagram.com", "scontent.cdninstagram.com",
                 "graph.threads.net","edge-mqtt.facebook.com","foo.meta.ai"):
        assert re.fullmatch(META_DNS_PATTERN,host+".") is not None or host in EXACT
    for host in ("api.telegram.org","web.telegram.org","t.me",
                 "www.youtube.com","claude.ai","grok.com","x.com","www.tiktok.com"):
        assert re.fullmatch(META_DNS_PATTERN,host+".") is None
    proxy=render_proxy()
    assert "listen "+WG_PRIVATE+";" in proxy
    assert "listen 0.0.0.0" not in proxy and "listen 443;" not in proxy
    assert "default 127.0.0.1:1;" in proxy
    assert "access_log /dev/stdout meta_stage;" in proxy
    assert "sent_to_origin=$upstream_bytes_sent" in proxy
    assert "$remote_addr" not in proxy and "$request" not in proxy
    for blocked in ("telegram.org","googlevideo.com","anthropic.com","tiktokv.com"):
        assert blocked not in proxy
    print("meta_exact_17_dynamic_17_offline=PASS")
    print("five_service_checkpoint_remains_unchanged=PASS")
    print("private_WireGuard_only_fail_closed_sidecar=PASS")

def main() -> None:
    if sys.argv[1:] == ["self-test"]:
        self_test()
        return
    if len(sys.argv)!=4 or sys.argv[1]!="render":
        raise SystemExit("usage: mnebydns-meta-overlay.py self-test | render BASE_CORE OUTPUT_DIR")
    base=pathlib.Path(sys.argv[2])
    target=pathlib.Path(sys.argv[3])
    if not base.is_file() or base.is_symlink() or not target.is_dir() or target.is_symlink():
        raise ValueError("Unsafe input or output")
    for name,body in (("dns.pilot",render_dns(base.read_text())),
                      ("proxy.meta",render_proxy())):
        dst=target/name
        with dst.open("x",encoding="utf-8") as fh:
            fh.write(body)
        dst.chmod(0o600)
    print("meta_overlay_staged_without_any_server_changes=true")

if __name__=="__main__":
    main()
