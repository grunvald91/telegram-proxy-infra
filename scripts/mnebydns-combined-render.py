#!/usr/bin/env python3
"""Staged three-app canary: ChatGPT via DE Claude/Google; Meta via RU/WG/DE.

This renderer does not change production. Baseline is the exact DE stable-five
checkpoint: nginx.stable, dns.stable, proxy.stable.
Outputs only additive DNS and German ChatGPT routes plus an isolated
private-WireGuard Meta sidecar. Both routes are strictly TLS SNI passthrough.
"""
from __future__ import annotations
import argparse
import importlib.util
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent

def load(filename: str, label: str):
    spec = importlib.util.spec_from_file_location(label, HERE / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

chat = load("mnebydns-chatgpt-de-overlay.py", "mnebydns_chatgpt_de")
meta = load("mnebydns-meta-overlay.py", "mnebydns_meta_isolated")
stable = chat.stable
RU = "188.120.254.223"
DE = "89.125.90.101"

def render(shared: str, dns: str, proxy: str) -> dict[str, str]:
    chatgpt = chat.render(shared, dns, proxy)
    combined_dns = meta.render_dns(chatgpt["dns.pilot"])
    meta_proxy = meta.render_proxy()
    result = {**chatgpt, "dns.pilot": combined_dns, "proxy.meta": meta_proxy}
    assert len(result) == 4
    # The Meta domains use ONLY RU entry + the private DE sidecar. The German
    # public nginx and DE five-service proxy are never assigned Meta domains.
    for key in ("nginx.pilot", "proxy.pilot"):
        if any(word in result[key] for word in ("instagram.com", "threads.com",
                                                "cdninstagram.com", "telegram.org")):
            raise AssertionError("Meta or Telegram leaked into public DE route")
    if RU in result["nginx.pilot"] or RU in result["proxy.pilot"]:
        raise AssertionError("RU entry in German public proxy")
    if "chatgpt.com" in result["proxy.meta"] or "openai.com" in result["proxy.meta"]:
        raise AssertionError("ChatGPT incorrectly assigned to RU / Meta sidecar")
    if "20 IN A " + RU not in combined_dns:
        raise AssertionError("Missing Meta RU DNS rewriting")
    if "20 IN A " + DE not in combined_dns:
        raise AssertionError("Missing German ChatGPT DNS rewriting")
    if "127.0.0.1:15449;" not in result["nginx.pilot"]:
        raise AssertionError("Missing German Claude and ChatGPT backend")
    if "listen 10.66.77.1:19443;" not in meta_proxy:
        raise AssertionError("Missing private Meta backend")
    for source, file in ((shared, "nginx.pilot"), (proxy, "proxy.pilot"),
                         (dns, "dns.pilot")):
        if source == result[file]:
            raise AssertionError("Combined config not additive")
    return result

def self_test() -> None:
    chat.self_test()
    meta.self_test()
    shared = (
        "stream { map $ssl_preread_server_name $direct_mtproxy_backend {\n"
        "gemini.google.com 127.0.0.1:15443;\n"
        "claude.ai 127.0.0.1:15449;\n"
        "www.tiktok.com 127.0.0.1:15449;\n"
        "default 127.0.0.1:9000;\n"
        "} }\n"
    )
    dns = (
        "tls://.:853 {\n"
        " template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
        " template IN A claude.ai { match ^claude[.]ai[.]$ }\n"
        ' template IN A example.test { answer "{{ .Name }} 20 IN A 89.125.90.101" }\n'
        "    cache 30\n"
        "    forward . tls://9.9.9.9 {}\n}\n"
    )
    proxy = (
        "stream { map $ssl_preread_server_name $experimental_origin {\n"
        "default 127.0.0.1:1;\n"
        "claude.ai claude.ai:443;\n"
        "}\nserver { listen 127.0.0.1:15449; }\n}\n"
    )
    out = render(shared, dns, proxy)
    assert len(out) == 4
    assert out["dns.pilot"].count("mnebydns-chatgpt-de-only-20261109") == 1
    assert out["dns.pilot"].count("mnebydns-meta-isolated-20261109") == 1
    assert out["nginx.pilot"].count("mnebydns-chatgpt-de-only-20261109") == 1
    assert out["proxy.pilot"].count("mnebydns-chatgpt-de-only-20261109") == 1
    assert "gemini.google.com 127.0.0.1:15443;" in out["nginx.pilot"]
    assert "claude.ai claude.ai:443;" in out["proxy.pilot"]
    assert "www.tiktok.com 127.0.0.1:15449;" in out["nginx.pilot"]
    assert out["dns.pilot"].count("template IN A . {") >= 2
    assert "api.telegram.org" not in out["dns.pilot"]
    try:
        render(out["nginx.pilot"], out["dns.pilot"], out["proxy.pilot"])
    except (ValueError, AssertionError):
        pass
    else:
        raise AssertionError("Double application must fail closed")
    print("three_apps_combined_source_selftest=PASS")
    print("ChatGPT_DE_Claude_Google_same_path=true")
    print("Meta_RU_to_private_DE_only=true")
    print("no_live_production_changes=true")

def main() -> None:
    arg = argparse.ArgumentParser()
    arg.add_argument("mode", choices=("self-test","render"))
    arg.add_argument("inputs", nargs="*")
    a = arg.parse_args()
    if a.mode == "self-test":
        if a.inputs:
            raise SystemExit(2)
        self_test()
        return
    if len(a.inputs) != 4:
        raise SystemExit("render shared-nginx corefile five-proxy output-directory")
    files = [pathlib.Path(p) for p in a.inputs]
    if any(not f.is_file() or f.is_symlink() for f in files[:3]):
        raise ValueError("Input must be three regular baseline files")
    target_dir = files[3]
    if not target_dir.is_dir() or target_dir.is_symlink():
        raise ValueError("Invalid output directory")
    output = render(*(f.read_text() for f in files[:3]))
    if any((target_dir / name).exists() for name in output):
        raise ValueError("Refusing to overwrite prior rollout")
    for name, value in output.items():
        with (target_dir / name).open("x", encoding="utf-8") as file:
            file.write(value)
        (target_dir / name).chmod(0o600)
    print("staged_combined_files=" + ",".join(sorted(output)))

if __name__ == "__main__":
    main()
