#!/usr/bin/env python3
"""Add ChatGPT to the SAME German MNEBYDNS TLS/SNI relay as Claude and Google.

Additive, offline renderer only. DOES NOT touch production, configure RU,
install a root CA, proxy arbitrary traffic or identify users.
Input must be the exact stable-five checkpoint from 2026-11-09.
"""
from __future__ import annotations
import argparse
import importlib.util
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("mnebydns_stable_renderer", HERE / "mnebydns-stable-five-render.py")
assert spec and spec.loader
stable = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stable)
old = stable.old

DE = "89.125.90.101"
BACKEND = "127.0.0.1:15449"
TAG = "mnebydns-chatgpt-de-only-20261109"
# Primary OpenAI families from its current published network recommendations.
# This is the same DE traffic path used by Claude and Google, not the Meta RU path.
SUFFIXES = ("chatgpt.com", "openai.com", "oaistatic.com",
            "oaiusercontent.com", "oaistatsig.com")
# Third-party shared vendor domains must be EXACT. Never route entire
# cloudflare.com, workos.com, stripe.com, sentry.io or intercomcdn.com.
EXACT = (
    "cdn.openaimerge.com", "cdn.workos.com", "challenges.cloudflare.com",
    "forwarder.workos.com", "frontend-apps-multi-region.workos.com",
    "humb.apple.com", "images.workoscdn.com", "js.intercomcdn.com",
    "js.stripe.com", "o207216.ingest.sentry.io", "o33249.ingest.sentry.io",
    "rum.browser-intake-datadoghq.com", "setup.workos.com",
    "workos.imgix.net", "ct.sendgrid.net",
)
# The app's android.chat.openai.com, WS and file domains match SUFFIXES.
DNS_PATTERN = r"(?i)^(?:[a-z0-9-]+[.])*(?:" + "|".join(
    re.escape(s) for s in SUFFIXES) + r")[.]$"
SNI_PATTERN = r"~*^(?:[a-z0-9-]+\.)*(?:" + "|".join(
    re.escape(s) for s in SUFFIXES) + r")$"
SHARED_MAP = re.compile(
    r"(map\s+\$ssl_preread_server_name\s+\$direct_mtproxy_backend\s*\{)([^{}]*)(\})", re.S
)
ORIGIN_MAP = re.compile(
    r"(map\s+\$ssl_preread_server_name\s+\$experimental_origin\s*\{)([^{}]*)(\})", re.S
)

def additions() -> tuple[str, str]:
    names = "".join(f"        {h} {BACKEND};\n" for h in EXACT)
    return names + f"        {SNI_PATTERN} {BACKEND};\n", (
        "".join(f"        {h} {h}:443;\n" for h in EXACT)
        + f"        {SNI_PATTERN} $ssl_preread_server_name:443;\n"
    )

def extend_map(source: str, pattern: re.Pattern[str], entries: str, owner: str) -> str:
    maps = list(pattern.finditer(source))
    if len(maps) != 1 or TAG in source:
        raise ValueError("Unknown or already modified " + owner + " SNI map")
    body = maps[0].group(2)
    if any(re.search(r"(?m)^\s*" + re.escape(name) + r"\s+\S+;", body)
           for name in EXACT + SUFFIXES):
        raise ValueError("Existing ChatGPT route would be overridden")
    if any(host in body for host in ("openai.com", "chatgpt.com", "oaistatic.com",
                                    "oaiusercontent.com", "oaistatsig.com")):
        raise ValueError("Existing ChatGPT domain policy detected")
    m = maps[0]
    insert = "        # " + TAG + "\n" + entries
    output = source[:m.end(2)] + insert + source[m.end(2):]
    if output.replace(insert, "", 1) != source:
        raise AssertionError("Not an additive SNI edit")
    return output

def render(nginx: str, dns: str, proxy: str) -> dict[str, str]:
    if (nginx.count("gemini.google.com 127.0.0.1:15443;") != 1
        or "claude.ai 127.0.0.1:15449;" not in nginx
        or "www.tiktok.com 127.0.0.1:15449;" not in nginx):
        raise ValueError("Shared German SNI differs from stable-five checkpoint")
    if ("template IN A claude.ai {" not in dns
        or dns.count("    cache 30\n") != 1
        or "20 IN A " + DE not in dns
        or "188.120.254.223" in dns):
        raise ValueError("CoreDNS differs from stable-five checkpoint")
    if ("listen 127.0.0.1:15449;" not in proxy
        or "claude.ai claude.ai:443;" not in proxy
        or "default 127.0.0.1:1;" not in proxy
        or "10.66.77.1:19443" in proxy):
        raise ValueError("German proxy differs from stable-five checkpoint")
    shared_entries, origin_entries = additions()
    out_nginx = extend_map(nginx, SHARED_MAP, shared_entries, "shared")
    out_proxy = extend_map(proxy, ORIGIN_MAP, origin_entries, "foreign")
    addition = "    # " + TAG + "\n"
    for host in EXACT:
        for kind in old.RR:
            addition += old.rr_template(host, kind, ip=DE)
    for kind in old.RR:
        addition += old.rr_template(".", kind, DNS_PATTERN, ip=DE)
    for host in EXACT:
        if re.search(r"(?m)^\s*template IN (?:A|AAAA|HTTPS|SVCB|CNAME)\s+"
                     + re.escape(host) + r"\s*\{", dns):
            raise ValueError("Existing DNS policy for " + host)
    if TAG in dns or re.search(r"(?m)^\s*template IN A (?:chatgpt\.com|openai\.com)\s*\{", dns):
        raise ValueError("ChatGPT DNS policy already exists")
    out_dns = dns.replace("    cache 30\n", addition + "    cache 30\n", 1)
    if out_dns.replace(addition, "", 1) != dns:
        raise AssertionError("Not an additive CoreDNS edit")
    for output in (out_nginx, out_dns, out_proxy):
        if "188.120.254.223" in output and output is out_dns:
            raise AssertionError("RU Meta address introduced into DE DNS")
    for bad in ("instagram.com", "threads.com", "telegram.org"):
        assert bad not in addition and bad not in shared_entries and bad not in origin_entries
    return {"nginx.pilot": out_nginx, "dns.pilot": out_dns, "proxy.pilot": out_proxy}

def self_test() -> None:
    assert len(EXACT) == 15 and len(SUFFIXES) == 5
    assert set(EXACT).isdisjoint(SUFFIXES)
    assert set(SUFFIXES).isdisjoint(set(stable.STABLE_SUFFIXES))
    assert all(re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", host)
               for host in EXACT + SUFFIXES)
    base_shared = ("stream { map $ssl_preread_server_name $direct_mtproxy_backend {\n"
                   " gemini.google.com 127.0.0.1:15443;\n"
                   " claude.ai 127.0.0.1:15449;\n"
                   " www.tiktok.com 127.0.0.1:15449;\n"
                   " default 127.0.0.1:9000;\n}\n}\n")
    base_dns = ("tls://.:853 {\n"
                " template IN A claude.ai { match ^claude[.]ai[.]$ }\n"
                ' template IN A example.test { answer "{{ .Name }} 20 IN A '+DE+'" }\n'
                "    cache 30\n    forward . tls://9.9.9.9 {}\n}\n")
    base_proxy = ("stream { map $ssl_preread_server_name $experimental_origin {\n"
                  " default 127.0.0.1:1;\n claude.ai claude.ai:443;\n}\n"
                  " server { listen 127.0.0.1:15449; }\n}\n")
    out = render(base_shared, base_dns, base_proxy)
    base = {"nginx": base_shared, "dns": base_dns, "proxy": base_proxy}
    for key, text in base.items():
        after = out[key + ".pilot"]
        assert TAG in after
        assert len(after) > len(text)
        assert after.count(TAG) == 1
        assert after.count("claude.ai") >= text.count("claude.ai")
    assert "claude.ai 127.0.0.1:15449;" in out["nginx.pilot"]
    for host in ("chatgpt.com", "ws.chatgpt.com", "android.chat.openai.com",
                 "api.openai.com", "files.oaiusercontent.com", "cdn.oaistatic.com"):
        assert re.fullmatch(DNS_PATTERN, host + ".") is not None
        assert re.fullmatch(SNI_PATTERN[2:], host, re.IGNORECASE) is not None
    for host in ("www.instagram.com", "threads.net", "t.me", "google.com",
                 "claude.ai", "x.com", "www.tiktok.com", "example.com"):
        assert re.fullmatch(DNS_PATTERN, host + ".") is None
    for host in EXACT:
        assert "template IN A " + host + " {" in out["dns.pilot"]
        assert host + " " + host + ":443;" in out["proxy.pilot"]
    assert "cdn.workos.com" in out["nginx.pilot"]
    for bad in ("stripe.com", "cloudflare.com", "workos.com"):
        assert "    " + bad + " 127.0.0.1:15449;" not in out["nginx.pilot"]
    try:
        render(out["nginx.pilot"], out["dns.pilot"], out["proxy.pilot"])
    except ValueError:
        pass
    else:
        raise AssertionError("Duplicate apply unexpectedly succeeded")
    print("chatgpt_DE_with_Claude_Google_routes_OFFLINE_PASS=true")
    print("stable_five_unchanged_additive_overlay=true")
    print("ChatGPT_domains_5_exact_third_party_15=true")
    print("Meta_RU_route_modified=false")

def main() -> None:
    cli = argparse.ArgumentParser()
    cli.add_argument("mode", choices=("self-test", "render"))
    cli.add_argument("inputs", nargs="*")
    args = cli.parse_args()
    if args.mode == "self-test":
        if args.inputs:
            raise SystemExit(2)
        self_test()
        return
    if len(args.inputs) != 4:
        raise SystemExit("render requires stable shared-nginx corefile proxy-nginx output-directory")
    files = [pathlib.Path(p) for p in args.inputs]
    if any(not p.is_file() or p.is_symlink() for p in files[:3]) or not files[3].is_dir():
        raise ValueError("Missing input or output")
    outputs = render(*(p.read_text() for p in files[:3]))
    for name, content in outputs.items():
        target = files[3] / name
        with target.open("x", encoding="utf-8") as fh:
            fh.write(content)
        target.chmod(0o600)
    print("chatgpt_DE_staged_no_production_changes=true")

if __name__ == "__main__":
    main()
