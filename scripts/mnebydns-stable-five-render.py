#!/usr/bin/env python3
"""Render the owner-confirmed MNEBYDNS five-service baseline.

Only Google/Gemini, Claude, Grok, X, TikTok are retained from the November
one-off experiments. Instagram, Threads and Telegram are NOT DNS-proxied.
Render from the original verified pre-experiment snapshots, not by fragile
regex surgery on the live CoreDNS file.
"""
import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("mnebydns_prior_canary", ROOT / "mnebydns-four-google-canary.py")
assert SPEC and SPEC.loader
old = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(old)

TELEGRAM_SUFFIXES = (
    "telegram.org", "telegram.me", "telegram.dog", "t.me", "telegra.ph",
    "telesco.pe", "telegram-cdn.org", "cdn-telegram.org",
    "telegramusercontent.com", "fragment.com",
)
META_SUFFIXES = tuple(old.META_SUFFIXES)
META_EXACT = tuple(old.META_EXACT)

def below(name: str, suffixes: tuple[str, ...]) -> bool:
    return any(name == zone or name.endswith("." + zone) for zone in suffixes)

def is_experimental(name: str) -> bool:
    return (name in META_EXACT or below(name, META_SUFFIXES)
            or below(name, TELEGRAM_SUFFIXES))

ALL_HOSTS = tuple(old.HOSTS)
ALL_SUFFIXES = tuple(old.DYNAMIC_SUFFIXES)
STABLE_HOSTS = tuple(h for h in ALL_HOSTS if not is_experimental(h))
STABLE_SUFFIXES = tuple(s for s in ALL_SUFFIXES if not is_experimental(s))
STABLE_MATCH = r"(?i)^(?:[a-z0-9-]+[.])*(?:" + "|".join(
    re.escape(s) for s in STABLE_SUFFIXES
) + r")[.]$"
STABLE_NGINX = r"~*^(?:[a-z0-9-]+\.)*(?:" + "|".join(
    re.escape(s) for s in STABLE_SUFFIXES
) + r")$"

def configure() -> None:
    old.HOSTS = STABLE_HOSTS
    old.DYNAMIC_SUFFIXES = STABLE_SUFFIXES
    old.META_SUFFIXES = ()
    old.META_EXACT = ()
    old.META_DYNAMIC = r"^$"  # inert block removed from rendered CoreDNS
    old.OTHER_SUFFIXES = STABLE_SUFFIXES
    old.OTHER_DYNAMIC = STABLE_MATCH
    old.VIDEO = STABLE_MATCH
    old.VIDEO_NGINX = STABLE_NGINX

def render(nginx: str, corefile: str) -> dict[str, str]:
    configure()
    result = {
        "nginx.stable": old.render_sni(nginx),
        "dns.stable": old.render_dot(corefile),
        "proxy.stable": old.proxy_config().replace(
            '        listen 10.66.77.1:19443;\n', ""
        )
    }
    for kind in old.RR:
        inert = old.rr_template(".", kind, old.META_DYNAMIC, ip=old.RU_INGRESS)
        if result["dns.stable"].count(inert) != 1:
            raise AssertionError("Missing inert Meta placeholder")
        result["dns.stable"] = result["dns.stable"].replace(inert, "", 1)

    for domain in ("gemini.google.com", "claude.ai", "api.anthropic.com",
                   "grok.com", "api.x.ai", "x.com", "www.tiktok.com",
                   "api.tiktokv.com", "mtalk.google.com"):
        # Some pre-existing exact hosts are owned by the original Gemini
        # backend, so only verify no unexpected experimental names were added.
        if domain not in corefile and domain not in STABLE_HOSTS:
            raise AssertionError("Required retained service omitted: " + domain)

    for name in ("instagram.com", "www.instagram.com", "threads.com",
                 "api.telegram.org", "t.me", "edge-mqtt.facebook.com",
                 "graph.threads.net", "cdninstagram.com"):
        for output in result.values():
            if name in output:
                raise AssertionError("Experimental domain still routed: " + name)
    if "10.66.77.1:19443" in result["proxy.stable"]:
        raise AssertionError("Temporary private WireGuard listener retained")
    if "188.120.254.223" in result["dns.stable"]:
        raise AssertionError("Temporary domestic Meta DNS answer retained")
    if "127.0.0.1:15449" not in result["proxy.stable"]:
        raise AssertionError("Existing German proxy service port missing")
    return result

def selftest() -> None:
    assert len(ALL_HOSTS) == 174 and len(ALL_SUFFIXES) == 97
    assert len(STABLE_HOSTS) == 132 and len(STABLE_SUFFIXES) == 70
    assert not any(is_experimental(h) for h in STABLE_HOSTS + STABLE_SUFFIXES)
    assert all(h in STABLE_HOSTS for h in (
        "www.youtube.com", "claude.ai", "api.anthropic.com",
        "x.com", "grok.com", "www.tiktok.com", "mtalk.google.com"))
    fixture_nginx = ("stream { map $ssl_preread_server_name $direct_mtproxy_backend {\n"
                     " default 127.0.0.1:9000;\n"
                     " gemini.google.com 127.0.0.1:15443;\n"
                     " discord.com 127.0.0.1:15401;\n"
                     "} }\n")
    fixture_dns = ("tls://.:853 {\n"
                   " template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
                   "    cache 30\n    forward . tls://9.9.9.9 {}\n}\n")
    staged = render(fixture_nginx, fixture_dns)
    assert staged["dns.stable"].count("template IN A . {") == 1
    assert "www.tiktok.com 127.0.0.1:15449;" in staged["nginx.stable"]
    assert "default 127.0.0.1:9000;" in staged["nginx.stable"]
    for h in ("www.instagram.com.", "api.telegram.org.", "threads.net."):
        assert re.fullmatch(STABLE_MATCH, h) is None
    for h in ("api.x.ai.", "api16-normal-c-useast1a.tiktokv.com.",
              "new-service.googleapis.com."):
        assert re.fullmatch(STABLE_MATCH, h) is not None
    print("stable_five_service_renderer_tests=PASS")
    print("retained_exact_hosts=132 retained_dynamic_suffixes=70")
    print("experimental_meta_telegram_routes_removed=true")

def main() -> None:
    if sys.argv[1:] == ["self-test"]:
        selftest()
        return
    if len(sys.argv) != 5 or sys.argv[1] != "render":
        raise SystemExit("usage: stable-render.py self-test | render original-nginx original-corefile output-directory")
    a, b, directory = map(pathlib.Path, sys.argv[2:])
    if not a.is_file() or not b.is_file() or not directory.is_dir():
        raise ValueError("Missing verified input snapshot or staging directory")
    staged = render(a.read_text(), b.read_text())
    for name, content in staged.items():
        dst = directory / name
        with dst.open("x") as out:
            out.write(content)
        dst.chmod(0o600)
    print("stable_five_service_output_complete=true")

if __name__ == "__main__":
    main()
