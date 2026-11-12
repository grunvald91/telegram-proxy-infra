#!/usr/bin/env python3
"""Render an all-family Meta -> EXISTING foreign Google ingress experiment.

Pure offline renderer: does NOT SSH, install services, alter the kernel, or
change CoreDNS/Nginx. Inputs are a CURRENT three-file read-only snapshot.
Output is intentionally separate; no automatic deployment is authorized.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re

FOREIGN = "89.125.90.101"
BACKEND = "127.0.0.1:15449"
TAG = "# mnebydns-meta-foreign-family-20261112"
# Established in prior Meta pilot: entire dynamic families, not 11 exact names.
META_SUFFIXES = (
    "instagram.com", "cdninstagram.com", "instagr.am", "ig.me",
    "igsonar.com", "threads.com", "threads.net", "facebook.com",
    "facebook.net", "fbcdn.net", "fbsbx.com", "fb.com",
    "meta.com", "meta.ai", "instagramstatic.com", "igcdn.com", "fbcdn.com",
)
# Only these observed/previously researched shared-CDN hostnames, NOT
# the entire akamaihd.net namespace (other customers use it).
META_EXACT = (
    "instagramstatic-a.akamaihd.net",
    "igcdn-photos-e-a.akamaihd.net",
    "igcdn-videos-a-0-a.akamaihd.net",
)
Q_TYPES = ("A", "AAAA", "HTTPS", "SVCB", "CNAME")

def patterns() -> tuple[str, str]:
    suffix = "|".join(re.escape(z) for z in META_SUFFIXES)
    exact = "|".join(re.escape(z) for z in META_EXACT)
    # CoreDNS template uses Go/RE2, nginx stream map uses PCRE.
    dns = r"(?i)^(?:(?:[a-z0-9-]+[.])*(?:" + suffix + r")|(?:" + exact + r"))[.]$"
    nginx = r"~*^(?:(?:[a-z0-9-]+\.)*(?:" + suffix + r")|(?:" + exact + r"))$"
    return dns, nginx

def belongs_to_meta(host: str) -> bool:
    h = host.lower().rstrip(".")
    return (h in META_EXACT or
            any(h == z or h.endswith("." + z) for z in META_SUFFIXES))

def preflight() -> None:
    assert len(META_SUFFIXES) == 17
    assert len(set(META_SUFFIXES)) == len(META_SUFFIXES)
    assert len(set(META_EXACT)) == len(META_EXACT)
    assert not (set(META_SUFFIXES) & set(META_EXACT))
    dns, nginx = patterns()
    good = (
        "instagram.com", "www.instagram.com", "i.instagram.com",
        "iglite-z.instagram.com", "graph.instagram.com",
        "scontent.cdninstagram.com", "video.cdninstagram.com",
        "graph.facebook.com", "z-m-gateway.facebook.com",
        "scontent.xx.fbcdn.net", "static.xx.fbcdn.net",
        "graph.threads.net", "threads.com", "abc.instagramstatic.com",
        "instagramstatic-a.akamaihd.net",
        "igcdn-photos-e-a.akamaihd.net",
    )
    bad = (
        "youtube.com", "r3---sn-a.googlevideo.com", "accounts.google.com",
        "gemini.google.com", "antigravity.google", "claude.ai", "api.x.ai",
        "api.telegram.org", "example.org", "evilinstagram.com",
        "scontent.evilfacebook.com", "akamaihd.net", "www.akamaihd.net",
        "i.instagram.com.evil.com",
    )
    for host in good:
        assert belongs_to_meta(host), host
        assert re.fullmatch(dns, host + "."), host
        assert re.fullmatch(nginx[2:], host, flags=re.IGNORECASE), host
    for host in bad:
        assert not belongs_to_meta(host), host
        assert not re.fullmatch(dns, host + "."), host
        assert not re.fullmatch(nginx[2:], host, flags=re.IGNORECASE), host

def _map_add(source: str, variable: str, destination: str) -> str:
    if TAG in source:
        raise ValueError("Meta overlay already installed; refuse duplicate")
    pattern = re.compile(
        r"(map\s+\$ssl_preread_server_name\s+\$" +
        re.escape(variable) + r"\s*\{)([^{}]*)(\})", re.S
    )
    matches = list(pattern.finditer(source))
    if len(matches) != 1:
        raise ValueError("Expected exactly one existing SNI map for " + variable)
    m = matches[0]
    body = m.group(2)
    if not re.search(r"(?m)^\s*default\s+\S+;", body):
        raise ValueError("SNI map has no default backend")
    # Do not silently override other ownership, including old Meta pilots.
    flattened = body.replace(r"\.", ".")
    if any(z in flattened for z in META_SUFFIXES):
        raise ValueError("Meta SNI family already owned by another map entry")
    if destination == BACKEND and "127.0.0.1:15449" not in source:
        raise ValueError("Shared Nginx does not already have GooglePilot backend")
    if destination == "$ssl_preread_server_name:443":
        if not re.search(r"\bresolver\s+\S+", source):
            raise ValueError("GooglePilot lacks an origin DNS resolver")
        if not re.search(r"(?m)^\s*ssl_preread\s+on\s*;", source):
            raise ValueError("GooglePilot TLS passthrough not verified")
    _, expr = patterns()
    addition = "\n    " + TAG + "\n    " + expr + " " + destination + ";\n"
    return source[:m.end(2)] + addition + source[m.end(2):]

def render_shared_nginx(source: str) -> str:
    return _map_add(source, "direct_mtproxy_backend", BACKEND)

def render_googlepilot(source: str) -> str:
    return _map_add(source, "experimental_origin",
                    "$ssl_preread_server_name:443")

def render_coredns(source: str) -> str:
    if TAG in source:
        raise ValueError("Meta DNS overlay already installed")
    if "template IN A gemini.google.com {" not in source:
        raise ValueError("Missing live Google SmartDNS baseline")
    # Match the same CoreDNS insertion point used by the successful Google pilot.
    marker = "    cache 30\n"
    if source.count(marker) != 1:
        raise ValueError("CoreDNS template structure changed")
    # A prior Meta DNS overlay must be reviewed and removed by its owner first.
    if any(z in source.replace(r"\.", ".") for z in META_SUFFIXES):
        raise ValueError("Existing Meta DNS policy must not be shadowed")
    regex, _ = patterns()
    insertion = "\n    " + TAG + " -- DNS A => foreign ingress, no alternate direct records\n"
    for kind in Q_TYPES:
        insertion += "    template IN " + kind + " . {\n"
        insertion += "        match " + regex + "\n"
        if kind == "A":
            insertion += '        answer "{{ .Name }} 20 IN A ' + FOREIGN + '"\n'
        else:
            insertion += "        rcode NOERROR\n"
        insertion += "        fallthrough\n    }\n"
    return source.replace(marker, insertion + marker, 1)

def render(dns: str, shared: str, pilot: str) -> dict[str, str]:
    preflight()
    new_dns = render_coredns(dns)
    new_shared = render_shared_nginx(shared)
    new_pilot = render_googlepilot(pilot)
    assert "www.youtube.com 127.0.0.1:15449;" in new_shared if (
        "www.youtube.com 127.0.0.1:15449;" in shared) else True
    assert "www.youtube.com" in new_shared if "www.youtube.com" in shared else True
    assert "gemini.google.com" in new_dns
    return {"Corefile.meta-candidate": new_dns,
            "nginx.meta-candidate": new_shared,
            "googlepilot.meta-candidate": new_pilot}

def self_test() -> None:
    preflight()
    core = ("tls://.:853 {\n"
            "    template IN A gemini.google.com { match ^gemini[.]google[.]com[.]$ }\n"
            "    cache 30\n"
            "    forward . tls://9.9.9.9 {}\n}\n")
    shared = ("stream {\n"
              "  map $ssl_preread_server_name $direct_mtproxy_backend {\n"
              "    default 127.0.0.1:9443;\n"
              "    www.youtube.com 127.0.0.1:15449;\n  }\n"
              "  server { ssl_preread on; proxy_pass $direct_mtproxy_backend; }\n}\n")
    pilot = ("stream {\n"
             "  resolver 9.9.9.9 ipv6=off valid=30s;\n"
             "  map $ssl_preread_server_name $experimental_origin {\n"
             "    default 127.0.0.1:1;\n"
             "    www.youtube.com www.youtube.com:443;\n  }\n"
             "  server {\n    ssl_preread on;\n    proxy_pass $experimental_origin;\n  }\n}\n")
    out = render(core, shared, pilot)
    assert len(out) == 3
    assert "20 IN A " + FOREIGN in out["Corefile.meta-candidate"]
    assert out["Corefile.meta-candidate"].count(TAG) == 1
    assert "www.youtube.com 127.0.0.1:15449;" in out["nginx.meta-candidate"]
    assert "www.youtube.com www.youtube.com:443;" in out["googlepilot.meta-candidate"]
    for candidate in out.values():
        assert TAG in candidate
    for func, src in ((render_coredns, out["Corefile.meta-candidate"]),
                      (render_shared_nginx, out["nginx.meta-candidate"]),
                      (render_googlepilot, out["googlepilot.meta-candidate"])):
        try:
            func(src)
        except ValueError:
            pass
        else:
            raise AssertionError("Duplicate overlay not rejected")
    for x in ("youtube.com", "gemini.google.com", "api.telegram.org"):
        assert not belongs_to_meta(x)
    print("meta_foreign_17_suffix_3_shared_cdn_offline=PASS")
    print("meta_foreign_existing_google_routes_unchanged=PASS")
    print("meta_foreign_duplicate_and_nonmeta_rejected=PASS")
    print("meta_foreign_production_change=false")

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("self-test")
    p = subs.add_parser("render")
    p.add_argument("--dns", required=True, type=pathlib.Path)
    p.add_argument("--shared-nginx", required=True, type=pathlib.Path)
    p.add_argument("--googlepilot", required=True, type=pathlib.Path)
    p.add_argument("--out-dir", required=True, type=pathlib.Path)
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return
    sources = (args.dns, args.shared_nginx, args.googlepilot)
    for path in sources:
        if not path.is_file() or path.is_symlink():
            raise ValueError("Current config snapshot missing or symlinked")
    if not args.out_dir.is_dir() or args.out_dir.is_symlink():
        raise ValueError("Output directory must exist and not be a symlink")
    if any(path.resolve().is_relative_to(args.out_dir.resolve()) for path in sources):
        raise ValueError("Output must not overlap sources")
    candidate = render(*(path.read_text() for path in sources))
    for name, body in candidate.items():
        dest = args.out_dir / name
        with dest.open("x", encoding="utf-8") as fh:
            fh.write(body)
        dest.chmod(0o600)
    manifest = {
        "status": "RENDER_ONLY_NOT_DEPLOYED",
        "foreign_ingress": FOREIGN,
        "shared_backend": BACKEND,
        "meta_suffix_count": len(META_SUFFIXES),
        "shared_cdn_exact_count": len(META_EXACT),
        "protocol": "TCP/443 only: UDP/443 QUIC is NOT covered",
        "outputs": list(candidate.keys()),
    }
    with (args.out_dir / "meta-manifest.json").open("x", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)
    print(json.dumps(manifest, ensure_ascii=False))

if __name__ == "__main__":
    main()
