#!/usr/bin/env python3
"""CoreDNS Corefile + Apple mobileconfig cutover helper for RU188 public ingress.

Rewrites every Smart DNS synthetic ``answer "{{ .Name }} <ttl> IN A 89.125.90.101"``
across all CoreDNS server blocks to ``188.120.254.223`` while preserving every
``bind 89.125.90.101`` directive, TLS/reload/cache/forward/FI217 stanza, and
non-A RR rules unchanged. Also builds an isolated loopback preflight Corefile
and updates ``DNSSettings.ServerAddresses`` in the Apple ``.mobileconfig`` plist.
"""
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
from pathlib import Path
import plistlib
import re
import secrets
import socket
import ssl
import struct
import sys

DE_IP = "89.125.90.101"
RU_IP = "188.120.254.223"
FI_IP = "217.11.167.91"
DOT_TLS_NAME = "dns.mnebyvpn.site"

PREFLIGHT_MAPPED_HOSTS = (
    "www.youtube.com",
    "claude.ai",
    "api.openai.com",
    "chatgpt.com",
    "x.com",
    "www.tiktok.com",
    "www.google.com",
    "gemini.google.com",
    "generativelanguage.googleapis.com",
    "play.googleapis.com",
)
PREFLIGHT_DIRECT_HOSTS = ("example.org", "api.telegram.org", "stun.l.google.com", "mtalk.google.com")
LIVE_DOT_HOSTS = ("www.youtube.com", "claude.ai", "www.google.com")

ANSWER_DE_RE = re.compile(
    r'(?m)^(?P<prefix>[ \t]*answer[ \t]+"\{\{[ \t]*\.Name[ \t]*\}\}[ \t]+[0-9]+[ \t]+IN[ \t]+A[ \t]+)'
    + re.escape(DE_IP)
    + r'(?P<suffix>"[ \t]*(?:#.*)?)$'
)
ANSWER_RU_RE = re.compile(
    r'(?m)^[ \t]*answer[ \t]+"\{\{[ \t]*\.Name[ \t]*\}\}[ \t]+[0-9]+[ \t]+IN[ \t]+A[ \t]+'
    + re.escape(RU_IP)
    + r'"[ \t]*(?:#.*)?$'
)
REMAINING_DE_A_RE = re.compile(r"(?m)\bIN[ \t]+A[ \t]+" + re.escape(DE_IP) + r"\b")
BIND_DE_RE = re.compile(r"(?m)^[ \t]*bind[ \t]+" + re.escape(DE_IP) + r"(?:[ \t].*)?$")
TLS_HEADER_RE = re.compile(r"(?m)^[ \t]*(?:tls://\S+:853(?=[ \t]+\S|[ \t]*\{)|tls://[^\s{}]+)")
TEMPLATE_HEADER_RE = re.compile(
    r"(?m)^[ \t]*template[ \t]+IN[ \t]+(?:A|AAAA|HTTPS|SVCB|CNAME|ANY)(?:[ \t]+[^\s{}]+)?[ \t]*\{"
)
FORWARD_LINE_RE = re.compile(r"(?m)^[ \t]*forward[ \t]+.*$")
SERVER_HEADER_RE = re.compile(r"^([ \t]*)(.+?)([ \t]*\{[ \t]*(?:#.*)?)$")
BIND_LINE_RE = re.compile(r"^([ \t]*bind[ \t]+)(.+?)([ \t]*(?:#.*)?)$")
SERVER_ADDR_BLOCK_RE = re.compile(
    r"(<key>ServerAddresses</key>\s*<array>)(.*?)(</array>)",
    re.DOTALL,
)


def _strip_comment(line: str) -> str:
    in_quote = False
    escaped = False
    for idx, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quote:
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch == "#" and not in_quote and (idx == 0 or line[idx - 1].isspace()):
            return line[:idx]
    return line


def _brace_delta(line: str) -> int:
    delta = 0
    in_quote = False
    escaped = False
    clean = _strip_comment(line)
    for ch in clean:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quote:
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if not in_quote:
            if ch == "{":
                delta += 1
            elif ch == "}":
                delta -= 1
    return delta


def _count_server_blocks(core: str) -> list[str]:
    depth = 0
    headers: list[str] = []
    for raw_line in core.splitlines():
        stripped = _strip_comment(raw_line).strip()
        if depth == 0 and stripped.endswith("{"):
            headers.append(stripped)
        depth += _brace_delta(raw_line)
        if depth < 0:
            raise ValueError("Unbalanced closing brace in Corefile")
    if depth != 0:
        raise ValueError("Unclosed brace in Corefile")
    return headers


def rewrite_corefile(core: str, *, min_rewrites: int = 600) -> tuple[str, dict]:
    """Rewrite DE_IP synthetic A answers to RU_IP while keeping DE89 binds intact."""
    if not isinstance(core, str) or not core.strip():
        raise ValueError("Corefile is empty")
    headers_before = _count_server_blocks(core)
    if not headers_before:
        raise ValueError("No CoreDNS server blocks found")

    bind_before = len(BIND_DE_RE.findall(core))
    if bind_before < 1:
        raise ValueError(f"Expected at least 1 'bind {DE_IP}' directive")

    templates_before = len(TEMPLATE_HEADER_RE.findall(core))
    forwards_before = FORWARD_LINE_RE.findall(core)
    fi_before = core.count(FI_IP)
    reload_before = len(re.findall(r"(?m)^[ \t]*reload[ \t]+5s[ \t]+1s[ \t]*$", core))
    ru_answers_before = len(ANSWER_RU_RE.findall(core))

    new_core, rewrite_count = ANSWER_DE_RE.subn(
        lambda m: f"{m.group('prefix')}{RU_IP}{m.group('suffix')}",
        core,
    )
    if rewrite_count < min_rewrites:
        raise ValueError(
            f"Expected at least {min_rewrites} rewritten IN A {DE_IP} lines, got {rewrite_count}"
        )
    if REMAINING_DE_A_RE.search(new_core):
        raise ValueError(f"Residual IN A {DE_IP} record remained after rewrite")

    headers_after = _count_server_blocks(new_core)
    if headers_after != headers_before:
        raise ValueError("CoreDNS server block headers changed unexpectedly")

    bind_after = len(BIND_DE_RE.findall(new_core))
    if bind_after != bind_before:
        raise ValueError(f"bind {DE_IP} count drifted ({bind_before} -> {bind_after})")

    templates_after = len(TEMPLATE_HEADER_RE.findall(new_core))
    if templates_after != templates_before:
        raise ValueError(f"Template block count drifted ({templates_before} -> {templates_after})")

    if FORWARD_LINE_RE.findall(new_core) != forwards_before:
        raise ValueError("Upstream forward stanzas drifted")
    if new_core.count(FI_IP) != fi_before:
        raise ValueError("FI217 references drifted")
    if len(re.findall(r"(?m)^[ \t]*reload[ \t]+5s[ \t]+1s[ \t]*$", new_core)) != reload_before:
        raise ValueError("reload 5s 1s directive drifted")

    old_lines = core.splitlines(keepends=True)
    new_lines = new_core.splitlines(keepends=True)
    if len(old_lines) != len(new_lines):
        raise ValueError("Line count drifted during rewrite")
    changed_lines = 0
    for old_line, new_line in zip(old_lines, new_lines):
        if old_line != new_line:
            expected_line, count = ANSWER_DE_RE.subn(
                lambda m: f"{m.group('prefix')}{RU_IP}{m.group('suffix')}",
                old_line,
            )
            if count != 1 or expected_line != new_line:
                raise ValueError("Unexpected non-answer line modification detected")
            changed_lines += 1
    if changed_lines != rewrite_count:
        raise ValueError("Changed line count mismatch")

    ru_answers_after = len(ANSWER_RU_RE.findall(new_core))
    if ru_answers_after != ru_answers_before + rewrite_count:
        raise ValueError("Post-rewrite RU A answer count mismatch")

    stats = {
        "server_blocks": len(headers_after),
        "bind_de_count": bind_after,
        "template_blocks": templates_after,
        "rewritten_a_count": rewrite_count,
        "total_ru_a_count": ru_answers_after,
        "fi217_count": fi_before,
        "reload_count": reload_before,
    }
    return new_core, stats


def make_preflight_corefile(
    core: str,
    *,
    preflight_port: int = 18553,
    preflight_bind: str = "127.0.0.1",
) -> str:
    """Convert a multi-block DoT Corefile into an isolated plain-DNS loopback config."""
    headers_orig = _count_server_blocks(core)
    bind_orig = len(BIND_DE_RE.findall(core))
    if bind_orig < 1:
        raise ValueError(f"Expected at least 1 'bind {DE_IP}' directive for preflight")

    out: list[str] = []
    depth = 0
    skip_block_depth: int | None = None
    converted_blocks = 0
    converted_binds = 0

    for raw_line in core.splitlines(keepends=True):
        line = raw_line.rstrip("\r\n")
        nl = raw_line[len(line):]
        stripped = _strip_comment(line).strip()
        delta = _brace_delta(line)

        if skip_block_depth is not None:
            depth += delta
            if depth < skip_block_depth:
                skip_block_depth = None
            continue

        if depth == 0 and stripped.endswith("{"):
            m = SERVER_HEADER_RE.match(line)
            if not m:
                raise ValueError(f"Unparseable CoreDNS server block header: {line!r}")
            new_tokens: list[str] = []
            for tok in m.group(2).split():
                zone = re.sub(r"^(?:tls|dns)://", "", tok)
                zone = re.sub(r":\d+$", "", zone)
                if not zone:
                    raise ValueError(f"Empty zone token in header: {line!r}")
                new_tokens.append(f"{zone}:{preflight_port}")
            out.append(f"{m.group(1)}{' '.join(new_tokens)}{m.group(3)}{nl}")
            converted_blocks += 1
            depth += delta
            continue

        if depth == 1:
            if re.match(r"^tls(?:[ \t]+.*)?$", stripped):
                if stripped.endswith("{"):
                    skip_block_depth = depth + 1
                depth += delta
                continue
            if re.match(r"^reload(?:[ \t]+.*)?$", stripped):
                if stripped.endswith("{"):
                    skip_block_depth = depth + 1
                depth += delta
                continue
            bm = BIND_LINE_RE.match(line)
            if bm:
                new_addrs, n_sub = re.subn(
                    r"\b" + re.escape(DE_IP) + r"\b",
                    preflight_bind,
                    bm.group(2),
                )
                if n_sub:
                    converted_binds += n_sub
                    out.append(f"{bm.group(1)}{new_addrs}{bm.group(3)}{nl}")
                    depth += delta
                    continue

        out.append(raw_line)
        depth += delta

    if depth != 0 or skip_block_depth is not None:
        raise ValueError("Unbalanced braces after preflight transform")
    if converted_blocks != len(headers_orig):
        raise ValueError(f"Server block conversion mismatch ({converted_blocks} vs {len(headers_orig)})")
    if converted_binds != bind_orig:
        raise ValueError(f"Preflight bind conversion mismatch ({converted_binds} vs {bind_orig})")

    result = "".join(out)
    if re.search(r"(?m)^[ \t]*tls://", result):
        raise ValueError("Residual tls:// server header in preflight Corefile")
    if re.search(r"(?m)^[ \t]*tls(?:[ \t]+|$)", result):
        raise ValueError("Residual tls directive in preflight Corefile")
    if re.search(r"(?m)^[ \t]*reload(?:[ \t]+|$)", result):
        raise ValueError("Residual reload directive in preflight Corefile")
    if BIND_DE_RE.search(result):
        raise ValueError(f"Residual bind {DE_IP} in preflight Corefile")
    _count_server_blocks(result)
    return result


def update_mobileconfig(src_text: str) -> tuple[str, dict]:
    """Update DNSSettings.ServerAddresses in Apple .mobileconfig from DE_IP to RU_IP."""
    before = plistlib.loads(src_text.encode("utf-8"))
    entries = before.get("PayloadContent")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Invalid mobileconfig: missing PayloadContent")
    dns_settings = entries[0].get("DNSSettings")
    if not isinstance(dns_settings, dict):
        raise ValueError("Invalid mobileconfig: missing DNSSettings")
    if dns_settings.get("ServerName") != DOT_TLS_NAME:
        raise ValueError("Unexpected mobileconfig ServerName")
    if dns_settings.get("ServerAddresses") != [DE_IP]:
        raise ValueError(f"Expected ServerAddresses [{DE_IP}], got {dns_settings.get('ServerAddresses')!r}")

    matches = list(SERVER_ADDR_BLOCK_RE.finditer(src_text))
    if len(matches) != 1:
        raise ValueError(f"Expected 1 ServerAddresses array in mobileconfig, found {len(matches)}")
    m = matches[0]
    inner = m.group(2)
    target_tag = f"<string>{DE_IP}</string>"
    replacement_tag = f"<string>{RU_IP}</string>"
    if inner.count(target_tag) != 1:
        raise ValueError("Expected single DE_IP <string> inside ServerAddresses")
    new_inner = inner.replace(target_tag, replacement_tag, 1)
    updated_text = src_text[: m.start(2)] + new_inner + src_text[m.end(2) :]

    after = plistlib.loads(updated_text.encode("utf-8"))
    after_dns = after["PayloadContent"][0]["DNSSettings"]
    if after_dns.get("ServerAddresses") != [RU_IP]:
        raise ValueError("Updated mobileconfig ServerAddresses validation failed")
    if after_dns.get("ServerName") != DOT_TLS_NAME:
        raise ValueError("Updated mobileconfig ServerName drifted")
    if DE_IP in updated_text:
        raise ValueError("Residual DE_IP remained in mobileconfig")
    return updated_text, {
        "server_name": after_dns.get("ServerName"),
        "server_addresses": after_dns.get("ServerAddresses"),
    }


def validate_guard_module(path: Path) -> dict:
    """Import and verify staged mnebydns_dns_policy_guard.py constants."""
    spec = importlib.util.spec_from_file_location("staged_dns_policy_guard", str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load guard module: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if getattr(mod, "RESOLVER_BIND", None) != DE_IP:
        raise RuntimeError(f"Guard RESOLVER_BIND mismatch: {getattr(mod, 'RESOLVER_BIND', None)!r}")
    if getattr(mod, "PIN", None) != RU_IP:
        raise RuntimeError(f"Guard PIN mismatch: {getattr(mod, 'PIN', None)!r}")
    if not callable(getattr(mod, "smoke_check", None)):
        raise RuntimeError("Guard smoke_check missing")
    return {"resolver_bind": mod.RESOLVER_BIND, "pin": mod.PIN}


def _recvn(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Unexpected EOF reading DNS TCP/TLS frame")
        buf.extend(chunk)
    return bytes(buf)


def _skip_dns_name(packet: bytes, pos: int) -> int:
    for _ in range(128):
        if pos >= len(packet):
            raise ValueError("Malformed DNS name offset")
        length = packet[pos]
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(packet):
                raise ValueError("Truncated DNS compression pointer")
            return pos + 2
        if length == 0:
            return pos + 1
        pos += 1 + length
    raise ValueError("DNS name pointer loop")


def build_dns_query(host: str, qtype: int) -> tuple[int, bytes]:
    qid = secrets.randbelow(65535) + 1
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in host.split(".")) + b"\x00"
    payload = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", qtype, 1)
    return qid, payload


def parse_dns_reply(qid: int, resp: bytes) -> dict:
    if len(resp) < 12:
        raise ValueError("Short DNS reply")
    if int.from_bytes(resp[:2], "big") != qid:
        raise ValueError("DNS transaction ID mismatch")
    rcode = resp[3] & 0x0F
    qdcount = struct.unpack_from("!H", resp, 4)[0]
    ancount = struct.unpack_from("!H", resp, 6)[0]
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(resp, offset) + 4
    a_ips: list[str] = []
    answers: list[tuple[int, int, bytes]] = []
    for _ in range(ancount):
        offset = _skip_dns_name(resp, offset)
        typ, cls, _ttl, rdlen = struct.unpack_from("!HHIH", resp, offset)
        offset += 10
        if offset + rdlen > len(resp):
            raise ValueError("Truncated DNS RRDATA")
        rdata = resp[offset : offset + rdlen]
        offset += rdlen
        answers.append((typ, cls, rdata))
        if typ == 1 and cls == 1 and rdlen == 4:
            a_ips.append(str(ipaddress.IPv4Address(rdata)))
    return {"rcode": rcode, "ancount": ancount, "a_ips": a_ips, "answers": answers}


def query_dns_tcp(address: str, port: int, host: str, qtype: int, timeout: float = 5.0) -> dict:
    qid, payload = build_dns_query(host, qtype)
    with socket.create_connection((address, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall(struct.pack("!H", len(payload)) + payload)
        size = struct.unpack("!H", _recvn(conn, 2))[0]
        if not 12 <= size <= 16384:
            raise ValueError(f"Invalid DNS TCP response length: {size}")
        resp = _recvn(conn, size)
    return parse_dns_reply(qid, resp)


def query_dot(
    address: str,
    port: int,
    host: str,
    qtype: int = 1,
    *,
    sni: str = DOT_TLS_NAME,
    timeout: float = 5.0,
) -> dict:
    qid, payload = build_dns_query(host, qtype)
    ctx = ssl.create_default_context()
    with socket.create_connection((address, port), timeout=timeout) as conn:
        conn.settimeout(timeout)
        with ctx.wrap_socket(conn, server_hostname=sni) as tls:
            if not tls.getpeercert():
                raise RuntimeError("Missing TLS certificate on DoT endpoint")
            tls.sendall(struct.pack("!H", len(payload)) + payload)
            size = struct.unpack("!H", _recvn(tls, 2))[0]
            if not 12 <= size <= 16384:
                raise ValueError(f"Invalid DoT response length: {size}")
            resp = _recvn(tls, size)
    return parse_dns_reply(qid, resp)


def verify_preflight_dns(address: str = "127.0.0.1", port: int = 18553) -> dict:
    for host in PREFLIGHT_MAPPED_HOSTS:
        a_res = query_dns_tcp(address, port, host, 1)
        if a_res["rcode"] != 0 or a_res["a_ips"] != [RU_IP]:
            raise RuntimeError(f"Preflight A mismatch for {host}: {a_res}")
        for qtype, label in ((28, "AAAA"), (65, "HTTPS")):
            other = query_dns_tcp(address, port, host, qtype)
            if other["rcode"] != 0 or other["ancount"] != 0:
                raise RuntimeError(f"Preflight {label} expected empty NODATA for {host}: {other}")

    for host in PREFLIGHT_DIRECT_HOSTS:
        d_res = query_dns_tcp(address, port, host, 1)
        if d_res["rcode"] != 0 or not d_res["a_ips"]:
            raise RuntimeError(f"Preflight direct lookup failed for {host}: {d_res}")
        if RU_IP in d_res["a_ips"] or DE_IP in d_res["a_ips"]:
            raise RuntimeError(f"Preflight direct host {host} unexpectedly mapped to SmartDNS IP: {d_res['a_ips']}")

    return {
        "mapped_checked": len(PREFLIGHT_MAPPED_HOSTS),
        "direct_checked": len(PREFLIGHT_DIRECT_HOSTS),
        "expected_ip": RU_IP,
    }


def verify_live_dot(
    address: str = DE_IP,
    port: int = 853,
    hosts: tuple[str, ...] = LIVE_DOT_HOSTS,
    expected_ip: str = RU_IP,
) -> dict:
    for host in hosts:
        res = query_dot(address, port, host, 1)
        if res["rcode"] != 0 or res["a_ips"] != [expected_ip]:
            raise RuntimeError(f"Live DoT mismatch for {host} at {address}:{port}: {res}")
    return {"checked": list(hosts), "address": address, "port": port, "expected_ip": expected_ip}


def _self_test() -> None:
    sample_lines = [
        "tls://.:853 {\n",
        f"    bind {DE_IP}\n",
        "    reload 5s 1s\n",
        "    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n",
    ]
    for i in range(6):
        sample_lines.extend([
            f"    template IN A host{i}.example.com {{\n",
            f"        match ^host{i}[.]example[.]com[.]$\n",
            f'        answer "{{{{ .Name }}}} 20 IN A {DE_IP}"\n',
            "        fallthrough\n",
            "    }\n",
        ])
    sample_lines.extend([
        f"    # FI217 exit {FI_IP}\n",
        "    forward . tls://9.9.9.9 tls://149.112.112.112 {\n",
        "        tls_servername dns.quad9.net\n",
        "    }\n",
        "}\n",
        "tls://stun.l.google.com:853 {\n",
        f"    bind {DE_IP}\n",
        "    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n",
        "    forward . tls://9.9.9.9 tls://149.112.112.112 {\n",
        "        tls_servername dns.quad9.net\n",
        "    }\n",
        "}\n",
        "tls://www.google.com:853 tls://generativelanguage.googleapis.com:853 {\n",
        f"    bind {DE_IP}\n",
        "    tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem\n",
        "    template IN A {\n",
        "        match ^www[.]google[.]com[.]$\n",
        f'        answer "{{{{ .Name }}}} 20 IN A {DE_IP}"\n',
        "    }\n",
        "}\n",
    ])
    sample = "".join(sample_lines)
    rewritten, stats = rewrite_corefile(sample, min_rewrites=7)
    assert stats["rewritten_a_count"] == 7
    assert stats["bind_de_count"] == 3
    assert stats["server_blocks"] == 3
    preflight = make_preflight_corefile(rewritten)
    assert ".:18553 {" in preflight
    assert "stun.l.google.com:18553 {" in preflight
    assert "www.google.com:18553 generativelanguage.googleapis.com:18553 {" in preflight
    assert preflight.count("bind 127.0.0.1") == 3
    assert "reload 5s 1s" not in preflight
    assert "/run/credentials/" not in preflight
    print("COREFILE_RU188_CUTOVER_SELFTEST=PASS")


def main() -> None:
    if sys.argv[1:] == ["--self-test"]:
        _self_test()
        return

    parser = argparse.ArgumentParser(description="MNEBYDNS RU188 Corefile & mobileconfig helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rw = sub.add_parser("rewrite")
    p_rw.add_argument("--input", type=Path, required=True)
    p_rw.add_argument("--output", type=Path, required=True)
    p_rw.add_argument("--min-rewrites", type=int, default=600)

    p_pf = sub.add_parser("preflight")
    p_pf.add_argument("--input", type=Path, required=True)
    p_pf.add_argument("--output", type=Path, required=True)
    p_pf.add_argument("--port", type=int, default=18553)
    p_pf.add_argument("--bind", default="127.0.0.1")

    p_mc = sub.add_parser("mobileconfig")
    p_mc.add_argument("--input", type=Path, required=True)
    p_mc.add_argument("--output", type=Path, required=True)

    p_pp = sub.add_parser("probe-preflight")
    p_pp.add_argument("--address", default="127.0.0.1")
    p_pp.add_argument("--port", type=int, default=18553)

    p_pd = sub.add_parser("probe-dot")
    p_pd.add_argument("--address", default=DE_IP)
    p_pd.add_argument("--port", type=int, default=853)
    p_pd.add_argument("--expected-ip", default=RU_IP)
    p_pd.add_argument("--hosts", nargs="+", default=list(LIVE_DOT_HOSTS))

    p_vg = sub.add_parser("validate-guard")
    p_vg.add_argument("--path", type=Path, required=True)

    args = parser.parse_args()
    if args.cmd == "rewrite":
        out_text, stats = rewrite_corefile(
            args.input.read_text(encoding="utf-8"),
            min_rewrites=args.min_rewrites,
        )
        args.output.write_text(out_text, encoding="utf-8")
        print(json.dumps(stats, sort_keys=True))
    elif args.cmd == "preflight":
        pf_text = make_preflight_corefile(
            args.input.read_text(encoding="utf-8"),
            preflight_port=args.port,
            preflight_bind=args.bind,
        )
        args.output.write_text(pf_text, encoding="utf-8")
        args.output.chmod(0o600)
        print(json.dumps({"preflight_port": args.port, "preflight_bind": args.bind}, sort_keys=True))
    elif args.cmd == "mobileconfig":
        mc_text, info = update_mobileconfig(args.input.read_text(encoding="utf-8"))
        args.output.write_text(mc_text, encoding="utf-8")
        print(json.dumps(info, sort_keys=True))
    elif args.cmd == "probe-preflight":
        print(json.dumps(verify_preflight_dns(args.address, args.port), sort_keys=True))
    elif args.cmd == "probe-dot":
        print(
            json.dumps(
                verify_live_dot(
                    args.address,
                    args.port,
                    hosts=tuple(args.hosts),
                    expected_ip=args.expected_ip,
                ),
                sort_keys=True,
            )
        )
    elif args.cmd == "validate-guard":
        print(json.dumps(validate_guard_module(args.path), sort_keys=True))


if __name__ == "__main__":
    main()
