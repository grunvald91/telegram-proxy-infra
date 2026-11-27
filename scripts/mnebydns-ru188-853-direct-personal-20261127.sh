#!/usr/bin/env bash
# RU188 DoT :853 cutover for personal SNIs: point 12-char *.dns.mnebyvpn.site
# directly to local WG listener 10.66.77.2:8858 instead of hairpinning to DE89
# 10.66.77.1:8854. Preserves dns.mnebyvpn.site -> 10.66.77.1:8854,
# default s1_mtproxy, and ports 993/995/465/853 untouched.
set -Eeuo pipefail
umask 077

PHASE="${1:-}"
if [[ -z "$PHASE" ]]; then
  echo "usage: $0 stage|switch|revert|finalize|status|--self-test" >&2
  exit 2
fi

CONF="${MNEBYDNS_RU188_CONF:-/etc/nginx/streams.d/01-mtproxy-stdports.conf}"
RELAY_CONF="${MNEBYDNS_RU188_RELAY_CONF:-/etc/nginx/streams.d/00-mtproxy-relay.conf}"
MOD_STREAM_CONF="${MNEBYDNS_RU188_MOD_STREAM_CONF:-/etc/nginx/modules-enabled/50-mod-stream.conf}"
STREAM_MODULE="${MNEBYDNS_RU188_STREAM_MODULE:-/usr/lib/nginx/modules/ngx_stream_module.so}"
ROOT="${MNEBYDNS_RU188_ROOT:-/opt/mnebydns-ru188-853-direct-20261127}"
SCRIPT="${MNEBYDNS_RU188_SCRIPT:-$ROOT/manage.sh}"
UNIT="${MNEBYDNS_RU188_UNIT:-mnebydns-ru188-853-direct-revert-20261127}"
TIMER="${UNIT}.timer"
WG_DEV="${MNEBYDNS_RU188_WG_DEV:-tg-relay}"
WG_ADDR="${MNEBYDNS_RU188_WG_ADDR:-10.66.77.2}"
PERSONAL_HOST="${MNEBYDNS_RU188_PERSONAL_HOST:-10.66.77.2}"
PERSONAL_PORT="${MNEBYDNS_RU188_PERSONAL_PORT:-8858}"
PROBE_ADDRS="${MNEBYDNS_RU188_PROBE_ADDRS:-127.0.0.1 188.120.254.223}"
PROBE_PORT="${MNEBYDNS_RU188_PROBE_PORT:-853}"
CANARY_PID="${MNEBYDNS_RU188_CANARY_PID:-/run/mnebydns-ru188-853-direct-canary.pid}"
CANARY_PORT="${MNEBYDNS_RU188_CANARY_PORT:-18544}"
AUTO_REVERT_SECONDS="${MNEBYDNS_RU188_AUTO_REVERT_SECONDS:-180}"

render_candidate_py() {
  python3 - "$@" <<'PY'
from __future__ import annotations
import pathlib
import re
import sys

SAMPLE = """# Sample RU188 stream config
map $ssl_preread_server_name $mnebydns_ru853_target {
    dns.mnebyvpn.site 10.66.77.1:8854;
    "~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.1:8854;
    default s1_mtproxy;
}
server { listen 993; listen [::]:993; proxy_pass s1_mtproxy; }
server { listen 995; listen [::]:995; proxy_pass s1_mtproxy; }
server { listen 465; listen [::]:465; proxy_pass s1_mtproxy; }
server {
    listen 853 so_keepalive=30s:10s:3;
    listen [::]:853 so_keepalive=30s:10s:3;
    ssl_preread on;
    proxy_pass $mnebydns_ru853_target;
}
"""

MAP_RE = re.compile(
    r"(?ms)^([ \t]*map[ \t]+\$ssl_preread_server_name[ \t]+\$mnebydns_ru853_target[ \t]*\{.*?\n[ \t]*\})"
)
PERSONAL_LINE_RE = re.compile(
    r'(?m)^([ \t]*"~\*\^\[a-z0-9\]\{12\}\[\.\]dns\[\.\]mnebyvpn\[\.\]site\$"[ \t]+)10\.66\.77\.1:8854([ \t]*;[ \t]*)$'
)
LEGACY_LINE = "dns.mnebyvpn.site 10.66.77.1:8854;"
DEFAULT_LINE = "default s1_mtproxy;"


def transform(
    src_text: str,
    *,
    stream_module: str,
    canary_pid: str,
    canary_port: int,
) -> tuple[str, str]:
    maps = MAP_RE.findall(src_text)
    if len(maps) != 1:
        raise RuntimeError(f"Expected exactly 1 $mnebydns_ru853_target map block, found {len(maps)}")
    old_map = maps[0]
    if old_map.count(LEGACY_LINE) != 1:
        raise RuntimeError("Expected exactly 1 dns.mnebyvpn.site 10.66.77.1:8854; entry")
    if old_map.count(DEFAULT_LINE) != 1:
        raise RuntimeError("Expected exactly 1 default s1_mtproxy; entry")
    personal_hits = PERSONAL_LINE_RE.findall(old_map)
    if len(personal_hits) != 1:
        raise RuntimeError(f"Expected exactly 1 12-char personal SNI entry on 10.66.77.1:8854, found {len(personal_hits)}")

    new_map, n = PERSONAL_LINE_RE.subn(r"\g<1>10.66.77.2:8858\g<2>", old_map, count=1)
    if n != 1 or new_map == old_map:
        raise RuntimeError("Failed to rewrite personal SNI target")

    candidate = src_text.replace(old_map, new_map, 1)

    old_lines = src_text.splitlines(keepends=True)
    new_lines = candidate.splitlines(keepends=True)
    if len(old_lines) != len(new_lines):
        raise RuntimeError("Unexpected line count change")
    diffs = [(a, b) for a, b in zip(old_lines, new_lines) if a != b]
    if len(diffs) != 1:
        raise RuntimeError(f"Expected exactly 1 changed line, got {len(diffs)}")
    if "10.66.77.2:8858;" not in diffs[0][1] or "10.66.77.1:8854;" not in diffs[0][0]:
        raise RuntimeError("Diff line did not match expected personal SNI rewrite")

    for port in ("993", "995", "465", "853"):
        pat = re.compile(rf"(?m)^\s*listen\s+(?:\[::\]:)?{port}\b")
        if len(pat.findall(src_text)) != len(pat.findall(candidate)):
            raise RuntimeError(f"Listener count drifted for port {port}")

    if candidate.count(LEGACY_LINE) != 1 or candidate.count(DEFAULT_LINE) != 1:
        raise RuntimeError("Legacy DNS or default MTProxy route drifted")

    canary = (
        f"load_module {stream_module};\n"
        "user www-data;\n"
        "worker_processes 1;\n"
        f"pid {canary_pid};\n"
        "error_log stderr warn;\n"
        "events { worker_connections 256; }\n"
        "stream {\n"
        "    upstream s1_mtproxy { server 127.0.0.1:9443; }\n"
        f"{new_map}\n"
        "    server {\n"
        f"        listen 127.0.0.1:{canary_port};\n"
        "        ssl_preread on;\n"
        "        proxy_pass $mnebydns_ru853_target;\n"
        "        proxy_connect_timeout 6s;\n"
        "        proxy_timeout 30s;\n"
        "        tcp_nodelay on;\n"
        "    }\n"
        "}\n"
    )
    return candidate, canary


mode = sys.argv[1]
if mode == "--self-test":
    cand, can = transform(
        SAMPLE,
        stream_module="/usr/lib/nginx/modules/ngx_stream_module.so",
        canary_pid="/run/mnebydns-ru188-853-direct-canary.pid",
        canary_port=18544,
    )
    assert '"~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.2:8858;' in cand
    assert "dns.mnebyvpn.site 10.66.77.1:8854;" in cand
    assert "default s1_mtproxy;" in cand
    assert "load_module /usr/lib/nginx/modules/ngx_stream_module.so;" in can
    assert "10.66.77.2:8858;" in can
    print("RU188_853_DIRECT_SELFTEST=PASS")
elif mode == "render":
    src, cand_out, canary_out, stream_mod, pid_path, cport = sys.argv[2:]
    src_text = pathlib.Path(src).read_text(encoding="utf-8")
    cand, can = transform(
        src_text,
        stream_module=stream_mod,
        canary_pid=pid_path,
        canary_port=int(cport),
    )
    p_cand = pathlib.Path(cand_out)
    p_cand.write_text(cand, encoding="utf-8")
    p_cand.chmod(0o600)
    p_can = pathlib.Path(canary_out)
    p_can.write_text(can, encoding="utf-8")
    p_can.chmod(0o600)
    print("RU188_853_DIRECT_CANDIDATE_RENDERED=PASS")
else:
    raise SystemExit(2)
PY
}

if [[ "$PHASE" == "--self-test" ]]; then
  render_candidate_py --self-test
  exit 0
fi

[[ "$(id -u)" == "0" ]] || exit 2

verify_personal_backend() {
  python3 - "$PERSONAL_HOST" "$PERSONAL_PORT" <<'PY'
from __future__ import annotations
import secrets
import socket
import ssl
import struct
import sys

host = sys.argv[1]
port = int(sys.argv[2])


def recvn(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("short DoT frame")
        buf.extend(chunk)
    return bytes(buf)


def dot_query(addr: str, port_num: int, sni: str, qname_str: str) -> tuple[int, int]:
    qid = secrets.randbelow(65535) + 1
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_str.split(".")) + b"\x00"
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    ctx = ssl.create_default_context()
    with socket.create_connection((addr, port_num), timeout=6) as raw:
        raw.settimeout(6)
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            if not tls.getpeercert():
                raise RuntimeError("Missing TLS certificate")
            tls.sendall(struct.pack("!H", len(msg)) + msg)
            hdr = recvn(tls, 2)
            size = struct.unpack("!H", hdr)[0]
            if not 12 <= size <= 16384:
                raise ValueError(f"Invalid DoT response frame size: {size}")
            resp = recvn(tls, size)
    if int.from_bytes(resp[:2], "big") != qid:
        raise ValueError("DoT transaction ID mismatch")
    return resp[3] & 15, struct.unpack_from("!H", resp, 6)[0]


ctx = ssl.create_default_context()
with socket.create_connection((host, port), timeout=6) as raw:
    raw.settimeout(6)
    with ctx.wrap_socket(raw, server_hostname="aaaaaaaaaaaa.dns.mnebyvpn.site") as tls:
        if tls.version() not in ("TLSv1.2", "TLSv1.3") or not tls.getpeercert():
            raise RuntimeError("Personal backend TLS handshake invalid")
print(f"RU188_853_DIRECT_BACKEND_TLS=PASS({host}:{port})", flush=True)

try:
    rcode, ancount = dot_query(host, port, "000000000000.dns.mnebyvpn.site", "youtube.com")
except (OSError, ValueError, ssl.SSLError, EOFError):
    print(f"RU188_853_DIRECT_BACKEND_UNKNOWN_REJECTED=PASS({host}:{port})", flush=True)
else:
    if rcode == 0 and ancount > 0:
        raise RuntimeError("Personal backend unexpectedly answered unknown 12-char SNI")
    print(f"RU188_853_DIRECT_BACKEND_UNKNOWN_REJECTED=PASS(rcode={rcode},ancount={ancount})", flush=True)
PY
}

verify_dot_ingress() {
  python3 - "$PROBE_PORT" $PROBE_ADDRS <<'PY'
from __future__ import annotations
import secrets
import socket
import ssl
import struct
import sys

port = int(sys.argv[1])
addrs = sys.argv[2:]
if not addrs:
    raise RuntimeError("No DoT probe addresses configured")


def recvn(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("short DoT frame")
        buf.extend(chunk)
    return bytes(buf)


def dot_query(addr: str, port_num: int, sni: str, qname_str: str) -> tuple[int, int]:
    qid = secrets.randbelow(65535) + 1
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname_str.split(".")) + b"\x00"
    msg = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)
    ctx = ssl.create_default_context()
    with socket.create_connection((addr, port_num), timeout=6) as raw:
        raw.settimeout(6)
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            if not tls.getpeercert():
                raise RuntimeError("Missing TLS certificate")
            tls.sendall(struct.pack("!H", len(msg)) + msg)
            size = struct.unpack("!H", recvn(tls, 2))[0]
            if not 12 <= size <= 16384:
                raise ValueError(f"Invalid DoT response frame size: {size}")
            resp = recvn(tls, size)
    if int.from_bytes(resp[:2], "big") != qid:
        raise ValueError("DoT transaction ID mismatch")
    return resp[3] & 15, struct.unpack_from("!H", resp, 6)[0]


for addr in addrs:
    rcode, ancount = dot_query(addr, port, "dns.mnebyvpn.site", "example.org")
    if rcode != 0 or ancount < 1:
        raise RuntimeError(f"Legacy DoT failed via {addr}:{port}: rcode={rcode} ancount={ancount}")
    print(f"RU188_853_LEGACY_DOT_PASS={addr}:{port}", flush=True)

    try:
        rcode, ancount = dot_query(addr, port, "000000000000.dns.mnebyvpn.site", "youtube.com")
    except (OSError, ValueError, ssl.SSLError, EOFError):
        print(f"RU188_853_UNKNOWN_PERSONAL_REJECTED={addr}:{port}", flush=True)
    else:
        if rcode == 0 and ancount > 0:
            raise RuntimeError(f"Unknown 12-char SNI unexpectedly answered via {addr}:{port}")
        print(f"RU188_853_UNKNOWN_PERSONAL_REJECTED={addr}:{port}(rcode={rcode},ancount={ancount})", flush=True)
PY
}

verify_preserved_ports() {
  local p
  for p in 993 995 465 853; do
    test "$(grep -Fc "listen ${p}" "$ROOT/original.conf" || true)" -eq "$(grep -Fc "listen ${p}" "$CONF" || true)"
    test "$(grep -Fc "listen [::]:${p}" "$ROOT/original.conf" || true)" -eq "$(grep -Fc "listen [::]:${p}" "$CONF" || true)"
  done
}

atomic_copy_0600() {
  local src="$1" dst="$2" ref="$3"
  local tmp
  tmp="$(mktemp "$(dirname "$dst")/.$(basename "$dst").ru188.XXXXXXXX")"
  cp -p "$src" "$tmp"
  if [[ -e "$ref" ]]; then
    chown --reference="$ref" "$tmp" >/dev/null 2>&1 || true
  fi
  chmod 0600 "$tmp"
  mv -f "$tmp" "$dst"
}

check_baseline() {
  test -s "$CONF" && test ! -L "$CONF"
  test -s "$RELAY_CONF"
  test -s "$MOD_STREAM_CONF"
  test -f "$STREAM_MODULE"
  grep -Fq 'upstream s1_mtproxy' "$RELAY_CONF"
  nginx -t >/dev/null 2>&1
  systemctl is-active --quiet nginx.service
  [[ "$(ip -o -4 addr show dev "$WG_DEV")" == *"${WG_ADDR}/"* ]]
}

do_revert() {
  if [[ ! -s "$ROOT/original.conf" ]]; then
    echo "RU188_853_DIRECT_BACKUP_MISSING=true" >&2
    return 3
  fi
  if cmp -s "$ROOT/candidate.conf" "$CONF"; then
    atomic_copy_0600 "$ROOT/original.conf" "$CONF" "$ROOT/original.conf"
    nginx -t >/dev/null 2>&1
    systemctl reload nginx
  elif ! cmp -s "$ROOT/original.conf" "$CONF"; then
    echo "RU188_853_DIRECT_CONFIG_DRIFT_REFUSED=true" >&2
    return 4
  fi
  rm -f "$ROOT/confirmed"
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  cmp -s "$ROOT/original.conf" "$CONF"
  echo "RU188_853_DIRECT_REVERTED=PASS"
}

case "$PHASE" in
  stage)
    if [[ -e "$ROOT" ]]; then
      if [[ -f "$ROOT/confirmed" ]] || systemctl is-active --quiet "$TIMER"; then
        echo "RU188_853_DIRECT_ACTIVE_OR_CONFIRMED_REFUSE_RESTAGE=true" >&2
        exit 3
      fi
      if [[ -s "$ROOT/original.conf" ]] && cmp -s "$ROOT/original.conf" "$CONF"; then
        rm -rf -- "$ROOT"
        echo "RU188_853_DIRECT_PRIOR_UNAPPLIED_STAGE_CLEANED=true"
      else
        echo "RU188_853_DIRECT_UNEXPECTED_STATE_REFUSE_STAGE=true" >&2
        exit 3
      fi
    fi
    check_baseline
    verify_personal_backend
    install -d -m 700 "$ROOT"
    cp -p "$CONF" "$ROOT/original.conf"
    chmod 0600 "$ROOT/original.conf"
    render_candidate_py render "$ROOT/original.conf" "$ROOT/candidate.conf" "$ROOT/canary.conf" \
      "$STREAM_MODULE" "$CANARY_PID" "$CANARY_PORT"
    nginx -t -c "$ROOT/canary.conf" >/dev/null 2>&1
    local_self="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
    local_target="$(readlink -f "$SCRIPT" 2>/dev/null || printf '%s' "$SCRIPT")"
    if [[ "$local_self" != "$local_target" ]]; then
      install -d -m 700 "$(dirname "$SCRIPT")"
      install -m 700 "$0" "$SCRIPT"
    fi
    echo "RU188_853_DIRECT_STAGED=PASS"
    ;;
  switch)
    test -s "$ROOT/original.conf"
    test -s "$ROOT/candidate.conf"
    test -s "$ROOT/canary.conf"
    test -x "$SCRIPT"
    test ! -e "$ROOT/confirmed"
    cmp -s "$ROOT/original.conf" "$CONF"
    check_baseline
    nginx -t -c "$ROOT/canary.conf" >/dev/null 2>&1
    verify_personal_backend
    systemd-run --quiet --unit="$UNIT" --on-active="$AUTO_REVERT_SECONDS" --collect \
      /bin/bash "$SCRIPT" revert
    systemctl is-active --quiet "$TIMER"
    trap 'do_revert || true' ERR
    atomic_copy_0600 "$ROOT/candidate.conf" "$CONF" "$ROOT/original.conf"
    nginx -t >/dev/null 2>&1
    systemctl reload nginx
    verify_personal_backend
    verify_dot_ingress
    cmp -s "$ROOT/candidate.conf" "$CONF"
    verify_preserved_ports
    trap - ERR
    echo "RU188_853_DIRECT_SWITCHED=PASS"
    ;;
  revert)
    do_revert
    ;;
  finalize)
    test -s "$ROOT/candidate.conf"
    cmp -s "$ROOT/candidate.conf" "$CONF"
    nginx -t >/dev/null 2>&1
    systemctl is-active --quiet nginx.service
    verify_personal_backend
    verify_dot_ingress
    verify_preserved_ports
    : > "$ROOT/confirmed"
    chmod 0600 "$ROOT/confirmed"
    systemctl stop "$TIMER" >/dev/null 2>&1 || true
    echo "RU188_853_DIRECT_FINALIZED=PASS"
    ;;
  status)
    test -s "$CONF"
    if grep -Fq '"~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.2:8858;' "$CONF"; then
      echo "RU188_853_DIRECT_PERSONAL_TARGET=10.66.77.2:8858"
    elif grep -Fq '"~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.1:8854;' "$CONF"; then
      echo "RU188_853_DIRECT_PERSONAL_TARGET=10.66.77.1:8854"
    else
      echo "RU188_853_DIRECT_PERSONAL_TARGET=UNKNOWN"
    fi
    if grep -Fq 'dns.mnebyvpn.site 10.66.77.1:8854;' "$CONF"; then
      echo "RU188_853_DIRECT_LEGACY_TARGET=10.66.77.1:8854"
    else
      echo "RU188_853_DIRECT_LEGACY_TARGET=DRIFT"
    fi
    if grep -Fq 'default s1_mtproxy;' "$CONF"; then
      echo "RU188_853_DIRECT_DEFAULT_TARGET=s1_mtproxy"
    else
      echo "RU188_853_DIRECT_DEFAULT_TARGET=DRIFT"
    fi
    if nginx -t >/dev/null 2>&1; then
      echo "RU188_853_DIRECT_NGINX_SYNTAX=PASS"
    else
      echo "RU188_853_DIRECT_NGINX_SYNTAX=FAIL"
    fi
    echo "RU188_853_DIRECT_NGINX_SERVICE=$(systemctl is-active nginx.service 2>/dev/null || true)"
    echo "RU188_853_DIRECT_REVERT_TIMER=$(systemctl is-active "$TIMER" 2>/dev/null || true)"
    ;;
  *)
    echo "usage: $0 stage|switch|revert|finalize|status|--self-test" >&2
    exit 2
    ;;
esac
