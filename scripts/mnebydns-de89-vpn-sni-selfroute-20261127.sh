#!/usr/bin/env bash
# DE89 VPN-only TLS SNI :443 self-route to avoid DE89->RU188->DE89 hairpin:
# intercepts TCP connections from uid=mnebyvpn-xray to 188.120.254.223:443 via
# iptables NAT OUTPUT -> 127.0.0.1:18443 (isolated nginx stream listener
# running under DynamicUser=yes, never uid 992), forwarding RU-hosted SNIs to
# 188.120.254.223:443 and all other SNIs (default) to local 127.0.0.1:443.
set -Eeuo pipefail
umask 077

MODE="${1:-status}"
ROOT="${MNEBYDNS_SNI_SELFROUTE_ROOT:-/var/lib/mnebydns-vpn-sni-selfroute-20261127}"
MARK="$ROOT/installed"
CONFIRMED="$ROOT/confirmed"
APP_DIR="${MNEBYDNS_SNI_SELFROUTE_APP_DIR:-/opt/mnebydns-vpn-sni-selfroute-20261127}"
SCRIPT="${MNEBYDNS_SNI_SELFROUTE_SCRIPT:-$APP_DIR/manage.sh}"
CONF_DIR="${MNEBYDNS_SNI_SELFROUTE_CONF_DIR:-/etc/mnebydns/vpn-sni-selfroute}"
CONF="$CONF_DIR/nginx.conf"
PID_FILE="${MNEBYDNS_SNI_SELFROUTE_PID_FILE:-/run/mnebydns-vpn-sni-selfroute/nginx.pid}"
SYSTEMD_DIR="${MNEBYDNS_SNI_SELFROUTE_SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE="${MNEBYDNS_SNI_SELFROUTE_SERVICE:-mnebydns-vpn-sni-selfroute-20261127.service}"
UNIT_SRC="${MNEBYDNS_SNI_SELFROUTE_UNIT_SRC:-}"
TIMER="${MNEBYDNS_SNI_SELFROUTE_TIMER:-mnebydns-vpn-sni-selfroute-autorevert-20261127.timer}"
REVERT_UNIT="${TIMER%.timer}"
OWNER="${MNEBYDNS_SNI_SELFROUTE_OWNER:-mnebyvpn-xray}"
RU_IP="${MNEBYDNS_SNI_SELFROUTE_RU_IP:-188.120.254.223}"
RU_PORT="${MNEBYDNS_SNI_SELFROUTE_RU_PORT:-443}"
LISTEN_ADDR="${MNEBYDNS_SNI_SELFROUTE_LISTEN_ADDR:-127.0.0.1}"
LISTEN_PORT="${MNEBYDNS_SNI_SELFROUTE_LISTEN_PORT:-18443}"
LOCAL_NGINX_PORT="${MNEBYDNS_SNI_SELFROUTE_LOCAL_NGINX_PORT:-443}"
IPTABLES_BIN="${MNEBYDNS_SNI_SELFROUTE_IPTABLES_BIN:-/usr/sbin/iptables}"
NGINX_BIN="${MNEBYDNS_SNI_SELFROUTE_NGINX_BIN:-/usr/sbin/nginx}"
RU_SITE_HOST="${MNEBYDNS_SNI_SELFROUTE_RU_SITE:-mnebyvpn.site}"
SMARTDNS_HOST="${MNEBYDNS_SNI_SELFROUTE_SMARTDNS_HOST:-www.youtube.com}"
LISTEN_WAIT_TRIES="${MNEBYDNS_SNI_SELFROUTE_LISTEN_WAIT_TRIES:-40}"
LISTEN_WAIT_SLEEP="${MNEBYDNS_SNI_SELFROUTE_LISTEN_WAIT_SLEEP:-0.25}"

log() { printf 'VPN_SNI_SELFROUTE_%s=%s\n' "$1" "$2"; }

render_nginx_conf() {
  cat <<NGINX
# Managed by mnebydns-de89-vpn-sni-selfroute-20261127.sh
# DE89 nginx is compiled with static --with-stream:
# load_module /usr/lib/nginx/modules/ngx_stream_module.so;
# Process runs under systemd DynamicUser=yes (UID != 992, never mnebyvpn-xray).
worker_processes 1;
pid ${PID_FILE};
error_log stderr warn;

events {
    worker_connections 2048;
}

stream {
    map \$ssl_preread_server_name \$vpn_sni_selfroute_target {
        hostnames;
        mnebyvpn.site ${RU_IP}:${RU_PORT};
        www.mnebyvpn.site ${RU_IP}:${RU_PORT};
        bandbook.site ${RU_IP}:${RU_PORT};
        www.bandbook.site ${RU_IP}:${RU_PORT};
        flight-profile.bandbook.site ${RU_IP}:${RU_PORT};
        default 127.0.0.1:${LOCAL_NGINX_PORT};
    }

    server {
        listen ${LISTEN_ADDR}:${LISTEN_PORT};
        ssl_preread on;
        proxy_pass \$vpn_sni_selfroute_target;
        proxy_connect_timeout 5s;
        proxy_timeout 1h;
        proxy_socket_keepalive on;
        tcp_nodelay on;
    }
}
NGINX
}

if [[ "$MODE" == "--self-test" ]]; then
  rendered="$(render_nginx_conf)"
  grep -Fq '# load_module /usr/lib/nginx/modules/ngx_stream_module.so;' <<<"$rendered"
  grep -Fq 'worker_connections 2048;' <<<"$rendered"
  grep -Fq 'listen 127.0.0.1:18443;' <<<"$rendered"
  grep -Fq 'default 127.0.0.1:443;' <<<"$rendered"
  for host in mnebyvpn.site www.mnebyvpn.site bandbook.site www.bandbook.site flight-profile.bandbook.site; do
    grep -Fq "${host} 188.120.254.223:443;" <<<"$rendered"
  done
  log SELFTEST PASS
  exit 0
fi

[[ "$(id -u)" == "0" ]] || exit 2

rule() {
  local uid
  uid="$(id -u "$OWNER")"
  test "$uid" -gt 0
  RULE=(-p tcp -d "$RU_IP"/32 --dport 443 -m owner --uid-owner "$uid" -j REDIRECT --to-ports "$LISTEN_PORT")
}

present() {
  rule
  iptables -w -t nat -C OUTPUT "${RULE[@]}" >/dev/null 2>&1
}

listener_ready() {
  ss -H -lnt "sport = :${LISTEN_PORT}" | grep -Fq "${LISTEN_ADDR}:${LISTEN_PORT}"
}

resolve_unit_src() {
  local script_dir repo_ops
  script_dir="$(cd "$(dirname "$0")" && pwd)"
  repo_ops="$(cd "$script_dir/.." && pwd)/ops/$SERVICE"
  local candidate
  for candidate in \
    "$UNIT_SRC" \
    "$repo_ops" \
    "$script_dir/$SERVICE" \
    "/tmp/$SERVICE" \
    "$APP_DIR/$SERVICE" \
    "$SYSTEMD_DIR/$SERVICE"; do
    if [[ -n "$candidate" && -s "$candidate" && ! -L "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

validate_unit_file() {
  local unit_file="$1"
  local req
  for req in \
    "DynamicUser=yes" \
    "RuntimeDirectory=mnebydns-vpn-sni-selfroute" \
    "ExecStartPre=/usr/sbin/nginx -t -c /etc/mnebydns/vpn-sni-selfroute/nginx.conf" \
    "ExecStart=/usr/sbin/nginx -c /etc/mnebydns/vpn-sni-selfroute/nginx.conf" \
    "ExecStartPost=+/opt/mnebydns-vpn-sni-selfroute-20261127/manage.sh ensure-rule" \
    "ExecStopPost=+/opt/mnebydns-vpn-sni-selfroute-20261127/manage.sh rollback-rule" \
    "MemoryMax=128M" \
    "LimitNOFILE=4096"; do
    grep -Fq "$req" "$unit_file" || {
      echo "VPN_SNI_SELFROUTE_INVALID_UNIT_MISSING=$req" >&2
      return 3
    }
  done
}

preflight_baseline() {
  rule
  test -x "$IPTABLES_BIN"
  test -x "$NGINX_BIN"
  for svc in nginx.service mnebydns-googlepilot.service mnebyvpn-vpn-provisioner.service; do
    systemctl is-active --quiet "$svc"
  done
  nginx -t >/dev/null 2>&1
  ss -H -lnt "sport = :${LOCAL_NGINX_PORT}" | grep -Eq "(:${LOCAL_NGINX_PORT}|\\*:${LOCAL_NGINX_PORT})[[:space:]]"
}

probe_as_xray() {
  local mode="$1"
  local host="$2"
  runuser -u "$OWNER" -- python3 - "$RU_IP" "$RU_PORT" "$host" "$mode" <<'PY'
from __future__ import annotations
import socket
import ssl
import sys

addr, port_s, host, mode = sys.argv[1:]
port = int(port_s)
ctx = ssl.create_default_context()
with socket.create_connection((addr, port), timeout=8) as raw:
    raw.settimeout(8)
    with ctx.wrap_socket(raw, server_hostname=host) as tls:
        if tls.version() not in ("TLSv1.2", "TLSv1.3") or not tls.getpeercert():
            raise RuntimeError(f"Invalid TLS handshake for {host} via {addr}:{port}")
        if mode == "http200":
            req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: mnebydns-probe\r\n\r\n"
            tls.sendall(req.encode("ascii"))
            head = b""
            while b"\r\n" not in head and len(head) < 4096:
                chunk = tls.recv(1024)
                if not chunk:
                    break
                head += chunk
            status_line = head.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            parts = status_line.split()
            if len(parts) < 2 or not parts[0].startswith("HTTP/") or parts[1] != "200":
                raise RuntimeError(f"Expected HTTP 200 for {host}, got: {status_line!r}")
            print(f"VPN_SNI_SELFROUTE_PROBE_HTTP200={host}", flush=True)
        elif mode == "tls":
            print(f"VPN_SNI_SELFROUTE_PROBE_TLS={host}", flush=True)
        else:
            raise SystemExit(2)
PY
}

ensure_rule() {
  test -f "$MARK" || { log ERROR MISSING_OWNERSHIP_MARKER; exit 3; }
  rule
  local i ready=0
  for (( i = 0; i < LISTEN_WAIT_TRIES; i++ )); do
    if listener_ready; then
      ready=1
      break
    fi
    sleep "$LISTEN_WAIT_SLEEP"
  done
  if (( ! ready )); then
    log ERROR LISTENER_NOT_READY
    exit 3
  fi
  if ! present; then
    iptables -w -t nat -I OUTPUT 1 "${RULE[@]}"
  fi
  present
  log RULE_ENSURED ACTIVE
}

rollback_rule() {
  if ! test -f "$MARK"; then
    log RULE_SKIPPED UNOWNED
    return 0
  fi
  rule
  if present; then
    iptables -w -t nat -D OUTPUT "${RULE[@]}"
  fi
  log RULE_REMOVED YES
}

rollback() {
  systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
  rollback_rule
  rm -f "$MARK" "$CONFIRMED"
  if [[ -f "$SYSTEMD_DIR/$SERVICE" && -f "$APP_DIR/$SERVICE" ]] && cmp -s "$APP_DIR/$SERVICE" "$SYSTEMD_DIR/$SERVICE"; then
    rm -f "$SYSTEMD_DIR/$SERVICE"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  log ROLLBACK COMPLETE
}

nginx_test_conf() {
  # The pid directory is created only at runtime by systemd RuntimeDirectory=,
  # so validate a temp copy with a throwaway pid path.
  local conf_path="$1"
  local tmp_dir tmp_conf rc=0
  tmp_dir="$(mktemp -d)"
  tmp_conf="$tmp_dir/nginx.conf"
  sed "s|^pid ${PID_FILE};|pid ${tmp_dir}/nginx.pid;|" "$conf_path" > "$tmp_conf"
  nginx -t -c "$tmp_conf" >/dev/null 2>&1 || rc=$?
  rm -rf -- "$tmp_dir"
  return "$rc"
}

stage() {
  preflight_baseline
  if test -f "$MARK" || present || listener_ready; then
    log ERROR ACTIVE_OR_PORT_OCCUPIED
    exit 3
  fi
  local src_unit
  src_unit="$(resolve_unit_src)" || { log ERROR MISSING_UNIT_SOURCE; exit 3; }
  validate_unit_file "$src_unit"
  mkdir -p -m 0700 "$APP_DIR"
  local self_real target_real
  self_real="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  target_real="$(readlink -f "$SCRIPT" 2>/dev/null || printf '%s' "$SCRIPT")"
  if [[ "$self_real" != "$target_real" ]]; then
    install -m 0700 "$0" "$SCRIPT"
  else
    chmod 0700 "$SCRIPT"
  fi
  install -m 0644 "$src_unit" "$APP_DIR/$SERVICE"
  local conf_parent
  conf_parent="$(dirname "$CONF_DIR")"
  if [[ ! -d "$conf_parent" ]]; then
    install -d -m 0755 "$conf_parent"
  fi
  install -d -m 0755 "$CONF_DIR"
  local tmp_conf
  tmp_conf="$(mktemp "$CONF_DIR/.nginx.conf.XXXXXXXX")"
  render_nginx_conf > "$tmp_conf"
  chmod 0644 "$tmp_conf"
  mv -f "$tmp_conf" "$CONF"
  nginx_test_conf "$CONF"
  log STAGED PASS
}

apply() {
  preflight_baseline
  test -x "$SCRIPT"
  test -r "$CONF"
  test -s "$APP_DIR/$SERVICE"
  validate_unit_file "$APP_DIR/$SERVICE"
  nginx_test_conf "$CONF"
  if test -f "$MARK" || present || listener_ready; then
    log ERROR DUPLICATE_OR_FOREIGN_RULE
    exit 3
  fi
  # Pre-fix verification: RU-hosted site works over RU188 before NAT redirect.
  probe_as_xray http200 "$RU_SITE_HOST"
  install -m 0644 "$APP_DIR/$SERVICE" "$SYSTEMD_DIR/$SERVICE"
  systemctl daemon-reload
  systemd-run --quiet --unit="$REVERT_UNIT" --on-active=4m --collect /bin/bash "$SCRIPT" rollback
  systemctl is-active --quiet "$TIMER"
  log AUTO_ROLLBACK ARMED_4M
  trap 'rollback || true' ERR
  mkdir -p -m 0700 "$ROOT"
  : > "$MARK"
  chmod 0600 "$MARK"
  systemctl enable --now "$SERVICE"
  systemctl is-active --quiet "$SERVICE"
  systemctl is-enabled --quiet "$SERVICE"
  listener_ready
  present
  probe_as_xray http200 "$RU_SITE_HOST"
  probe_as_xray tls "$SMARTDNS_HOST"
  trap - ERR
  log APPLIED PENDING_FINALIZE
}

finalize() {
  test -f "$MARK"
  systemctl is-active --quiet "$SERVICE"
  systemctl is-enabled --quiet "$SERVICE"
  listener_ready
  present
  probe_as_xray http200 "$RU_SITE_HOST"
  probe_as_xray tls "$SMARTDNS_HOST"
  : > "$CONFIRMED"
  chmod 0600 "$CONFIRMED"
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  log FINALIZED PASS
}

status() {
  echo "VPN_SNI_SELFROUTE_SERVICE=$(systemctl is-active "$SERVICE" 2>/dev/null || true)"
  echo "VPN_SNI_SELFROUTE_BOOT=$(systemctl is-enabled "$SERVICE" 2>/dev/null || true)"
  if present; then log RULE ACTIVE; else log RULE ABSENT; fi
  if listener_ready; then log LISTENER ACTIVE; else log LISTENER ABSENT; fi
  if test -f "$MARK"; then log MARK PRESENT; else log MARK ABSENT; fi
  if test -f "$CONFIRMED"; then log CONFIRMED YES; else log CONFIRMED NO; fi
  echo "VPN_SNI_SELFROUTE_TIMER=$(systemctl is-active "$TIMER" 2>/dev/null || true)"
}

case "$MODE" in
  stage) stage ;;
  apply) apply ;;
  ensure-rule) ensure_rule ;;
  rollback) rollback ;;
  rollback-rule) rollback_rule ;;
  finalize) finalize ;;
  status) status ;;
  *) echo "usage: $0 stage|apply|ensure-rule|rollback|rollback-rule|finalize|status|--self-test" >&2; exit 2 ;;
esac
