#!/usr/bin/env bash
# Deploy/verify isolated non-443 protocol relay (mtalk TCP 5228-5230,
# STUN UDP 19302/3478, NTP UDP 123) over tg-relay (RU188 -> DE89).
set -Eeuo pipefail
umask 022

MODE="${1:-status}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

DE_WG_IP="${MNEBYDNS_PROTO_DE_WG_IP:-10.66.77.1}"
RU_PUB_IP="${MNEBYDNS_PROTO_RU_PUB_IP:-188.120.254.223}"
EXT_IFACE="${MNEBYDNS_PROTO_EXT_IFACE:-ens3}"

DE_CONF_DIR="${MNEBYDNS_PROTO_DE_CONF_DIR:-/etc/mnebydns/proto-relay}"
DE_CONF="$DE_CONF_DIR/nginx.conf"
DE_PID="${MNEBYDNS_PROTO_DE_PID:-/run/mnebydns-proto-relay/nginx.pid}"
DE_SERVICE="${MNEBYDNS_PROTO_DE_SERVICE:-mnebydns-proto-relay-20261127.service}"
DE_UNIT_PATH="/etc/systemd/system/$DE_SERVICE"
DE_UNIT_SRC="${MNEBYDNS_PROTO_DE_UNIT_SRC:-}"

RU_STREAM_CONF="${MNEBYDNS_PROTO_RU_STREAM_CONF:-/etc/nginx/streams.d/03-mnebydns-proto-relay.conf}"
BACKUP_DIR="${MNEBYDNS_PROTO_BACKUP_DIR:-/var/backups/mnebydns-proto-relay-20261127}"

log() { printf 'PROTO_RELAY_%s=%s\n' "$1" "$2"; }

render_de89_conf() {
  cat <<NGINX
# Managed by mnebydns-proto-relay-20261127.sh (DE89 isolated WG-only relay)
# DE89 nginx is compiled with static --with-stream:
# load_module /usr/lib/nginx/modules/ngx_stream_module.so;
worker_processes 1;
pid ${DE_PID};
error_log stderr warn;

events {
    worker_connections 2048;
}

stream {
    resolver 9.9.9.9 1.1.1.1 ipv6=off valid=300s;
    resolver_timeout 5s;

    upstream google_ntp {
        server 216.239.35.4:123 max_fails=2 fail_timeout=30s;
        server 162.159.200.1:123 backup;
    }

    map \$ssl_preread_server_name \$mtalk_host {
        mtalk.google.com mtalk.google.com;
        mtalk4.google.com mtalk4.google.com;
        alt1-mtalk.google.com alt1-mtalk.google.com;
        alt2-mtalk.google.com alt2-mtalk.google.com;
        alt3-mtalk.google.com alt3-mtalk.google.com;
        alt4-mtalk.google.com alt4-mtalk.google.com;
        alt5-mtalk.google.com alt5-mtalk.google.com;
        alt6-mtalk.google.com alt6-mtalk.google.com;
        alt7-mtalk.google.com alt7-mtalk.google.com;
        alt8-mtalk.google.com alt8-mtalk.google.com;
        default mtalk.google.com;
    }

    map \$remote_addr \$stun_19302_up {
        default stun.l.google.com:19302;
    }

    map \$remote_addr \$stun_3478_up {
        default stun.l.google.com:3478;
    }

    server {
        listen ${DE_WG_IP}:15228;
        ssl_preread on;
        proxy_pass \$mtalk_host:5228;
        proxy_connect_timeout 5s;
        proxy_timeout 30m;
        proxy_socket_keepalive on;
        tcp_nodelay on;
    }

    server {
        listen ${DE_WG_IP}:15229;
        ssl_preread on;
        proxy_pass \$mtalk_host:5229;
        proxy_connect_timeout 5s;
        proxy_timeout 30m;
        proxy_socket_keepalive on;
        tcp_nodelay on;
    }

    server {
        listen ${DE_WG_IP}:15230;
        ssl_preread on;
        proxy_pass \$mtalk_host:5230;
        proxy_connect_timeout 5s;
        proxy_timeout 30m;
        proxy_socket_keepalive on;
        tcp_nodelay on;
    }

    server {
        listen ${DE_WG_IP}:15930 udp;
        proxy_pass \$stun_19302_up;
        proxy_responses 1;
        proxy_timeout 5s;
    }

    server {
        listen ${DE_WG_IP}:15347 udp;
        proxy_pass \$stun_3478_up;
        proxy_responses 1;
        proxy_timeout 5s;
    }

    server {
        listen ${DE_WG_IP}:15123 udp;
        proxy_pass google_ntp;
        proxy_responses 1;
        proxy_timeout 5s;
    }
}
NGINX
}

render_ru188_conf() {
  cat <<NGINX
# Managed by mnebydns-proto-relay-20261127.sh (RU188 ingress -> DE89 over tg-relay)
server {
    listen ${RU_PUB_IP}:5228 so_keepalive=30s:10s:3;
    proxy_pass ${DE_WG_IP}:15228;
    proxy_connect_timeout 5s;
    proxy_timeout 30m;
    proxy_socket_keepalive on;
    tcp_nodelay on;
}

server {
    listen ${RU_PUB_IP}:5229 so_keepalive=30s:10s:3;
    proxy_pass ${DE_WG_IP}:15229;
    proxy_connect_timeout 5s;
    proxy_timeout 30m;
    proxy_socket_keepalive on;
    tcp_nodelay on;
}

server {
    listen ${RU_PUB_IP}:5230 so_keepalive=30s:10s:3;
    proxy_pass ${DE_WG_IP}:15230;
    proxy_connect_timeout 5s;
    proxy_timeout 30m;
    proxy_socket_keepalive on;
    tcp_nodelay on;
}

server {
    listen ${RU_PUB_IP}:19302 udp;
    proxy_pass ${DE_WG_IP}:15930;
    proxy_responses 1;
    proxy_timeout 5s;
}

server {
    listen ${RU_PUB_IP}:3478 udp;
    proxy_pass ${DE_WG_IP}:15347;
    proxy_responses 1;
    proxy_timeout 5s;
}

server {
    listen ${RU_PUB_IP}:123 udp;
    proxy_pass ${DE_WG_IP}:15123;
    proxy_responses 1;
    proxy_timeout 5s;
}
NGINX
}

nginx_test_with_tmp_pid() {
  local conf_path="$1"
  local tmp_dir tmp_conf rc=0
  tmp_dir="$(mktemp -d)"
  tmp_conf="$tmp_dir/nginx.conf"
  sed "s|^pid ${DE_PID};|pid ${tmp_dir}/nginx.pid;|" "$conf_path" > "$tmp_conf"
  nginx -t -c "$tmp_conf" >/dev/null 2>&1 || rc=$?
  rm -rf -- "$tmp_dir"
  return "$rc"
}

resolve_unit_src() {
  local repo_unit
  repo_unit="$(cd "$SCRIPT_DIR/.." && pwd)/ops/$DE_SERVICE"
  local c
  for c in "$DE_UNIT_SRC" "$repo_unit" "$SCRIPT_DIR/$DE_SERVICE" "/tmp/$DE_SERVICE" "$DE_UNIT_PATH"; do
    if [[ -n "$c" && -s "$c" && ! -L "$c" ]]; then
      printf '%s\n' "$c"
      return 0
    fi
  done
  return 1
}

probe_relay_endpoints() {
  local target_ip="$1" p_mtalk1="$2" p_mtalk2="$3" p_mtalk3="$4" p_stun19="$5" p_stun34="$6" p_ntp="$7"
  python3 - "$target_ip" "$p_mtalk1" "$p_mtalk2" "$p_mtalk3" "$p_stun19" "$p_stun34" "$p_ntp" <<'PY'
import socket, ssl, struct, sys

ip = sys.argv[1]
p_m1, p_m2, p_m3, p_s19, p_s34, p_ntp = [int(x) for x in sys.argv[2:]]

ctx = ssl.create_default_context()
with socket.create_connection((ip, p_m1), timeout=6) as raw:
    raw.settimeout(6)
    with ctx.wrap_socket(raw, server_hostname="mtalk.google.com") as tls:
        assert tls.version() in ("TLSv1.2", "TLSv1.3")
        assert tls.getpeercert()
for port in (p_m2, p_m3):
    with socket.create_connection((ip, port), timeout=5):
        pass

req = struct.pack("!HHI12s", 0x0001, 0, 0x2112A442, b"123456789012")
for label, port in (("stun_19302", p_s19), ("stun_3478", p_s34)):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(req, (ip, port))
        data, _ = s.recvfrom(512)
        if len(data) < 20 or struct.unpack("!H", data[:2])[0] != 0x0101:
            raise RuntimeError(f"Invalid STUN response on {ip}:{port}")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.settimeout(5)
    s.sendto(b"\x1b" + 47 * b"\x00", (ip, p_ntp))
    data, _ = s.recvfrom(512)
    if len(data) < 48 or (data[0] & 7) != 4:
        raise RuntimeError(f"Invalid NTP response on {ip}:{p_ntp}")

print(f"PROTO_RELAY_PROBES=PASS({ip})", flush=True)
PY
}

de89_apply() {
  local unit_src
  unit_src="$(resolve_unit_src)" || { echo "PROTO_RELAY_MISSING_UNIT_SRC=true" >&2; exit 3; }
  install -d -m 0700 "$BACKUP_DIR"
  [[ -f "$DE_CONF" ]] && cp -p "$DE_CONF" "$BACKUP_DIR/nginx.conf.before" || true
  [[ -f "$DE_UNIT_PATH" ]] && cp -p "$DE_UNIT_PATH" "$BACKUP_DIR/unit.before" || true

  install -d -m 0755 "$DE_CONF_DIR"
  local tmp_conf
  tmp_conf="$(mktemp "$DE_CONF_DIR/.nginx.conf.XXXXXXXX")"
  render_de89_conf > "$tmp_conf"
  chmod 0644 "$tmp_conf"
  mv -f "$tmp_conf" "$DE_CONF"
  nginx_test_with_tmp_pid "$DE_CONF"

  install -m 0644 "$unit_src" "$DE_UNIT_PATH"
  systemctl daemon-reload
  systemctl enable "$DE_SERVICE"
  systemctl restart "$DE_SERVICE"
  local i ready=0
  for (( i = 0; i < 40; i++ )); do
    if ss -H -lnt "sport = :15228" | grep -Fq "${DE_WG_IP}:15228"; then
      ready=1
      break
    fi
    sleep 0.15
  done
  test "$ready" -eq 1
  systemctl is-active --quiet "$DE_SERVICE"
  probe_relay_endpoints "$DE_WG_IP" 15228 15229 15230 15930 15347 15123
  log DE89_APPLIED PASS
}

de89_rollback() {
  systemctl disable --now "$DE_SERVICE" >/dev/null 2>&1 || true
  rm -f "$DE_CONF" "$DE_UNIT_PATH"
  systemctl daemon-reload >/dev/null 2>&1 || true
  log DE89_ROLLBACK COMPLETE
}

ru188_apply() {
  install -d -m 0700 "$BACKUP_DIR"
  [[ -f "$RU_STREAM_CONF" ]] && cp -p "$RU_STREAM_CONF" "$BACKUP_DIR/03-mnebydns-proto-relay.conf.before" || true

  local revert_unit="mnebydns-proto-relay-ru188-revert-20261127"
  systemctl stop "${revert_unit}.timer" "${revert_unit}.service" >/dev/null 2>&1 || true
  systemctl reset-failed "${revert_unit}.timer" "${revert_unit}.service" >/dev/null 2>&1 || true
  local script_copy="/opt/mnebydns-proto-relay-20261127/manage.sh"
  install -d -m 0700 /opt/mnebydns-proto-relay-20261127
  if [[ "$(readlink -f "$0")" != "$script_copy" ]]; then
    install -m 0700 "$0" "$script_copy"
  fi
  systemd-run --quiet --unit="$revert_unit" --on-active=3m --collect /bin/bash "$script_copy" ru188-rollback
  trap 'ru188_rollback || true' ERR

  local tmp_conf
  tmp_conf="$(mktemp "$(dirname "$RU_STREAM_CONF")/.03-proto.XXXXXXXX")"
  render_ru188_conf > "$tmp_conf"
  chmod 0644 "$tmp_conf"
  mv -f "$tmp_conf" "$RU_STREAM_CONF"
  nginx -t >/dev/null 2>&1
  systemctl reload nginx

  for spec in "5228/tcp:mtalk TCP" "5229/tcp:mtalk4 TCP" "5230/tcp:mtalk alt TCP" "19302/udp:Google STUN UDP" "3478/udp:STUN 3478 UDP" "123/udp:Google NTP UDP"; do
    local port_proto="${spec%%:*}" cmt="${spec#*:}"
    local port="${port_proto%/*}" proto="${port_proto#*/}"
    ufw allow in on "$EXT_IFACE" to "$RU_PUB_IP" port "$port" proto "$proto" comment "$cmt -> DE89" >/dev/null
  done

  probe_relay_endpoints "$RU_PUB_IP" 5228 5229 5230 19302 3478 123
  systemctl stop "${revert_unit}.timer" >/dev/null 2>&1 || true
  trap - ERR
  log RU188_APPLIED PASS
}

ru188_rollback() {
  if [[ -f "$BACKUP_DIR/03-mnebydns-proto-relay.conf.before" ]]; then
    cp -p "$BACKUP_DIR/03-mnebydns-proto-relay.conf.before" "$RU_STREAM_CONF"
  else
    rm -f "$RU_STREAM_CONF"
  fi
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
  for spec in 5228/tcp 5229/tcp 5230/tcp 19302/udp 3478/udp 123/udp; do
    local port="${spec%/*}" proto="${spec#*/}"
    ufw delete allow in on "$EXT_IFACE" to "$RU_PUB_IP" port "$port" proto "$proto" >/dev/null 2>&1 || true
  done
  log RU188_ROLLBACK COMPLETE
}

status_cmd() {
  if [[ -f "$DE_UNIT_PATH" ]]; then
    log DE89_SERVICE "$(systemctl is-active "$DE_SERVICE" 2>/dev/null || true)"
  fi
  if [[ -f "$RU_STREAM_CONF" ]]; then
    log RU188_STREAM_CONF PRESENT
    log RU188_NGINX "$(systemctl is-active nginx.service 2>/dev/null || true)"
  fi
}

if [[ "$MODE" == "--self-test" ]]; then
  dconf="$(render_de89_conf)"
  grep -Fq "listen 10.66.77.1:15228;" <<<"$dconf"
  grep -Fq "listen 10.66.77.1:15930 udp;" <<<"$dconf"
  grep -Fq "listen 10.66.77.1:15123 udp;" <<<"$dconf"
  rconf="$(render_ru188_conf)"
  grep -Fq "listen 188.120.254.223:5228" <<<"$rconf"
  grep -Fq "listen 188.120.254.223:19302 udp;" <<<"$rconf"
  grep -Fq "listen 188.120.254.223:123 udp;" <<<"$rconf"
  log SELFTEST PASS
  exit 0
fi

[[ "$(id -u)" == "0" ]] || exit 2
case "$MODE" in
  de89-apply) de89_apply ;;
  de89-rollback) de89_rollback ;;
  ru188-apply) ru188_apply ;;
  ru188-rollback) ru188_rollback ;;
  status) status_cmd ;;
  *) echo "usage: $0 de89-apply|de89-rollback|ru188-apply|ru188-rollback|status|--self-test" >&2; exit 2 ;;
esac
