#!/usr/bin/env bash
# An additive RU-only WireGuard origin for the unchanged existing DE CoreDNS.
# Does not change existing dns.mnebyvpn.site, public TCP/853 or NAT.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
phase="${1:?phase}"
root=/etc/mnebydns/personal-private-origin
service=mnebydns-personal-private-origin.service
case "$phase" in
  install)
    [[ "$(systemctl is-active mnebydns-dot)" == active ]] || exit 2
    [[ "$(ip -o -4 addr show dev tg-relay)" == *10.66.77.1/24* ]] || exit 2
    test -f /usr/lib/nginx/modules/ngx_stream_module.so
    ! ss -Hlnt | awk '{print $4}' | grep -Eq ':1853$' ||
      { echo 'PERSONAL_PRIVATE_ORIGIN_PORT_OCCUPIED=true'; exit 2; }
    [[ ! -e "$root" && ! -e /etc/systemd/system/$service ]] ||
      { echo 'PERSONAL_PRIVATE_ORIGIN_REFUSE_OVERWRITE=true'; exit 2; }
    install -d -m 700 "$root"
    cat > "$root/nginx.conf" <<'CONF'
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user www-data;
worker_processes 1;
pid /run/mnebydns-personal-private-origin.pid;
error_log stderr warn;
events { worker_connections 512; }
stream {
  server {
    listen 10.66.77.1:1853;
    allow 10.66.77.2;
    deny all;
    proxy_pass 89.125.90.101:853;
    proxy_connect_timeout 5s;
    proxy_timeout 65s;
  }
}
CONF
    chmod 600 "$root/nginx.conf"
    cat > "/etc/systemd/system/$service" <<'UNIT'
[Unit]
Description=MNEBYDNS private RU-only origin bridge for CoreDNS on DE
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/sbin/nginx -c /etc/mnebydns/personal-private-origin/nginx.conf -g 'daemon off;'
KillSignal=SIGQUIT
Restart=on-failure
RestartSec=2s
LimitNOFILE=4096
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
    if ! nginx -t -c "$root/nginx.conf"; then
      rm -f "/etc/systemd/system/$service"
      rm -rf "$root"
      exit 2
    fi
    systemctl daemon-reload
    systemctl enable --now "$service" >/dev/null
    systemctl is-active --quiet "$service"
    systemctl is-active --quiet mnebydns-dot
    echo 'PERSONAL_PRIVATE_ORIGIN=READY_10_66_77_1_1853'
    echo 'PERSONAL_PRIVATE_ORIGIN_LEGACY_PUBLIC_UNCHANGED=true'
    ;;
  rollback)
    # Roll back only our isolated bridge, never stop existing public CoreDNS.
    systemctl disable --now "$service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$service"
    systemctl daemon-reload
    rm -rf "$root"
    echo 'PERSONAL_PRIVATE_ORIGIN=REMOVED_PUBLIC_UNCHANGED'
    ;;
  status)
    echo "PERSONAL_PRIVATE_ORIGIN_SERVICE=$(systemctl is-active "$service" || true)"
    ;;
  *) exit 2;;
esac
