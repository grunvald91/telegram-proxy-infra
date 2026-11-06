#!/usr/bin/env bash
# Reuse existing tg-relay 10.66.77.2 <-> 10.66.77.1 for Telegram ingress.
# No edits to existing proxy vhosts or global WireGuard configuration.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || { echo "root_required"; exit 2; }
exec 9>/run/lock/mnebyvpn-wg-webhook-ru.lock
flock -n 9 || { echo "deployment_locked"; exit 2; }
ip -4 addr show dev tg-relay | grep -Fq '10.66.77.2/' || { echo "missing_ru_existing_wg"; exit 2; }
test "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8793/healthz)" = 200
nginx -t >/dev/null
CFG=/etc/nginx/conf.d/mnebyvpn-wg-telegram.conf
UNIT=/etc/systemd/system/mnebyvpn-wg-webhook-firewall.service
mkdir -p /opt/mnebyvpn/backups
BACKUP="$(mktemp -d /opt/mnebyvpn/backups/wg-telegram-ru-XXXXXX)"
chmod 700 "$BACKUP"
[[ ! -e "$CFG" ]] || cp -p "$CFG" "$BACKUP/original.conf"
[[ ! -e "$UNIT" ]] || cp -p "$UNIT" "$BACKUP/original.service"
restore(){
  set +e
  if [[ -f "$BACKUP/original.conf" ]]; then cp -p "$BACKUP/original.conf" "$CFG"; else rm -f "$CFG"; fi
  if [[ -f "$BACKUP/original.service" ]]; then cp -p "$BACKUP/original.service" "$UNIT"; else
    systemctl disable --now mnebyvpn-wg-webhook-firewall.service >/dev/null 2>&1
    rm -f "$UNIT"
    iptables -D INPUT -i tg-relay -s 10.66.77.1 -d 10.66.77.2 -p tcp --dport 8794 -j ACCEPT >/dev/null 2>&1
  fi
  systemctl daemon-reload
  nginx -t >/dev/null 2>&1 && systemctl reload nginx
  echo "ru_bridge_rolled_back=true"
}
trap restore ERR
if ss -H -lnt | awk '{print $4}' | grep -Fq '10.66.77.2:8794'; then
  [[ -f "$CFG" ]] && grep -Fq 'listen 10.66.77.2:8794;' "$CFG" || {
    echo "wg_bridge_port_occupied"; exit 2;
  }
fi
cat > "$CFG" <<'CONF'
# Dedicated MNEBYVPN Telegram-only bridge over the EXISTING WireGuard.
server {
    listen 10.66.77.2:8794;
    server_name _;
    access_log off;
    client_max_body_size 64k;
    location = /webhooks/telegram {
        limit_except POST { deny all; }
        proxy_http_version 1.1;
        proxy_pass http://127.0.0.1:8793;
        proxy_set_header Host mnebyvpn.site;
        proxy_set_header X-Telegram-Bot-Api-Secret-Token $http_x_telegram_bot_api_secret_token;
        proxy_set_header Content-Type $content_type;
        proxy_connect_timeout 3s;
        proxy_read_timeout 12s;
        proxy_send_timeout 12s;
        proxy_buffering off;
    }
    location / { return 404; }
}
CONF
cat > "$UNIT" <<'UNIT'
[Unit]
Description=MNEBYVPN webhook bridge: allow only foreign WireGuard peer
After=network-online.target wg-quick@tg-relay.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c '/usr/sbin/iptables -C INPUT -i tg-relay -s 10.66.77.1 -d 10.66.77.2 -p tcp --dport 8794 -j ACCEPT 2>/dev/null || /usr/sbin/iptables -I INPUT 1 -i tg-relay -s 10.66.77.1 -d 10.66.77.2 -p tcp --dport 8794 -j ACCEPT'
ExecStop=/bin/sh -c '/usr/sbin/iptables -D INPUT -i tg-relay -s 10.66.77.1 -d 10.66.77.2 -p tcp --dport 8794 -j ACCEPT 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 "$CFG" "$UNIT"
nginx -t >/dev/null
systemctl daemon-reload
systemctl enable --now mnebyvpn-wg-webhook-firewall.service >/dev/null
systemctl reload nginx
# This bridge accepts only source 10.66.77.1 on WireGuard. A request
# from RU itself is deliberately blocked. Test it from relay89 in the next step.
ready=no
for attempt in $(seq 1 15); do
  if ss -H -lnt | awk '{print $4}' | grep -Fqx '10.66.77.2:8794'; then
    ready=yes; break
  fi
  sleep 1
done
if [[ "$ready" != yes ]]; then
  echo "wg_bridge_not_listening"
  # Report whether config was included, without revealing unrelated routes.
  if nginx -T 2>/dev/null | grep -Fq '# configuration file /etc/nginx/conf.d/mnebyvpn-wg-telegram.conf:'; then
    echo "wg_bridge_nginx_config_included=true"
  else
    echo "wg_bridge_nginx_config_included=false"
  fi
  exit 2
fi
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 -X POST -H 'Content-Type: application/json' -d '{"update_id":1}' http://127.0.0.1:8793/webhooks/telegram)" = 401
trap - ERR
echo "ru_wg_webhook_bridge=ready"
echo "ru_local_webhook_auth_required=true"
echo "ru_wg_listen=10.66.77.2:8794"
echo "ru_other_proxy_sites_unmodified=true"
