#!/usr/bin/env bash
# Use a dedicated public IPv4:8443 TLS listener for Telegram.
# The live 443 SNI dispatcher and 127.0.0.1:8443 relay stay untouched.
set -Eeuo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-telegram-8443.lock
flock -n 9 || { echo "busy"; exit 2; }
PUBLIC=89.125.90.101
PRIVATE=10.66.77.2
SITE=/etc/nginx/sites-available/mnebyvpn-telegram-8443.conf
LINK=/etc/nginx/sites-enabled/mnebyvpn-telegram-8443.conf
CERT=/etc/letsencrypt/live/cdn.servgo.ru/fullchain.pem
KEY=/etc/letsencrypt/live/cdn.servgo.ru/privkey.pem
[[ -s "$CERT" && -s "$KEY" ]] || { echo "foreign_cdn_cert_missing"; exit 2; }
BIND_ADDR="$(ip -4 -o addr show dev eth0 | awk '$3=="inet" {print $4}' | cut -d/ -f1 | head -1)"
[[ "$BIND_ADDR" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "eth0_ipv4_not_assigned"; exit 2;
}
[[ "$BIND_ADDR" != 127.* ]] || { echo "refusing_loopback_eth0"; exit 2; }
echo "foreign_8443_bind_address_selected=true"
ip -4 addr show dev tg-relay | grep -Fq '10.66.77.1/' || exit 2
nginx -t >/dev/null 2>&1
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST -H 'Content-Type: application/json' -d '{"update_id":1}' "http://$PRIVATE:8794/webhooks/telegram")" = 401 || {
  echo "existing_wireguard_webhook_not_ready"; exit 2;
}
[[ ! -L "$LINK" ]] || [[ "$(readlink "$LINK")" == "$SITE" ]] || {
  echo "foreign_8443_symlink_conflict"; exit 2;
}
if ss -H -lnt | awk '{print $4}' | grep -Fqx "$BIND_ADDR:8443"; then
  [[ -f "$SITE" ]] && grep -Fq "listen $BIND_ADDR:8443 ssl;" "$SITE" || {
    echo "public_8443_already_used"; exit 2;
  }
fi
if ss -H -lnt | awk '{print $4}' | grep -Eq '^(0\.0\.0\.0|\*):8443$'; then
  echo "wildcard_8443_already_used"; exit 2
fi
mkdir -p /opt/mnebyvpn/backups /etc/nginx/sites-available /etc/nginx/sites-enabled
BACKUP="$(mktemp -d /opt/mnebyvpn/backups/bot8443-XXXXXXXX)"
chmod 700 "$BACKUP"
[[ ! -f "$SITE" ]] || cp -p "$SITE" "$BACKUP/original"
rollback(){
  set +e
  if [[ -f "$BACKUP/original" ]]; then cp -p "$BACKUP/original" "$SITE"; else rm -f "$SITE" "$LINK"; fi
  nginx -t >/dev/null 2>&1 && systemctl reload nginx
  echo "foreign_8443_rolled_back=true"
}
trap rollback ERR
# Baseline is a service that must not change.
curl --noproxy '*' -fsS --max-time 8 --resolve cdn.servgo.ru:443:127.0.0.1 \
  https://cdn.servgo.ru/ > "$BACKUP/cdn-before"
cat > "$SITE" <<'CONF'
# Dedicated TLS endpoint for Telegram on supported alternative port 8443.
# Exact public IPv4 binding, independent of the existing 443 SNI and 8443 loopback.
server {
    listen __BIND_ADDR__:8443 ssl;
    server_name cdn.servgo.ru;
    ssl_certificate /etc/letsencrypt/live/cdn.servgo.ru/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cdn.servgo.ru/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    server_tokens off;
    access_log off;
    client_max_body_size 64k;
    add_header Cache-Control "no-store" always;
    location = /mnebyvpn-telegram/webhook {
        limit_except POST { deny all; }
        proxy_pass http://10.66.77.2:8794/webhooks/telegram;
        proxy_http_version 1.1;
        proxy_set_header Host mnebyvpn.site;
        proxy_set_header X-Telegram-Bot-Api-Secret-Token $http_x_telegram_bot_api_secret_token;
        proxy_connect_timeout 3s;
        proxy_read_timeout 14s;
        proxy_send_timeout 14s;
        proxy_buffering off;
    }
    location / { return 404; }
}
CONF
sed -i "s/__BIND_ADDR__/$BIND_ADDR/g" "$SITE"
chmod 644 "$SITE"
ln -sfn "$SITE" "$LINK"
nginx -t
systemctl reload nginx
ready=no
for attempt in $(seq 1 15); do
  code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 6 \
    --resolve cdn.servgo.ru:8443:$BIND_ADDR -X POST \
    -H 'Content-Type: application/json' -d '{"update_id":1}' \
    https://cdn.servgo.ru:8443/mnebyvpn-telegram/webhook || true)"
  if [[ "$code" == 401 ]]; then ready=yes; break; fi
  sleep 1
done
[[ "$ready" == yes ]] || { echo "foreign_8443_auth_probe_failed"; exit 2; }
curl --noproxy '*' -fsS --max-time 8 --resolve cdn.servgo.ru:443:127.0.0.1 \
  https://cdn.servgo.ru/ > "$BACKUP/cdn-after"
cmp -s "$BACKUP/cdn-before" "$BACKUP/cdn-after" || { echo "existing_cdn_443_changed"; exit 2; }
ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:8443' || {
  echo "preexisting_loopback_8443_missing"; exit 2;
}
ss -H -lnt | awk '{print $4}' | grep -Fqx "$BIND_ADDR:8443" || {
  echo "public_8443_not_listening"; exit 2;
}
trap - ERR
echo "foreign_public_8443=https_ready"
echo "foreign_public_8443_without_signature=401"
echo "foreign_local_8443_service_preserved=true"
echo "foreign_existing_443_site_preserved=true"
echo "existing_wireguard_reused=true"
