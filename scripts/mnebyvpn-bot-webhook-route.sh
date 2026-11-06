#!/usr/bin/env bash
# Add only one exact Telegram webhook location to the existing MNEBYVPN TLS vhost.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -n 9 || { echo 'route lock unavailable'; exit 2; }
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8793/healthz)" = 200
VHOST=/etc/nginx/sites-available/mnebyvpn-tls.conf
test -f "$VHOST"
grep -Fq 'listen 127.0.0.1:18449 ssl;' "$VHOST"
grep -Fq 'proxy_pass http://127.0.0.1:8792;' "$VHOST"
mkdir -p /opt/mnebyvpn/backups
BACKUP="$(mktemp /opt/mnebyvpn/backups/bot-vhost-XXXXXXXX.conf)"
chmod 600 "$BACKUP"
cp -p "$VHOST" "$BACKUP"
rollback(){
  cp -p "$BACKUP" "$VHOST"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx || true
}
trap rollback ERR
python3 - "$VHOST" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1])
s=p.read_text()
if 'location = /webhooks/telegram {' in s:
  print('bot_route_already_present=true')
else:
  marker='    location / {\n        proxy_pass http://127.0.0.1:8792;'
  if s.count(marker)!=1:raise SystemExit('Cannot locate original public site location')
  added='''    location = /webhooks/telegram {
        access_log off;
        client_max_body_size 64k;
        limit_except POST { deny all; }
        proxy_pass http://127.0.0.1:8793;
        proxy_connect_timeout 3s;
        proxy_send_timeout 10s;
        proxy_read_timeout 12s;
        proxy_set_header Host $host;
        proxy_set_header X-Telegram-Bot-Api-Secret-Token $http_x_telegram_bot_api_secret_token;
    }
'''
  p.write_text(s.replace(marker,added+marker))
  print('bot_route_added=true')
PY
nginx -t
systemctl reload nginx
ready=no
for attempt in $(seq 1 12); do
  response="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    --resolve mnebyvpn.site:443:127.0.0.1 \
    -X POST -H 'Content-Type: application/json' -d '{"update_id":1}' \
    https://mnebyvpn.site/webhooks/telegram || true)"
  if [[ "$response" == 401 ]]; then ready=yes; break; fi
  sleep 1
done
test "$ready" = yes || { echo 'Telegram webhook auth route did not reach backend'; exit 2; }
trap - ERR
echo 'telegram_webhook_tls_route=healthy'
echo 'telegram_webhook_auth_required=true'
echo 'telegram_bot_token_on_server=false'
