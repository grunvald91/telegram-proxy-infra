#!/usr/bin/env bash
# Add ONLY VPN subscription GET paths to the two existing, isolated MNEBYVPN
# WireGuard/8443 Nginx vhosts. No changes to TLS, Telegram, Xray, firewall,
# ports, general websites or other services.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || exit 2
MODE="${1:?expected ru or foreign}"
case "$MODE" in
  ru)
    CFG=/etc/nginx/conf.d/mnebyvpn-wg-telegram.conf
    UPSTREAM=http://127.0.0.1:8792
    ANCHOR='location = /webhooks/telegram {'
    ;;
  foreign)
    CFG=/etc/nginx/sites-available/mnebyvpn-telegram-8443.conf
    UPSTREAM=http://10.66.77.2:8794
    ANCHOR='location = /mnebyvpn-telegram/webhook {'
    ;;
  *) echo 'Invalid gateway target'; exit 2 ;;
esac
test -f "$CFG"
grep -Fq "$ANCHOR" "$CFG"
grep -Fq 'location / { return 404; }' "$CFG"
nginx -t >/dev/null 2>&1
LOCK=/run/lock/mnebyvpn-subscription-gateway.lock
exec 9>"$LOCK"
flock -w 20 9 || exit 2
mkdir -p /opt/mnebyvpn/backups
BACKUP="$(mktemp /opt/mnebyvpn/backups/sub-gateway-${MODE}-XXXXXXXX.conf)"
cp -p "$CFG" "$BACKUP"
restore(){
  local code=$?
  trap - ERR
  if ((code != 0)); then
    cp -p "$BACKUP" "$CFG"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx
    echo "subscription_gateway_${MODE}_restored=true"
  fi
  exit "$code"
}
trap restore ERR

python3 - "$CFG" "$UPSTREAM" <<'PY'
from pathlib import Path
import sys
path=Path(sys.argv[1])
upstream=sys.argv[2]
src=path.read_text()
tag='# MNEBYVPN_USER_SUBSCRIPTION_GET_GATEWAY'
anchor='    location / { return 404; }\n'
if tag in src:
    if (src.count(tag)!=1 or src.count('proxy_pass '+upstream+';')<3):
        raise SystemExit('Existing subscription gateway differs; manual review required')
    print('subscription_gateway_existing_verified=true')
else:
    if src.count(anchor)!=1:
        raise SystemExit('Expected exactly one default deny location')
    shared='''        access_log off;
        limit_except GET { deny all; }
        proxy_http_version 1.1;
        proxy_set_header Host mnebyvpn.site;
        proxy_set_header Cookie "";
        proxy_set_header Authorization "";
        proxy_set_header X-Forwarded-For "";
        proxy_connect_timeout 3s;
        proxy_read_timeout 12s;
        proxy_send_timeout 12s;
        proxy_buffering off;
        add_header Cache-Control "no-store" always;
'''
    rules='    '+tag+'\n'
    for matcher in (
        'location ~ "^/sub/[A-Za-z0-9_-]{43}$"',
        'location ~ "^/install/[A-Za-z0-9_-]{43}$"',
        'location = /vpn-install.js',
    ):
        rules+='    '+matcher+' {\n'+shared+f'        proxy_pass {upstream};\n'+'    }\n'
    path.write_text(src.replace(anchor,rules+anchor))
    print('subscription_gateway_added=true')
PY
nginx -t >/dev/null
systemctl reload nginx
if [[ "$MODE" == foreign ]]; then
  BIND="$(ip -4 -o addr show dev eth0 | awk '$3=="inet" {print $4}' | cut -d/ -f1 | head -1)"
  [[ "$BIND" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]
  for request in '/sub/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' \
                 '/install/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA?client=incy'; do
    code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 7 \
      --resolve "cdn.servgo.ru:8443:$BIND" \
      "https://cdn.servgo.ru:8443$request" || true)"
    echo "foreign_invalid_subscription_status=$code"
    test "$code" = 404
  done
  curl --noproxy '*' -fsS --max-time 7 \
    --resolve "cdn.servgo.ru:8443:$BIND" \
    https://cdn.servgo.ru:8443/vpn-install.js | grep -Fq 'incy://import/'
  code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 7 \
    --resolve "cdn.servgo.ru:8443:$BIND" \
    -X POST -H 'Content-Type: application/json' -d '{"update_id":1}' \
    https://cdn.servgo.ru:8443/mnebyvpn-telegram/webhook)"
  test "$code" = 401
  echo 'foreign_existing_telegram_auth=401'
else
  test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
    --max-time 4 http://127.0.0.1:8792/healthz)" = 200
  echo 'ru_site_health=200'
fi
trap - ERR
echo "subscription_gateway_${MODE}_ready=true"
