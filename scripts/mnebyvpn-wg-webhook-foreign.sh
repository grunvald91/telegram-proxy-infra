#!/usr/bin/env bash
# Exact path on the EXISTING cdn.servgo.ru TLS vhost -> existing WG -> RU bot.
# Preserve all foreign MTProxy, CDN, SNI and WireGuard listeners.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || { echo "root_required"; exit 2; }
exec 9>/run/lock/mnebyvpn-wg-webhook-foreign.lock
flock -n 9 || { echo "foreign_deploy_locked"; exit 2; }
ip -4 addr show dev tg-relay | grep -Fq '10.66.77.1/' || { echo "missing_foreign_wg"; exit 2; }
nginx -t >/dev/null
probe="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 -X POST -H 'Content-Type: application/json' -d '{"update_id":1}' http://10.66.77.2:8794/webhooks/telegram || true)"
[[ "$probe" == 401 ]] || { echo "existing_WG_bridge_unreachable_or_unprotected:$probe"; exit 2; }
SITE=/etc/nginx/sites-enabled/cdn-servgo
test -f "$SITE" && [[ "$(readlink -f "$SITE")" == /etc/nginx/* ]] || {
  echo "foreign_cdn_vhost_not_found"; exit 2;
}
REAL_SITE="$(readlink -f "$SITE")"
BACKUP="$(mktemp /root/mnebyvpn-cdn-webhook-XXXXXXXX.bak)"
chmod 600 "$BACKUP"
cp -p "$REAL_SITE" "$BACKUP"
rollback(){
  set +e
  cp -p "$BACKUP" "$REAL_SITE"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx
  echo "foreign_cdn_route_rolled_back=true"
}
trap rollback ERR
BEFORE_HTML="$(mktemp)"
AFTER_HTML="$(mktemp)"
# Direct loopback SNI test avoids regional filtering of public TCP443.
curl -fsS --noproxy '*' --max-time 8 --resolve cdn.servgo.ru:443:127.0.0.1 \
  https://cdn.servgo.ru/ > "$BEFORE_HTML"
python3 - "$REAL_SITE" <<'PY'
import sys,pathlib,re
path=pathlib.Path(sys.argv[1])
source=path.read_text()
if 'location = /mnebyvpn-telegram/webhook {' in source:
  if (source.count('location = /mnebyvpn-telegram/webhook {')!=1 or
      'http://10.66.77.2:8794/webhooks/telegram' not in source):
    raise SystemExit('Conflicting Telegram route already present')
  print('foreign_webhook_route_already_present=true')
else:
  marker=re.compile(r'(?m)^([ \t]*)server_name[ \t]+cdn\.servgo\.ru[ \t]*;[ \t]*$')
  matches=list(marker.finditer(source))
  if len(matches)!=1:raise SystemExit('CDN server name is not unique')
  if 'listen 127.0.0.1:4453' not in source:
    raise SystemExit('CDN listener is not the previously checked 4453')
  match=matches[0]
  indent=match.group(1)
  block=f'''
{indent}# Isolated MNEBYVPN webhook: TLS at foreign CDN, payload over existing WireGuard.
{indent}location = /mnebyvpn-telegram/webhook {{
{indent}    access_log off;
{indent}    client_max_body_size 64k;
{indent}    limit_except POST {{ deny all; }}
{indent}    proxy_pass http://10.66.77.2:8794/webhooks/telegram;
{indent}    proxy_http_version 1.1;
{indent}    proxy_set_header Host mnebyvpn.site;
{indent}    proxy_set_header X-Telegram-Bot-Api-Secret-Token $http_x_telegram_bot_api_secret_token;
{indent}    proxy_set_header X-Forwarded-Proto https;
{indent}    proxy_connect_timeout 3s;
{indent}    proxy_read_timeout 12s;
{indent}    proxy_send_timeout 12s;
{indent}    proxy_buffering off;
{indent}}}
'''
  source=source[:match.end()]+block+source[match.end():]
  path.write_text(source)
  print('foreign_webhook_route_added=true')
PY
nginx -t >/dev/null
systemctl reload nginx
code=no
for attempt in $(seq 1 12); do
  code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 8 \
    --resolve cdn.servgo.ru:443:127.0.0.1 -X POST \
    -H 'Content-Type: application/json' -d '{"update_id":1}' \
    https://cdn.servgo.ru/mnebyvpn-telegram/webhook || true)"
  if [[ "$code" == 401 ]]; then break; fi
  sleep 1
done
test "$code" = 401 || { echo "foreign_webhook_auth_check_failed:$code"; exit 2; }
curl -fsS --noproxy '*' --max-time 8 --resolve cdn.servgo.ru:443:127.0.0.1 \
  https://cdn.servgo.ru/ > "$AFTER_HTML"
cmp -s "$BEFORE_HTML" "$AFTER_HTML" || { echo "cdn_homepage_changed"; exit 2; }
rm -f "$BEFORE_HTML" "$AFTER_HTML"
trap - ERR
echo "foreign_telegram_webhook_over_existing_WG=ready"
echo "foreign_telegram_unsigned_request=401"
echo "foreign_cdn_homepage_unchanged=true"
echo "foreign_proxy_services_not_restarted=true"
