#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
EXPECTED=c57c5adde8ccbb3ef3bd7bbbbc9f25ee321e1aa9
ROOT=/opt/mnebyvpn
BOT="$ROOT/bot"
ENV="$BOT/web.env"
test "$(id -u)" -eq 0
test -s "$ENV"
test "$(cat "$ROOT/staging/active_sha")" = "$EXPECTED"
test "$(docker inspect --format '{{.Config.Image}}' mnebyvpn-bot-info)" = "mnebyvpn-stage-web:$EXPECTED"
test "$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage -c "SELECT (to_regclass('public.manual_sales') IS NOT NULL AND EXISTS(SELECT 1 FROM deployment_schema_migrations WHERE file_name='0141_owner_manual_sales.sql'))::text")" = true
grep -Eq '^SUPPORT_TELEGRAM_OPERATOR_ID=[1-9][0-9]{0,15}$' "$ENV" || grep -Eq '^DNS_ADMIN_TELEGRAM_ID=[1-9][0-9]{0,15}$' "$ENV"
grep -Eq '^MNEBYDNS_OWNER_LINK_KEY=[a-f0-9]{64}$' "$ENV"
if grep -Fxq 'MNEBYVPN_OFFLINE_SALES_ENABLED=yes' "$ENV"; then
  echo 'manual_sales=already_enabled'
  exit 0
fi
if grep -q '^MNEBYVPN_OFFLINE_SALES_ENABLED=' "$ENV"; then
  grep -Fxq 'MNEBYVPN_OFFLINE_SALES_ENABLED=no' "$ENV"
fi
backup="$(mktemp "$BOT/.manual-sales-backup.XXXXXXXX")"
cp -p "$ENV" "$backup"
rollback() {
  status=$?
  trap - ERR EXIT
  if ((status!=0)); then
    cp -p "$backup" "$ENV" || true
    echo 'manual_sales_env=restored'
  fi
  rm -f "$backup"
  exit "$status"
}
trap rollback ERR EXIT
temp="$(mktemp "$BOT/.manual-sales-next.XXXXXXXX")"
cp -p "$ENV" "$temp"
if grep -Fxq 'MNEBYVPN_OFFLINE_SALES_ENABLED=no' "$temp"; then
  sed -i 's/^MNEBYVPN_OFFLINE_SALES_ENABLED=no$/MNEBYVPN_OFFLINE_SALES_ENABLED=yes/' "$temp"
else
  printf '\nMNEBYVPN_OFFLINE_SALES_ENABLED=yes\n' >> "$temp"
fi
mv "$temp" "$ENV"
bash /tmp/mnebyvpn-owner-sales-promote.sh "$EXPECTED"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-bot-info | grep -Fxq 'MNEBYVPN_OFFLINE_SALES_ENABLED=yes'
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8793/readyz)" = 200
trap - ERR EXIT
rm -f "$backup"
echo 'manual_sales=enabled_owner_only'
