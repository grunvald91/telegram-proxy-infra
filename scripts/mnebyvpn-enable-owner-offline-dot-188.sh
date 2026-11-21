#!/usr/bin/env bash
# Owner-only DoT flag. No public DNS rollout and no customer records changed.
set -Eeuo pipefail
umask 077
EXPECTED=2b632f1f4b65f6716a28451cc69c89fabc5d7a8c
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
# No public customer DNS setting, product or existing profile is changed.
grep -Fxq 'MNEBYVPN_OFFLINE_SALES_ENABLED=yes' "$ENV"
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8859/readyz)" = 200
test "$(docker inspect -f '{{.State.Running}}' mnebydns-personal-dot-private)" = true
test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-vpn-worker)" = true
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-vpn-worker | grep -Fxq 'MNEBYDNS_SMART_DNS_WORKER=enabled'
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-vpn-worker | grep -Eq '^MNEBYDNS_PERSONAL_DOT_HEALTH_URL=http://127[.]0[.]0[.]1:[0-9]+/'
test "$(docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage -c "SELECT (to_regprocedure('public.issue_personal_dns_credential(uuid,text,text,bigint)') IS NOT NULL AND has_function_privilege(current_user,'public.issue_personal_dns_credential(uuid,text,text,bigint)','EXECUTE'))::text")" = true
if grep -Fxq 'MNEBYVPN_OFFLINE_DNS_ISSUE_ENABLED=yes' "$ENV"; then
  echo 'owner_offline_dns=already_enabled'
  exit 0
fi
if grep -q '^MNEBYVPN_OFFLINE_DNS_ISSUE_ENABLED=' "$ENV"; then
  grep -Fxq 'MNEBYVPN_OFFLINE_DNS_ISSUE_ENABLED=no' "$ENV"
fi
changed=0
temp=''
backup="$(mktemp "$BOT/.owner-offline-dot-backup.XXXXXXXX")"
cp -p "$ENV" "$backup"
rollback() {
  status=$?
  trap - ERR EXIT
  if ((status!=0)); then
    cp -p "$backup" "$ENV" || true
    if [[ "$changed" == 1 ]]; then
      bash /tmp/mnebyvpn-owner-offline-dns-promote.sh "$EXPECTED" ||
        echo 'owner_offline_dns_repromote_needs_review=true'
    fi
    echo 'owner_offline_dns_env=restored'
  fi
  if [[ -n "$temp" ]]; then rm -f "$temp"; fi
  rm -f "$backup"
  exit "$status"
}
trap rollback ERR EXIT
temp="$(mktemp "$BOT/.owner-offline-dot-next.XXXXXXXX")"
cp -p "$ENV" "$temp"
if grep -Fxq 'MNEBYVPN_OFFLINE_DNS_ISSUE_ENABLED=no' "$temp"; then
  sed -i 's/^MNEBYVPN_OFFLINE_DNS_ISSUE_ENABLED=no$/MNEBYVPN_OFFLINE_DNS_ISSUE_ENABLED=yes/' "$temp"
else
  printf '\nMNEBYVPN_OFFLINE_DNS_ISSUE_ENABLED=yes\n' >> "$temp"
fi
mv "$temp" "$ENV"
changed=1
bash /tmp/mnebyvpn-owner-offline-dns-promote.sh "$EXPECTED"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-bot-info | grep -Fxq 'MNEBYVPN_OFFLINE_DNS_ISSUE_ENABLED=yes'
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8793/readyz)" = 200
trap - ERR EXIT
rm -f "$backup"
echo 'owner_offline_dns=enabled_private_sales_only'
