#!/usr/bin/env bash
# Activate support in the original MNEBYVPN Telegram webhook; no Bot API token.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo 'Root required'; exit 2; }
ROOT=/opt/mnebyvpn
KEY="$ROOT/private/support-transfer-oaep.pem"
CIPHER="${1:?Encrypted operator file required}"
BOT_PROMOTER="${2:?Bot promoter required}"
WEB_PROMOTER="${3:?Web promoter required}"
for f in "$KEY" "$CIPHER" "$BOT_PROMOTER" "$WEB_PROMOTER"; do
  [[ -s "$f" ]] || { echo 'Missing support prerequisite'; exit 2; }
done
OP_LINE="$(base64 -d "$CIPHER" | openssl pkeyutl -decrypt \
  -inkey "$KEY" -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256)" || { echo 'Operator identity decrypt failed'; exit 2; }
[[ "$OP_LINE" =~ ^SUPPORT_TELEGRAM_OPERATOR_ID=[1-9][0-9]{5,15}$ ]] ||
  { echo 'Invalid operator identity'; exit 2; }
OP_ID="${OP_LINE#*=}"
SHA="$(cat "$ROOT/staging/active_sha")"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid stage SHA'; exit 2; }
test "$(cat "$ROOT/public/active_sha")" = "$SHA"
test "$(docker inspect -f '{{.Config.Image}}' mnebyvpn-bot-info)" = "mnebyvpn-stage-web:$SHA"
test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-stage-postgres)" = true
BOT_SRC="$ROOT/releases/$SHA/apps/service/src/telegram-cabinet-server.ts"
WEB_SRC="$ROOT/releases/$SHA/apps/web/src/server.ts"
test -s "$BOT_SRC" && test -s "$WEB_SRC"
grep -Fq 'operatorSupportInbox' "$BOT_SRC"
grep -Fq 'if(!support.botToken)' "$BOT_SRC"
grep -Fq 'if(!support.botToken)' "$WEB_SRC"
test "$(docker exec mnebyvpn-stage-postgres psql -At \
  -U mnebyvpn_stage -d mnebyvpn_stage \
  -c "SELECT to_regclass('public.website_support_tickets')::text")" = website_support_tickets
grep -Fq 'SUPPORT_BRIDGE_SECRET' "$BOT_SRC"
grep -Fq 'SUPPORT_BRIDGE_SECRET' "$WEB_SRC"
grep -Fq '/api/support/operator-inbox' "$WEB_SRC"
# The public website uses an INDEPENDENT PostgreSQL database. Apply ONLY
# the additive support-ticket migration in that known site-owned database.
SITE_MIGRATION="$ROOT/releases/$SHA/db/migrations/0018_website_support_tickets.sql"
test -s "$SITE_MIGRATION"
test "$(docker exec mnebyvpn-stage-postgres psql -At -U mnebyvpn_stage \
  -d mnebyvpn_public -c 'SELECT current_database()')" = mnebyvpn_public
site_table="$(docker exec mnebyvpn-stage-postgres psql -At -U mnebyvpn_stage \
  -d mnebyvpn_public -c "SELECT to_regclass('public.website_support_tickets')::text")"
if [[ -z "$site_table" ]]; then
  {
    printf 'BEGIN;\n'
    cat "$SITE_MIGRATION"
    printf '\nGRANT SELECT, INSERT, UPDATE, DELETE ON public.website_support_tickets TO mnebyvpn_public;\nCOMMIT;\n'
  } | docker exec -i mnebyvpn-stage-postgres psql -v ON_ERROR_STOP=1 -q \
    -U mnebyvpn_stage -d mnebyvpn_public
else
  [[ "$site_table" == website_support_tickets ]] || { echo 'Unexpected site support table'; exit 2; }
fi
docker exec mnebyvpn-stage-postgres psql -v ON_ERROR_STOP=1 -q \
  -U mnebyvpn_stage -d mnebyvpn_public \
  -c 'GRANT SELECT, INSERT, UPDATE, DELETE ON public.website_support_tickets TO mnebyvpn_public'
# Check the public role has ONLY data access, no schema creation.
test "$(docker exec mnebyvpn-stage-postgres psql -At -U mnebyvpn_stage \
  -d mnebyvpn_public \
  -c "SELECT has_table_privilege('mnebyvpn_public','public.website_support_tickets','SELECT,INSERT,UPDATE,DELETE')")" = t
BRIDGE_SECRET="$(openssl rand -hex 32)"
[[ "$BRIDGE_SECRET" =~ ^[0-9a-f]{64}$ ]] || { echo 'Support bridge entropy missing'; exit 2; }
BOT_ENV="$ROOT/bot/web.env"
WEB_ENV="$ROOT/public/web.env"
test -s "$BOT_ENV" && test -s "$WEB_ENV"
BACKUP="$(mktemp -d "$ROOT/private/support-webhook-rollback.XXXXXXXX")"
chmod 700 "$BACKUP"
cp -p "$BOT_ENV" "$BACKUP/bot.env"
cp -p "$WEB_ENV" "$BACKUP/web.env"
changed=0
cleanup() {
  status=$?
  trap - EXIT
  if (( status != 0 && changed == 1 )); then
    echo 'Support configuration failed; restoring previous MNEBYVPN app settings' >&2
    cp -p "$BACKUP/bot.env" "$BOT_ENV"
    cp -p "$BACKUP/web.env" "$WEB_ENV"
    bash "$BOT_PROMOTER" "$SHA" >/dev/null 2>&1 || true
    bash "$WEB_PROMOTER" "$SHA" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$BACKUP"
  exit "$status"
}
trap cleanup EXIT
for env_file in "$BOT_ENV" "$WEB_ENV"; do
  temp="$(mktemp "$env_file.support.XXXXXXXX")"
  grep -Ev '^(SUPPORT_TELEGRAM_OPERATOR_ID|SUPPORT_BRIDGE_SECRET)=' "$env_file" > "$temp" || true
  printf 'SUPPORT_TELEGRAM_OPERATOR_ID=%s\nSUPPORT_BRIDGE_SECRET=%s\n' "$OP_ID" "$BRIDGE_SECRET" >> "$temp"
  chmod 600 "$temp"
  mv -f "$temp" "$env_file"
done
changed=1
# Real environment changes require safe canary + container re-creation.
bash "$BOT_PROMOTER" "$SHA"
bash "$WEB_PROMOTER" "$SHA"
[[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
  --max-time 5 http://127.0.0.1:8793/readyz)" = 200 ]]
curl --noproxy '*' -fsS --max-time 7 \
  http://127.0.0.1:8792/api/support/status |
  python3 -c 'import json,sys; assert json.load(sys.stdin)["available"] is True'
[[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
  -X POST -H 'Content-Type: application/json' -d '{"update_id":1}' \
  http://127.0.0.1:8793/webhooks/telegram)" = 401 ]]
echo "support_deployed_sha=$SHA"
echo 'support_bot=existing_webhook'
echo 'support_site=queue_ready'
echo 'support_private_bridge=authenticated'
echo 'no_new_token_or_bot=true'
