#!/usr/bin/env bash
# One-time MNEBYVPN support activation. Operates ONLY on two owned app containers.
# Input: existing primary Bot API token via encrypted SSH stdin, NEVER CLI args/logs.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo 'Root required' >&2; exit 2; }
ROOT=/opt/mnebyvpn
KEY="$ROOT/private/support-transfer-oaep.pem"
CIPHER="${1:?Encrypted owner configuration path missing}"
BOT_PROMOTER="${2:?Bot promotion script missing}"
WEB_PROMOTER="${3:?Website promotion script missing}"
[[ -s "$KEY" && -s "$CIPHER" && -s "$BOT_PROMOTER" && -s "$WEB_PROMOTER" ]] || {
  echo 'Support activation prerequisites absent' >&2; exit 2;
}
command -v openssl >/dev/null
command -v docker >/dev/null
command -v python3 >/dev/null
command -v curl >/dev/null
read -r BOT_TOKEN || { echo 'Bot credential not received' >&2; exit 2; }
[[ "$BOT_TOKEN" =~ ^[0-9]{5,20}:[A-Za-z0-9_-]{25,}$ ]] || {
  echo 'Invalid Bot API token shape' >&2; exit 2;
}
OP_LINE="$(base64 -d "$CIPHER" |
  openssl pkeyutl -decrypt -inkey "$KEY" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256)" || {
  echo 'Operator identity decrypt failed' >&2; exit 2;
}
[[ "$OP_LINE" =~ ^SUPPORT_TELEGRAM_OPERATOR_ID=[1-9][0-9]{5,15}$ ]] || {
  echo 'Invalid operator identity' >&2; exit 2;
}
OPERATOR_ID="${OP_LINE#*=}"
# Verify token belongs to the exact already-published production bot.
MAIN_BOT_TOKEN="$BOT_TOKEN" python3 - <<'PY'
import json,os,urllib.request
token=os.environ['MAIN_BOT_TOKEN']
url='https://api.telegram.org/bot'+token+'/getMe'
with urllib.request.urlopen(url,timeout=9) as r:
    payload=json.load(r)
if not payload.get('ok') or payload.get('result',{}).get('username','').lower()!='mnebyvpn_bot':
    raise SystemExit('Wrong Telegram bot account; no changes made')
print('primary_bot_identity_verified=true')
PY
SHA="$(cat "$ROOT/staging/active_sha")"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'No verified stage SHA' >&2; exit 2; }
test "$(cat "$ROOT/public/active_sha")" = "$SHA"
test "$(docker inspect -f '{{.Config.Image}}' mnebyvpn-bot-info)" = "mnebyvpn-stage-web:$SHA"
test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-stage-postgres)" = true
test "$(docker exec mnebyvpn-stage-postgres psql -At -U mnebyvpn_stage -d mnebyvpn_stage -c "SELECT to_regclass('public.website_support_tickets')::text")" = website_support_tickets
for file in "$ROOT/bot/web.env" "$ROOT/public/web.env"; do
  test -s "$file"
  test "$(stat -c %a "$file")" = 600 || chmod 600 "$file"
done
# Keep backups in the private area until both new images pass readiness.
BOT_ENV="$ROOT/bot/web.env"
WEB_ENV="$ROOT/public/web.env"
BACKUP_DIR="$(mktemp -d "$ROOT/private/support-activation.XXXXXXXX")"
chmod 700 "$BACKUP_DIR"
cp -p "$BOT_ENV" "$BACKUP_DIR/bot.env"
cp -p "$WEB_ENV" "$BACKUP_DIR/web.env"
applied=0
cleanup() {
  status=$?
  trap - EXIT
  if (( status != 0 && applied == 1 )); then
    echo 'Support activation failed; restoring previous MNEBYVPN configuration' >&2
    cp -p "$BACKUP_DIR/bot.env" "$BOT_ENV"
    cp -p "$BACKUP_DIR/web.env" "$WEB_ENV"
    bash "$BOT_PROMOTER" "$SHA" >/dev/null 2>&1 || true
    bash "$WEB_PROMOTER" "$SHA" >/dev/null 2>&1 || true
    echo 'Rollback attempted; independently verify bot/site services' >&2
  fi
  rm -rf -- "$BACKUP_DIR"
  exit "$status"
}
trap cleanup EXIT
for file in "$BOT_ENV" "$WEB_ENV"; do
  tmp="$(mktemp "$file.support.XXXXXXXX")"
  grep -Ev '^(TELEGRAM_TOKEN_BOT|SUPPORT_TELEGRAM_OPERATOR_ID)=' "$file" > "$tmp" || true
  printf 'TELEGRAM_TOKEN_BOT=%s\nSUPPORT_TELEGRAM_OPERATOR_ID=%s\n' "$BOT_TOKEN" "$OPERATOR_ID" >> "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$file"
done
applied=1
# Standard reviewed deployment scripts recreate containers with fresh env files,
# canary health checks and rollback. docker restart alone would NOT reload env!
bash "$BOT_PROMOTER" "$SHA"
bash "$WEB_PROMOTER" "$SHA"
BOT_HTTP="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8793/readyz)"
test "$BOT_HTTP" = 200
# Requires applied 0018 DB migration as well as secrets in the web process.
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8792/api/support/status |
  python3 -c 'import json,sys; assert json.load(sys.stdin)["available"] is True'
# Prove Telegram is permitted to notify this operator from the SAME bot.
MAIN_BOT_TOKEN="$BOT_TOKEN" SUPPORT_OPERATOR="$OPERATOR_ID" python3 - <<'PY'
import json,os,urllib.request
url='https://api.telegram.org/bot'+os.environ['MAIN_BOT_TOKEN']+'/sendMessage'
body=json.dumps({
    'chat_id':int(os.environ['SUPPORT_OPERATOR']),
    'text':'✅ MNEBYVPN: уведомления поддержки подключены. Ответить клиенту можно через «Ответить» на его обращение.',
}).encode()
req=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'},method='POST')
with urllib.request.urlopen(req,timeout=9) as response:
    result=json.load(response)
if result.get('ok') is not True:
    raise SystemExit('Telegram did not confirm operator notification')
print('operator_notification_delivered=true')
PY
echo "support_runtime_sha=$SHA"
echo 'support_site_status=available'
echo 'support_bot_status=ready'
echo 'support_primary_bot_token=secured'
