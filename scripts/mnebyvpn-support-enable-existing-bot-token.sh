#!/usr/bin/env bash
# Enable immediate website notifications using the same original Telegram bot.
# Token arrives only via stdin from private GitHub Actions env; never as argv.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo 'Root required'; exit 2; }
IFS= read -r TOKEN || { echo 'Private bot token input unavailable'; exit 2; }
[[ "$TOKEN" =~ ^[0-9]{5,20}:[A-Za-z0-9_-]{25,}$ ]] || { echo 'Invalid token format'; exit 2; }
ROOT=/opt/mnebyvpn
BOT_ENV="$ROOT/bot/web.env"
WEB_ENV="$ROOT/public/web.env"
BOT_PROMOTER="\${1:?Bot promoter required}"
WEB_PROMOTER="\${2:?Web promoter required}"
for path in "$BOT_ENV" "$WEB_ENV" "$BOT_PROMOTER" "$WEB_PROMOTER"; do
  test -s "$path" || { echo 'Private MNEBYVPN prerequisite missing'; exit 2; }
done
for env_file in "$BOT_ENV" "$WEB_ENV"; do
  [[ "$(stat -c '%a' "$env_file")" =~ ^(600|640)$ ]] || {
    echo 'Unsafe private environment permissions'; exit 2;
  }
  grep -Fxq 'MNEBYVPN_ENV=production' "$env_file"
  grep -Eq '^SUPPORT_BRIDGE_SECRET=[0-9a-f]{64}$' "$env_file"
  grep -Eq '^SUPPORT_TELEGRAM_OPERATOR_ID=[1-9][0-9]{5,15}$' "$env_file"
done
operator="$(sed -n 's/^SUPPORT_TELEGRAM_OPERATOR_ID=//p' "$BOT_ENV")"
[[ "$operator" =~ ^[1-9][0-9]{5,15}$ ]] || { echo 'Operator is missing'; exit 2; }
[[ "$(sed -n 's/^SUPPORT_TELEGRAM_OPERATOR_ID=//p' "$WEB_ENV")" == "$operator" ]] ||
  { echo 'Site and bot operator mismatch'; exit 2; }
[[ "$(sed -n 's/^SUPPORT_BRIDGE_SECRET=//p' "$BOT_ENV")" ==
   "$(sed -n 's/^SUPPORT_BRIDGE_SECRET=//p' "$WEB_ENV")" ]] ||
  { echo 'Private support bridge mismatch'; exit 2; }
test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-bot-info)" = true
test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-public-web)" = true
for env_file in "$ROOT/bot/worker.env" "$ROOT/public/subscription-db.env"; do
  if [[ -f "$env_file" ]] && grep -q '^TELEGRAM_TOKEN_BOT=' "$env_file"; then
    echo 'Bot token is also defined in another mounted environment'; exit 2
  fi
done
SHA="$(cat "$ROOT/staging/active_sha")"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid stage SHA'; exit 2; }
[[ "$(cat "$ROOT/public/active_sha")" == "$SHA" ]] ||
  { echo 'Website release differs from staging'; exit 2; }
[[ "$(docker inspect -f '{{.Config.Image}}' mnebyvpn-bot-info)" ==
   "mnebyvpn-stage-web:$SHA" ]] ||
  { echo 'Bot release differs from staging'; exit 2; }
docker image inspect "mnebyvpn-stage-web:$SHA" >/dev/null
exec 8>/run/lock/mnebyvpn-support-token-activation.lock
flock -w 20 8 || { echo 'Support token activation already in progress'; exit 2; }
BACKUP="$(mktemp -d "$ROOT/private/support-token-rollback.XXXXXXXX")"
chmod 700 "$BACKUP"
cp -p "$BOT_ENV" "$BACKUP/bot.env"
cp -p "$WEB_ENV" "$BACKUP/web.env"
changed=0
finish() {
  status=$?
  trap - EXIT
  if (( status != 0 && changed == 1 )); then
    echo 'Support token activation failed; restoring previous private configuration' >&2
    cp -p "$BACKUP/bot.env" "$BOT_ENV"
    cp -p "$BACKUP/web.env" "$WEB_ENV"
    bash "$WEB_PROMOTER" "$SHA" >/dev/null 2>&1 || true
    bash "$BOT_PROMOTER" "$SHA" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$BACKUP"
  unset TOKEN
  exit "$status"
}
trap finish EXIT
changed=1
for env_file in "$BOT_ENV" "$WEB_ENV"; do
  temp="$(mktemp "$env_file.token.XXXXXXXX")"
  grep -Ev '^TELEGRAM_TOKEN_BOT=' "$env_file" > "$temp" || true
  printf 'TELEGRAM_TOKEN_BOT=%s\n' "$TOKEN" >> "$temp"
  chmod 600 "$temp"
  mv -f -- "$temp" "$env_file"
done
unset TOKEN
# Recreate only existing MNEBYVPN site/bot; canaries test before promotion.
bash "$WEB_PROMOTER" "$SHA"
bash "$BOT_PROMOTER" "$SHA"
[[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
  http://127.0.0.1:8793/readyz)" == 200 ]]
curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8792/api/support/status |
  python3 -c 'import json,sys; assert json.load(sys.stdin)["available"] is True'
# Genuine Telegram delivery from the site container's actual egress path.
# Never print the token, its URL, or the destination operator ID.
docker exec mnebyvpn-public-web node --input-type=module -e '
  const token=process.env.TELEGRAM_TOKEN_BOT??"";
  const operator=Number(process.env.SUPPORT_TELEGRAM_OPERATOR_ID??"");
  if(!/^[0-9]{5,20}:[A-Za-z0-9_-]{25,}$/.test(token)||
    !Number.isSafeInteger(operator)||operator<=0)process.exit(2);
  try {
    const response=await fetch("https://api.telegram.org/bot"+token+"/sendMessage",{
      method:"POST",signal:AbortSignal.timeout(8000),
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({chat_id:operator,
        text:"✅ MNEBYVPN: уведомления о новых заявках с сайта включены. Проверка доставки."}),
    });
    const result=await response.json();
    if(!response.ok||result?.ok!==true)throw new Error("Delivery rejected");
    console.log("real_operator_notification_delivered=true");
  }catch {console.error("Operator notification test failed");process.exit(2);}
'
echo "support_deployed_sha=$SHA"
echo 'support_private_token_loaded=true'
echo 'automatic_site_notifications=true'
echo 'existing_bot_and_telegram_webhook_unchanged=true'
