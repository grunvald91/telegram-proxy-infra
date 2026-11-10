#!/usr/bin/env bash
# Enable ONE-tap Telegram Stars invoices from the already-running MNEBYVPN
# cabinet, using the existing original @MnebyVPN_bot token. No new bot,
# proxy, web container, nginx rule or payment mechanism is created.
# The token arrives exclusively through authenticated SSH stdin.
set -Eeuo pipefail
set +x
umask 077
[[ "$(id -u)" == 0 ]] || { echo 'Root required'; exit 2; }
SHA="${1:?Expected already deployed SHA}"
PROMOTER="${2:?Bot promoter path required}"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || exit 2
[[ -s "$PROMOTER" ]] || exit 2
IFS= read -r TOKEN || { echo 'Private bot token was not supplied'; exit 2; }
[[ "$TOKEN" =~ ^[0-9]{5,20}:[A-Za-z0-9_-]{25,}$ ]] || {
  echo 'Invalid original bot token format'; exit 2;
}
ROOT=/opt/mnebyvpn
ENV_FILE="$ROOT/bot/web.env"
[[ -s "$ENV_FILE" ]] || { echo 'Missing private bot settings'; exit 2; }
[[ "$(stat -c '%a' "$ENV_FILE")" =~ ^(600|640)$ ]] || exit 2
grep -Fxq 'MNEBYVPN_ENV=production' "$ENV_FILE"
grep -Fxq 'BOT_PUBLIC_INFO_ONLY=no' "$ENV_FILE"
grep -Eq '^TELEGRAM_WEBHOOK_SECRET_SHA256=[0-9a-f]{64}$' "$ENV_FILE"
grep -Eq '^DATABASE_URL=postgresql://' "$ENV_FILE"
[[ "$(cat "$ROOT/staging/active_sha")" == "$SHA" ]] || {
  echo 'Staged source SHA changed, refusing activation'; exit 2;
}
[[ "$(docker inspect -f '{{.Config.Image}}' mnebyvpn-bot-info)" == "mnebyvpn-stage-web:$SHA" ]] || {
  echo 'Active Telegram bot differs from verified release'; exit 2;
}
[[ "$(curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8793/readyz |
  python3 -c 'import json,sys; assert json.load(sys.stdin).get("ready") is True; print("ready")')" == ready ]]
exec 8>/run/lock/mnebyvpn-stars-token-activation.lock
flock -w 60 8 || exit 2

# Fail-closed: prepare an atomic settings update and keep a private rollback.
backup="$(mktemp "$ROOT/bot/stars-original-env.XXXXXXXX")"
cp -p -- "$ENV_FILE" "$backup"
changed=no
finish() {
  status=$?
  trap - EXIT
  if (( status != 0 )) && [[ "$changed" == yes ]]; then
    echo 'Stars token activation failed; restoring original bot settings' >&2
    cp -p -- "$backup" "$ENV_FILE"
    bash "$PROMOTER" "$SHA" >/dev/null 2>&1 || true
  fi
  rm -f -- "$backup"
  unset TOKEN
  exit "$status"
}
trap finish EXIT

temp="$(mktemp "$ROOT/bot/stars-new-env.XXXXXXXX")"
grep -Ev '^TELEGRAM_TOKEN_BOT=' "$ENV_FILE" >"$temp" || true
printf 'TELEGRAM_TOKEN_BOT=%s\n' "$TOKEN" >>"$temp"
chown --reference="$ENV_FILE" "$temp"
chmod 600 "$temp"
mv -f -- "$temp" "$ENV_FILE"
changed=yes
unset TOKEN

# The established bot promoter canaries readiness, atomically replaces
# only mnebyvpn-bot-info and rolls back its container on failure.
bash "$PROMOTER" "$SHA"
# Validate outbound API access FROM THE BOT CONTAINER, not the CI runner.
# Never print bot credentials, request URL, Telegram response, chat IDs or IP.
docker exec mnebyvpn-bot-info node --input-type=module -e '
  const token=process.env.TELEGRAM_TOKEN_BOT??"";
  if(!/^[0-9]{5,20}:[A-Za-z0-9_-]{25,}$/.test(token))process.exit(2);
  try {
    const response=await fetch("https://api.telegram.org/bot"+token+"/getMe",{
      method:"POST",signal:AbortSignal.timeout(9500),
      headers:{"Content-Type":"application/json"},body:"{}",
      redirect:"error"});
    const data=await response.json();
    if(!response.ok||data?.ok!==true||
      String(data?.result?.username??"").toLowerCase()!=="mnebyvpn_bot")
      process.exit(2);
  } catch { process.exit(2); }
  console.log("bot_outbound_invoice_api_ready=true");
'
echo 'stars_widget_original_bot_token_installed=true'
echo 'stars_widget_one_tap_invoice_transport_ready=true'
echo 'only_mnebyvpn_bot_service_restarted=true'
