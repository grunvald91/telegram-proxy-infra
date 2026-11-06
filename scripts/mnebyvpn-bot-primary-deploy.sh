#!/usr/bin/env bash
# Promote Telegram-first cabinet on existing server188; preserve Telegram
# relay89 -> WireGuard -> loopback route and all unrelated services.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-bot-info.lock
flock -n 9 || { echo "Telegram deploy in progress"; exit 2; }
ROOT=/opt/mnebyvpn
STAGE="$ROOT/staging"
BOT="$ROOT/bot"
SHA="$(cat "$STAGE/active_sha")"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || exit 2
SOURCE="$ROOT/releases/$SHA/apps/service/src/telegram-cabinet-server.ts"
IMAGE="mnebyvpn-stage-web:$SHA"
test -s "$SOURCE"
docker image inspect "$IMAGE" >/dev/null
test -s "$STAGE/web.env"
test -s "$BOT/web.env"
DB="$(sed -n 's/^DATABASE_URL=//p' "$STAGE/web.env")"
DIGEST="$(sed -n 's/^TELEGRAM_WEBHOOK_SECRET_SHA256=//p' "$BOT/web.env")"
[[ "$DB" == postgresql://* ]] || { echo "database_url_absent"; exit 2; }
[[ "$DIGEST" =~ ^[a-f0-9]{64}$ ]] || { echo "webhook_digest_absent"; exit 2; }
if ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:8793'; then
  docker ps --format '{{.Names}}' | grep -qx 'mnebyvpn-bot-info' || {
    echo "refusing_to_take_occupied_8793"; exit 2;
  }
fi
mkdir -p "$BOT/backups"
chmod 700 "$BOT" "$BOT/backups"
B="$(mktemp -d "$BOT/backups/primary-XXXXXXXX")"
chmod 700 "$B"
cp -p "$BOT/web.env" "$B/original.env"
OLD_IMAGE=""
if docker ps -a --format '{{.Names}}' | grep -qx 'mnebyvpn-bot-info'; then
  OLD_IMAGE="$(docker inspect --format '{{.Config.Image}}' mnebyvpn-bot-info)"
fi
start_bot(){
  docker run -d --name mnebyvpn-bot-info --restart unless-stopped \
    --network host --user 1000:1000 --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=16m \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 96 --memory 256m --cpus 0.35 \
    --env-file "$BOT/web.env" \
    --entrypoint node "$1" \
    --experimental-strip-types "$2" >/dev/null
}
rollback(){
  set +e
  docker stop -t 8 mnebyvpn-bot-info >/dev/null 2>&1 || true
  docker rm mnebyvpn-bot-info >/dev/null 2>&1 || true
  cp -p "$B/original.env" "$BOT/web.env"
  if [[ -n "$OLD_IMAGE" ]]; then
    start_bot "$OLD_IMAGE" apps/service/src/telegram-brochure-server.ts || true
  fi
  echo "telegram_cabinet_rolled_back=true"
}
trap rollback ERR
cat > "$BOT/web.env" <<EOF
MNEBYVPN_ENV=production
BOT_PUBLIC_INFO_ONLY=no
BOT_PORT=8793
TELEGRAM_WEBHOOK_SECRET_SHA256=$DIGEST
DATABASE_URL=$DB
EOF
chmod 600 "$BOT/web.env"
if [[ -n "$OLD_IMAGE" ]]; then
  docker stop -t 9 mnebyvpn-bot-info >/dev/null
  docker rm mnebyvpn-bot-info >/dev/null
fi
start_bot "$IMAGE" apps/service/src/telegram-cabinet-server.ts
READY=no
for attempt in $(seq 1 35); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:8793/readyz || true)"
  if [[ "$code" == 200 ]]; then READY=yes; break; fi
  sleep 1
done
[[ "$READY" == yes ]] || { echo "primary_cabinet_db_unavailable"; exit 2; }
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 4 -X POST \
 -H 'Content-Type: application/json' -d '{"update_id":101}' \
 http://127.0.0.1:8793/webhooks/telegram)" = 401
# The user approved enabling the 24-hour VPN trial. This reserves a grant
# in PostgreSQL; its 24-hour clock only starts upon node-side verified ENABLE.
# The unavailable network adapter is not faked or bypassed.
ENABLED="$(docker exec mnebyvpn-stage-postgres psql -v ON_ERROR_STOP=1 -At \
 -U mnebyvpn_stage -d mnebyvpn_stage \
 -c "UPDATE trial_offers SET enabled=true WHERE product='vpn' AND duration_seconds=86400 RETURNING enabled;" | tail -n 2 | head -n 1)"
[[ "$ENABLED" == t ]] || { echo "vpn_trial_enable_failed"; exit 2; }
test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8793/readyz)" = 200
ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:8793'
trap - ERR
echo "telegram_primary_cabinet=healthy"
echo "telegram_subscription_database=connected"
echo "telegram_vpn_trial_requests=enabled"
echo "telegram_trial_24h_clock=starts_after_real_activation"
echo "telegram_signed_webhook_requirement=enabled"
echo "telegram_bot_token_on_ru_vps=false"
echo "telegram_foreign_ingress_untouched=true"
echo "source_sha=$SHA"
