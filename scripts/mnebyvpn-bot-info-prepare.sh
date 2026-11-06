#!/usr/bin/env bash
# Deploy a Telegram webhook responder WITHOUT keeping Bot API token on the VPS.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-bot-info.lock
flock -n 9 || { echo 'Another bot deployment active'; exit 2; }
SHA="$(cat /opt/mnebyvpn/staging/active_sha)"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || exit 2
test -f "/opt/mnebyvpn/releases/$SHA/apps/service/src/telegram-brochure-server.ts"
IMAGE="mnebyvpn-stage-web:$SHA"
docker image inspect "$IMAGE" >/dev/null
if ss -H -lnt | awk '{print $4}' | grep -Eq ':8793$'; then
  docker ps --format '{{.Names}}' | grep -qx 'mnebyvpn-bot-info' || {
    echo 'Port 8793 owned by another service'; exit 2;
  }
fi
mkdir -p /opt/mnebyvpn/bot
chmod 700 /opt/mnebyvpn/bot
# The digest cannot be used to forge Telegram's secret_token (SHA-256 preimage).
# Generated from the BotFather token by the dedicated MNEBYVPN Actions workflow.
DIGEST='4038dae2b7ca4e5665f892643810d18caed4746096960ea4a7d6b409fe94b956'
if [[ ! "$DIGEST" =~ ^[a-f0-9]{64}$ ]]; then exit 2; fi
cat > /opt/mnebyvpn/bot/web.env <<EOF
MNEBYVPN_ENV=production
BOT_PUBLIC_INFO_ONLY=yes
BOT_PORT=8793
TELEGRAM_WEBHOOK_SECRET_SHA256=$DIGEST
EOF
chmod 600 /opt/mnebyvpn/bot/web.env
if docker ps -a --format '{{.Names}}' | grep -qx 'mnebyvpn-bot-info'; then
  docker stop -t 8 mnebyvpn-bot-info >/dev/null
  docker rm mnebyvpn-bot-info >/dev/null
fi
docker run -d --name mnebyvpn-bot-info --restart unless-stopped \
  --network host --user 1000:1000 --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=16m \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 72 --memory 150m --cpus 0.2 \
  --env-file /opt/mnebyvpn/bot/web.env \
  --entrypoint node "$IMAGE" \
  --experimental-strip-types apps/service/src/telegram-brochure-server.ts >/dev/null
ok=no
for i in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:8793/healthz || true)"
  if [[ "$code" == 200 ]]; then ok=yes; break; fi
  sleep 1
done
test "$ok" = yes || { echo 'Bot failed health check'; exit 2; }
test "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8793/readyz)" = 503
test "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"update_id":100}' http://127.0.0.1:8793/webhooks/telegram)" = 401
ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:8793'
echo 'telegram_bot_info_backend=healthy'
echo 'telegram_bot_listen=127.0.0.1:8793'
echo 'telegram_bot_api_token_stored_on_vps=false'
echo 'telegram_bot_money_features=disabled'
echo "bot_image_sha=$SHA"
