#!/usr/bin/env bash
# Isolated Prodamus receipt / VPN-ready Telegram notifications only.
# Does not touch Xray, the VPN worker, site, network, ingress or billing state.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo 'root required'; exit 2; }
SHA="${1:?green MNEBYVPN source SHA required}"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT=/opt/mnebyvpn
BOT="$ROOT/bot"
IMAGE="mnebyvpn-stage-web:$SHA"
NAME=mnebyvpn-purchase-notices
PREVIOUS=mnebyvpn-purchase-notices-previous
exec 9>/run/lock/mnebyvpn-purchase-notices-deploy.lock
flock -w 60 9 || { echo 'Purchase notice deploy already running'; exit 2; }

test "$(cat "$ROOT/staging/active_sha")" = "$SHA" || {
  echo 'Staged MNEBYVPN source is not the green commit'; exit 2;
}
test "$(cat "$ROOT/public/active_sha")" = "$SHA" || {
  echo 'Public MNEBYVPN site source differs; refusing partial release'; exit 2;
}
docker image inspect "$IMAGE" >/dev/null
test -s "$ROOT/releases/$SHA/apps/service/src/purchase-notification-worker.ts"
test -s "$ROOT/releases/$SHA/packages/notifications/src/vpn-purchase.ts"
test -s "$ROOT/releases/$SHA/packages/notifications/src/vpn-trial-ready.ts"
test -s "$BOT/web.env"
grep -Eq '^DATABASE_URL=postgresql://' "$BOT/web.env" || exit 2
grep -Eq '^TELEGRAM_TOKEN_BOT=[0-9]{5,20}:[A-Za-z0-9_-]{25,}$' "$BOT/web.env" || {
  echo 'Existing private Telegram token is not configured'; exit 2;
}
test "$(docker inspect --format '{{.State.Running}}' mnebyvpn-stage-postgres)" = true
old_worker="$(docker inspect --format '{{.Image}}' mnebyvpn-vpn-worker)"
test "$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8794/readyz)" = 200
# Preflight schema and do not duplicate notifications if enabled in the existing node worker.
docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c "SELECT 1 FROM vpn_purchase_notifications LIMIT 1" >/dev/null
docker exec mnebyvpn-stage-postgres psql -qAtX -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage -c "SELECT 1 FROM vpn_trial_ready_notifications LIMIT 1" >/dev/null
if grep -Fxq 'VPN_PURCHASE_NOTIFICATIONS_ENABLED=yes' "$BOT/web.env" ||
  { test -f "$BOT/worker.env" &&
    grep -Fxq 'VPN_PURCHASE_NOTIFICATIONS_ENABLED=yes' "$BOT/worker.env"; }; then
  echo 'Existing VPN worker already configured as purchase sender; refusing duplicate'; exit 2;
fi
if docker ps -a --format '{{.Names}}' | grep -qx "$PREVIOUS"; then
  echo 'Reserved rollback container name occupied'; exit 2;
fi

old=no
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then old=yes; fi
rollback(){
  local result=$?
  trap - ERR EXIT
  if (( result != 0 )); then
    echo 'Purchase notice process failed; restoring previous isolated process'
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [[ "$old" == yes ]] &&
      docker ps -a --format '{{.Names}}' | grep -qx "$PREVIOUS"; then
      docker rename "$PREVIOUS" "$NAME" >/dev/null || true
      docker start "$NAME" >/dev/null 2>&1 || true
    fi
  fi
  exit "$result"
}
trap rollback ERR EXIT
if [[ "$old" == yes ]]; then
  docker stop -t 8 "$NAME" >/dev/null
  docker rename "$NAME" "$PREVIOUS" >/dev/null
fi

docker run -d --name "$NAME" --restart unless-stopped \
  --network host --user 1000:1000 --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=8m \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 48 --memory 160m --cpus 0.2 \
  --env-file "$BOT/web.env" -e MNEBYVPN_PURCHASE_NOTICE_WORKER=enabled \
  --entrypoint node "$IMAGE" --experimental-strip-types \
  apps/service/src/purchase-notification-worker.ts >/dev/null
for _ in $(seq 1 8); do
  test "$(docker inspect --format '{{.State.Running}}' "$NAME")" = true || exit 2
  test "$(docker inspect --format '{{.RestartCount}}' "$NAME")" = 0 || {
    echo 'Purchase notice process restarted during canary';exit 2;
  }
  sleep 1
done
test "$(docker inspect --format '{{.Image}}' mnebyvpn-vpn-worker)" = "$old_worker" || {
  echo 'Unexpected VPN worker change';exit 2;
}
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8794/readyz)" = 200
if [[ "$old" == yes ]]; then docker rm "$PREVIOUS" >/dev/null; fi
trap - ERR EXIT
echo 'purchase_notices=running'
echo 'trial_ready_notices=enabled_node_verified'
echo "purchase_notices_sha=$SHA"
echo 'vpn_worker=unchanged'
echo 'telegram_token=existing_private_env'
echo 'vpn_and_proxy_ports=untouched'
