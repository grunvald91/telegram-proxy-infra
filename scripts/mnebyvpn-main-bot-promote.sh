#!/usr/bin/env bash
# Promote an already CI-verified and staged MNEBYVPN main image into the
# existing Telegram bot service on server188. This touches only its container.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo 'root required'; exit 2; }
SHA="${1:?immutable release SHA required}"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || exit 2
ROOT=/opt/mnebyvpn
BOT="$ROOT/bot"
IMAGE="mnebyvpn-stage-web:$SHA"
NAME=mnebyvpn-bot-info
CANARY=mnebyvpn-bot-update-canary
BACKUP=mnebyvpn-bot-update-previous
LOCK=/run/lock/mnebyvpn-bot-info.lock
exec 9>"$LOCK"
flock -w 80 9 || { echo 'bot deploy already in progress'; exit 2; }

command -v docker >/dev/null
command -v curl >/dev/null
command -v ss >/dev/null
test "$(cat "$ROOT/staging/active_sha" 2>/dev/null)" = "$SHA" ||
  { echo 'stage code does not match reviewed main SHA'; exit 2; }
docker image inspect "$IMAGE" >/dev/null
test -s "$ROOT/releases/$SHA/apps/service/src/telegram-cabinet-server.ts"
test -s "$BOT/web.env"
# Preserve all existing private config including Telegram secret and DB URL.
grep -Fxq 'MNEBYVPN_ENV=production' "$BOT/web.env"
grep -Fxq 'BOT_PUBLIC_INFO_ONLY=no' "$BOT/web.env"
grep -Eq '^TELEGRAM_WEBHOOK_SECRET_SHA256=[a-f0-9]{64}$' "$BOT/web.env"
grep -Eq '^DATABASE_URL=postgresql://' "$BOT/web.env"
test "$(docker inspect --format '{{.State.Running}}' mnebyvpn-stage-postgres)" = true

port_owned() {
  ss -H -lnt | awk '{print $4}' | grep -Fqx "127.0.0.1:$1"
}
if port_owned 8793; then
  docker ps --format '{{.Names}}' | grep -qx "$NAME" ||
    { echo 'refusing to take unknown service on 8793'; exit 2; }
fi
if ss -H -lnt | awk '{print $4}' | grep -Eq ':18796$'; then
  echo 'canary port 18796 is occupied'; exit 2
fi
for name in "$CANARY" "$BACKUP"; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    echo "reserved container name already occupied: $name"; exit 2
  fi
done

run_bot() {
  local name="$1" port="$2" restart="$3"
  docker run -d --name "$name" --network host \
    --user 1000:1000 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=16m \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 96 --memory 256m --cpus 0.35 \
    --env-file "$BOT/web.env" -e "BOT_PORT=$port" \
    $restart --entrypoint node "$IMAGE" \
    --experimental-strip-types apps/service/src/telegram-cabinet-server.ts >/dev/null
}
healthy() {
  local port="$1" code
  for _ in $(seq 1 28); do
    code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$port/readyz" || true)"
    [[ "$code" == 200 ]] && break
    sleep 1
  done
  [[ "$code" == 200 ]] || return 1
  [[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 \
    -X POST -H 'Content-Type: application/json' \
    -d '{"update_id":100}' \
    "http://127.0.0.1:$port/webhooks/telegram")" == 401 ]]
}

# First verify the candidate without modifying the live instance.
run_bot "$CANARY" 18796 '--rm'
cleanup_canary(){
  docker stop -t 5 "$CANARY" >/dev/null 2>&1 || true
}
trap cleanup_canary EXIT
healthy 18796 || { echo 'canary Telegram readiness failed'; exit 2; }
cleanup_canary
trap - EXIT

old=no
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  old=yes
fi
restore(){
  local status=$?
  trap - ERR EXIT
  if (( status != 0 )); then
    echo 'telegram promotion failed; restoring original container'
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [[ "$old" == yes ]] &&
      docker ps -a --format '{{.Names}}' | grep -qx "$BACKUP"; then
      docker rename "$BACKUP" "$NAME" || true
      docker start "$NAME" >/dev/null 2>&1 || true
    fi
  fi
  exit "$status"
}
trap restore ERR EXIT
if [[ "$old" == yes ]]; then
  docker stop -t 10 "$NAME" >/dev/null
  docker rename "$NAME" "$BACKUP"
fi
run_bot "$NAME" 8793 '--restart unless-stopped'
healthy 8793 || { echo 'new Telegram bot failed readiness'; exit 3; }
port_owned 8793
if [[ "$old" == yes ]]; then docker rm "$BACKUP" >/dev/null; fi
trap - ERR EXIT
echo "telegram_primary_sha=$SHA"
echo 'telegram_primary_readyz=200'
echo 'telegram_primary_unsigned_updates_rejected=401'
echo 'telegram_foreign_ingress_untouched=true'
echo 'previous_bot_rollback_available_during_promotion=true'
