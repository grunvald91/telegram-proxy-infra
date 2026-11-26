#!/usr/bin/env bash
# Permanent FI customer release. Only the already verified bot image is reused.
# The old container remains available until the database gate is committed.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
ROOT=/opt/mnebyvpn
BOT="$ROOT/bot"
NAME=mnebyvpn-bot-info
CANARY=mnebyvpn-bot-update-canary
BACKUP=mnebyvpn-bot-update-previous
SHA=535bd4e143e164f259470c459cf4f02af20626f7
IMAGE="mnebyvpn-stage-web:$SHA"
exec 9>/run/lock/mnebyvpn-bot-info.lock
flock -w 30 9
test "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true
test "$(docker inspect -f '{{.Config.Image}}' "$NAME")" = "$IMAGE"
test -s "$ROOT/releases/$SHA/apps/service/src/telegram-cabinet-server.ts"
grep -Fq 'MNEBYDNS_REGIONAL_DOT_ENABLED' "$ROOT/releases/$SHA/apps/service/src/telegram-cabinet-server.ts"
test -f "$BOT/web.env" && test ! -L "$BOT/web.env"
grep -Fxq 'MNEBYVPN_ENV=production' "$BOT/web.env"
grep -Fxq 'BOT_PUBLIC_INFO_ONLY=no' "$BOT/web.env"
grep -Eq '^DATABASE_URL=postgresql://' "$BOT/web.env"
grep -Eq '^TELEGRAM_WEBHOOK_SECRET_SHA256=[a-f0-9]{64}$' "$BOT/web.env"
if grep -Fxq 'MNEBYDNS_REGIONAL_DOT_ENABLED=yes' "$BOT/web.env"; then exit 2; fi
if docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" | grep -Fx 'MNEBYDNS_REGIONAL_DOT_ENABLED=yes' >/dev/null; then exit 2; fi
if ss -H -lnt | awk '{print $4}' | grep -Eq ':18796$'; then exit 2; fi
for name in "$CANARY" "$BACKUP"; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then exit 2; fi
done
db() {
  docker exec -i mnebyvpn-stage-postgres psql -XqAt -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage "$@"
}
test "$(db -c 'SELECT (NOT enabled)::text FROM public.fi_dns_meter_gate WHERE singleton;')" = true
test "$(db -c 'SELECT (NOT EXISTS(SELECT 1 FROM public.fi_dns_regional_credentials WHERE revoked_at IS NULL))::text;')" = true
work="$(mktemp -d "$BOT/fi-release.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
cp -p "$BOT/web.env" "$work/original"
awk '!/^MNEBYDNS_REGIONAL_DOT_ENABLED=/' "$work/original" > "$work/candidate"
printf '%s\n' 'MNEBYDNS_REGIONAL_DOT_ENABLED=yes' >> "$work/candidate"
chmod 600 "$work/candidate"
worker=()
if [[ -s "$BOT/worker.env" ]]; then
  grep -Eq '^VPN_WORKER_PROFILE_TOKEN=[a-f0-9]{64}$' "$BOT/worker.env"
  # The worker env must not override the candidate regional flag.
  ! grep -q '^MNEBYDNS_REGIONAL_DOT_ENABLED=' "$BOT/worker.env"
  worker=(--env-file "$BOT/worker.env")
fi
run_bot() {
  local name="$1" port="$2" restart="$3" env="$4"
  docker run -d --name "$name" --network host \
    --user 1000:1000 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=16m \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 96 --memory 256m --cpus 0.35 \
    --env-file "$env" "${worker[@]}" -e "BOT_PORT=$port" \
    $restart --entrypoint node "$IMAGE" \
    --experimental-strip-types apps/service/src/telegram-cabinet-server.ts >/dev/null
}
healthy() {
  local port="$1" code
  for _ in $(seq 1 20); do
    code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$port/readyz" || true)"
    [[ "$code" == 200 ]] && break
    sleep 1
  done
  [[ "$code" == 200 ]] || return 1
  [[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 \
    -X POST -H 'Content-Type: application/json' -d '{"update_id":100}' \
    "http://127.0.0.1:$port/webhooks/telegram")" == 401 ]]
}
has_flag() {
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$1" |
    grep -Fx 'MNEBYDNS_REGIONAL_DOT_ENABLED=yes' >/dev/null
}
old_stopped=no
config_changed=no
committed=no
cleanup(){
  local status=$?
  trap - EXIT
  set +e
  docker rm -f "$CANARY" >/dev/null 2>&1
  if [[ "$committed" != yes ]]; then
    # If the DB outcome is ambiguous, do not undo a possibly committed
    # release or delete any real customer credentials.
    local closed
    closed="$(db -c 'SELECT (NOT enabled)::text FROM public.fi_dns_meter_gate WHERE singleton;' 2>/dev/null)"
    if [[ "$closed" != true ]]; then
      echo 'FI_RELEASE_RU_STATE=AMBIGUOUS_OR_COMMITTED'
      exit 3
    fi
    if [[ "$old_stopped" == yes ]]; then
      if docker ps -a --format '{{.Names}}' | grep -qx "$BACKUP"; then
        docker rm -f "$NAME" >/dev/null 2>&1
        docker rename "$BACKUP" "$NAME" && docker start "$NAME" >/dev/null
      else
        docker start "$NAME" >/dev/null
      fi
    fi
    if [[ "$config_changed" == yes ]]; then
      cp -p "$work/original" "$work/restore" && mv -f "$work/restore" "$BOT/web.env"
    fi
    if healthy 8793; then echo 'FI_RELEASE_RU_ROLLBACK=READY'; else echo 'FI_RELEASE_RU_ROLLBACK=UNCONFIRMED'; fi
  fi
  rm -rf -- "$work"
  exit "$status"
}
trap cleanup EXIT
run_bot "$CANARY" 18796 '--rm' "$work/candidate"
healthy 18796
has_flag "$CANARY"
docker stop -t 5 "$CANARY" >/dev/null
echo 'FI_RELEASE_BOT_CANARY=PASS'
old_stopped=yes
docker stop -t 10 "$NAME" >/dev/null
docker rename "$NAME" "$BACKUP"
run_bot "$NAME" 8793 '--restart unless-stopped' "$work/candidate"
healthy 8793
has_flag "$NAME"
config_changed=yes
cp -p "$work/candidate" "$work/install"
mv -f "$work/install" "$BOT/web.env"
echo 'FI_RELEASE_BOT_LIVE=PASS'
# Last state-changing step: commit only once the bot and FI runtime are ready.
# An ambiguous client-side response is handled conservatively in cleanup.
test "$(db -c 'UPDATE public.fi_dns_meter_gate SET enabled=true WHERE singleton AND NOT enabled RETURNING enabled::text;')" = true
committed=yes
echo 'FI_RELEASE_GATE_OPEN=true'
docker rm "$BACKUP" >/dev/null || echo 'FI_RELEASE_OLD_STOPPED_CONTAINER_RETAINED=true'
echo 'FI_RELEASE_RU=COMMITTED'
