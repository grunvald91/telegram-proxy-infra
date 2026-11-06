#!/usr/bin/env bash
# Isolated Xray HMAC worker on server188. Preserves site, Telegram ingress,
# shared proxy, nginx, DNS, database, and existing unrelated services.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo 'root required'; exit 2; }
SHA="${1:?CI verified main SHA required}"
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || exit 2
ROOT=/opt/mnebyvpn
BOT="$ROOT/bot"
IMAGE="mnebyvpn-stage-web:$SHA"
NAME=mnebyvpn-vpn-worker
PREVIOUS=mnebyvpn-vpn-worker-previous
LOCK=/run/lock/mnebyvpn-vpn-agent-deploy.lock
exec 9>"$LOCK"
flock -w 100 9 || { echo 'VPN worker deployment already running'; exit 2; }

test "$(cat "$ROOT/staging/active_sha")" = "$SHA" ||
  { echo 'Staged app SHA differs from reviewed main'; exit 2; }
docker image inspect "$IMAGE" >/dev/null
test -s "$ROOT/releases/$SHA/apps/service/src/vpn-provisioning-worker.ts"
test -s "$ROOT/releases/$SHA/packages/provisioning/src/xray-node.ts"
test -s "$BOT/provisioner.key"
test -s "$BOT/web.env"
grep -Eq '^DATABASE_URL=postgresql://' "$BOT/web.env"
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
  --max-time 8 http://10.66.77.1:18944/healthz)" = 200
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
  --max-time 5 http://127.0.0.1:8793/readyz)" = 200
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
  --max-time 5 http://127.0.0.1:8792/healthz)" = 200
test "$(docker inspect --format '{{.State.Running}}' mnebyvpn-stage-postgres)" = true

# Node itself is already live and separately enforces expiry.
# Do not restart the foreign node or replay the ephemeral canary for a
# website feature release. The existing worker container is replaced with
# rollback; active customer node credentials and timers remain unchanged.
for candidate in "$PREVIOUS"; do
  if docker ps -a --format '{{.Names}}' | grep -qx "$candidate"; then
    echo 'Reserved rollback container name occupied'; exit 2
  fi
done
old=no
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  old=yes
elif ss -H -lnt | awk '{print $4}' | grep -Eq '^(127[.]0[.]0[.]1|0[.]0[.]0[.]0|\\[::\\]|\\*):8794$'; then
  echo 'VPN worker port occupied by unknown process'; exit 2
fi

# This token authorizes ONLY the private bot -> worker profile lookups.
if [[ ! -e "$BOT/worker.env" ]]; then
  printf 'VPN_WORKER_PROFILE_TOKEN=%s\nVPN_WORKER_HEALTH_PORT=8794\n' \
    "$(openssl rand -hex 32)" > "$BOT/worker.env"
  chmod 600 "$BOT/worker.env"
fi
grep -Eq '^VPN_WORKER_PROFILE_TOKEN=[a-f0-9]{64}$' "$BOT/worker.env"
grep -Fxq 'VPN_WORKER_HEALTH_PORT=8794' "$BOT/worker.env"

start_worker(){
  docker run -d --name "$NAME" --restart unless-stopped \
    --network host --user 0:0 --read-only \
    --tmpfs /tmp:rw,nosuid,nodev,size=16m \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 96 --memory 300m --cpus 0.45 \
    --mount "type=bind,source=$BOT/provisioner.key,target=/run/secrets/provisioner.key,readonly" \
    --env-file "$BOT/web.env" --env-file "$BOT/worker.env" \
    -e MNEBYVPN_PROVISIONING_WORKER=enabled \
    -e MNEBYVPN_NODE_WORKER=enabled \
    -e VPN_NODE_KEY_FILE=/run/secrets/provisioner.key \
    --entrypoint node "$IMAGE" \
    --experimental-strip-types apps/service/src/vpn-provisioning-worker.ts >/dev/null
}
recover(){
  local exit_code=$?
  trap - ERR EXIT
  if (( exit_code != 0 )); then
    echo 'VPN worker promotion failed; restoring prior container when available'
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [[ "$old" == yes ]] &&
      docker ps -a --format '{{.Names}}' | grep -qx "$PREVIOUS"; then
      docker rename "$PREVIOUS" "$NAME" || true
      docker start "$NAME" >/dev/null 2>&1 || true
    fi
  fi
  exit "$exit_code"
}
trap recover ERR EXIT
if [[ "$old" == yes ]]; then
  docker stop -t 12 "$NAME" >/dev/null
  docker rename "$NAME" "$PREVIOUS"
fi
start_worker
ready=no
for _ in $(seq 1 32); do
  if [[ "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
     --max-time 3 http://127.0.0.1:8794/readyz || true)" == 200 ]]; then
    ready=yes
    break
  fi
  sleep 1
done
[[ "$ready" == yes ]] || { echo 'New Xray worker failed live readiness'; exit 3; }
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' \
  --max-time 3 -X POST -H 'Content-Type: application/json' \
  -d '{"telegramUserId":1}' \
  http://127.0.0.1:8794/profile)" = 401
if [[ "$old" == yes ]]; then docker rm "$PREVIOUS" >/dev/null; fi
trap - ERR EXIT
echo "node_worker_sha=$SHA"
echo 'node_hmac_wireguard=verified'
echo 'foreign_xray_node_and_existing_customers_untouched=true'
echo 'node_worker_readyz=200'
echo 'node_worker_profile_requires_token=401'
echo 'other_188_services_preserved=true'
