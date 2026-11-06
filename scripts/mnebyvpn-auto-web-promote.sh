#!/usr/bin/env bash
# Promote only the tested MNEBYVPN website container to its existing public port.
# No nginx, firewall, DNS, proxy, Telegram, payment or other-container changes.
set -Eeuo pipefail
umask 077

SHA="$1"
ROOT=/opt/mnebyvpn
PUBLIC="$ROOT/public"
ENV_FILE="$PUBLIC/web.env"
IMAGE="mnebyvpn-stage-web:$SHA"
NAME=mnebyvpn-public-web
CANARY=mnebyvpn-public-web-canary
LOCK=/run/lock/mnebyvpn-public-prepare.lock

[ "$(id -u)" -eq 0 ] || { echo 'Deploy must run with existing infrastructure privileges'; exit 2; }
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || { echo 'Invalid commit SHA'; exit 2; }
exec 9>"$LOCK"
flock -w 90 9 || { echo 'Another website promotion is in progress'; exit 2; }
command -v docker >/dev/null && command -v curl >/dev/null && command -v python3 >/dev/null
docker image inspect "$IMAGE" >/dev/null
[ -f "$ENV_FILE" ] || { echo 'Missing existing public web environment; refusing to bootstrap'; exit 2; }
[ "$(docker inspect -f '{{.State.Running}}' mnebyvpn-stage-postgres)" = true ] || {
  echo 'Existing database is not running'; exit 2;
}

# Never enable the unfinished commercial functionality by deploying UI code.
for setting in   MNEBYVPN_ENV=production   WEB_BASE_URL=https://mnebyvpn.site   WEB_TELEGRAM_OIDC_ENABLED=no   WEB_PRODAMUS_WEBHOOK_ENABLED=no   WEB_CHECKOUT_ENABLED=0   WEB_TRIAL_ENABLED=no   WEB_NETWORK_PROVISIONING_VERIFIED=no   WEB_DNS_METERING_VERIFIED=no; do
  grep -Fxq "$setting" "$ENV_FILE" || {
    echo 'Existing production web environment violates the read-only deployment policy'; exit 2;
  }
done

# This deploy owns only the two named website containers and localhost ports.
port_busy() { ss -H -lnt | awk '{print $4}' | grep -Eq ":$1$"; }
if docker ps -a --format '{{.Names}}' | grep -qx "$CANARY"; then
  echo 'Canary name is occupied; refusing to replace unknown container'; exit 2
fi
if port_busy 8793; then echo 'Canary port occupied; refusing'; exit 2; fi
has_public=no
old_image=''
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  has_public=yes
  old_image="$(docker inspect -f '{{.Image}}' "$NAME")"
elif port_busy 8792; then
  echo 'Public web port belongs to an unknown service; refusing'; exit 2
fi

run_web() {
  local name="$1" image="$2" port="$3" ephemeral="$4"
  local cleanup_flags=()
  if [ "$ephemeral" = yes ]; then cleanup_flags=(--rm); fi
  docker run -d "${cleanup_flags[@]}" --name "$name" --restart "$( [ "$ephemeral" = yes ] && echo no || echo unless-stopped )"     --network host --user 1000:1000 --read-only     --tmpfs /tmp:rw,nosuid,nodev,size=32m --cap-drop ALL     --security-opt no-new-privileges --pids-limit 96     --memory 300m --cpus 0.4 --env-file "$ENV_FILE" -e "WEB_PORT=$port"     "$image" >/dev/null
}
healthy() {
  local port="$1"
  local code=''
  for attempt in $(seq 1 35); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$port/healthz" 2>/dev/null || true)"
    if [ "$code" = 200 ]; then break; fi
    sleep 1
  done
  [ "$code" = 200 ] || return 1
  curl -fsS --max-time 5 "http://127.0.0.1:$port/neo.css" | grep -Fq 'portal-art' || return 1
  curl -fsS --max-time 5 "http://127.0.0.1:$port/api/plans" |
    python3 -c 'import sys,json; x=json.load(sys.stdin); assert x["checkoutEnabled"] is False and x["loginEnabled"] is False' || return 1
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$port/readyz")" = 503 ] || return 1
  [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:$port/auth/login")" = 503 ] || return 1
}

cleanup_canary() {
  docker stop -t 3 "$CANARY" >/dev/null 2>&1 || true
}
trap cleanup_canary EXIT
run_web "$CANARY" "$IMAGE" 8793 yes
healthy 8793 || { echo 'New website failed canary health / security checks'; exit 2; }
cleanup_canary
trap - EXIT

# Downtime is limited to replacing this single named brochure container.
if [ "$has_public" = yes ]; then
  docker stop -t 12 "$NAME" >/dev/null
  docker rm "$NAME" >/dev/null
fi
if ! run_web "$NAME" "$IMAGE" 8792 no || ! healthy 8792; then
  echo 'Public website health failed; restoring previous image'
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  if [ -n "$old_image" ]; then
    run_web "$NAME" "$old_image" 8792 no
    healthy 8792 || { echo 'CRITICAL: previous public website image failed recovery'; exit 3; }
    echo 'public_rollback=restored_previous_image'
  fi
  exit 2
fi
test "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true
# The web must not expose any new public port.
ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:8792' || {
  echo 'Expected local-only website listener missing'; exit 2;
}
tmp="$(mktemp "$PUBLIC/active_sha.tmp.XXXXXX")"
printf '%s\n' "$SHA" > "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$PUBLIC/active_sha"

echo "public_web_sha=$SHA"
echo 'public_web_health=200'
echo 'public_web_readyz=503_expected'
echo 'public_checkout_enabled=false'
echo 'public_telegram_oidc_enabled=false'
echo 'public_web_port=127.0.0.1:8792'
echo 'nginx_and_other_services_unchanged=yes'
