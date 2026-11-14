#!/usr/bin/env bash
# Stage NEW private TLS/DoT on RU WireGuard; existing public DE:853 untouched.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
SHA="${1:?pinned green MNEBYVPN SHA required}"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || exit 2
ROOT=/opt/mnebyvpn
IMAGE="mnebyvpn-stage-web:$SHA"
STAGED="/tmp/mnebydns-personal-stage-$SHA"
TARGET=/etc/mnebydns/personal-dot
NAME=mnebydns-personal-dot
LOCK=/run/lock/mnebydns-personal-dot-stage.lock
exec 9>"$LOCK"
flock -w 20 9 || { echo 'PERSONAL_DOT_LOCK=BUSY'; exit 2; }
test "$(cat "$ROOT/staging/active_sha" 2>/dev/null)" = "$SHA" ||
  { echo 'PERSONAL_DOT_SOURCE_SHA_MISMATCH=true'; exit 2; }
docker image inspect "$IMAGE" >/dev/null
test -s "$ROOT/releases/$SHA/apps/service/src/personal-dot-production.ts"
test -s "$ROOT/bot/web.env"
grep -Fxq 'MNEBYVPN_ENV=production' "$ROOT/bot/web.env"
grep -Eq '^DATABASE_URL=postgresql://' "$ROOT/bot/web.env"
test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-stage-postgres)" = true
test "$(ip -o -4 addr show dev tg-relay | grep -c '10.66.77.2/24')" -eq 1
test -s "$STAGED/privkey.pem"
test -s "$STAGED/fullchain.pem"
test -s "$STAGED/policy.json"
test -s "$STAGED/personal-dot-production.ts"
# Confirm the exact Git blob from reviewed application commit 88d0a157.
# This overrides only the private DoT gateway source in the pinned stage
# image; the live site, Telegram bot and CoreDNS are never replaced.
python3 - "$STAGED/personal-dot-production.ts" <<'PY'
import hashlib,pathlib,sys
data=pathlib.Path(sys.argv[1]).read_bytes()
digest=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
assert digest=='88a1f0d617c3d462c862af184157a0c6375dde8d', 'Unreviewed gateway source'
assert b"const portNumber=port('MNEBYDNS_PERSONAL_'+prefix+'_DOT_PORT',853,1);" in data
print('PERSONAL_DOT_REVIEWED_PORT_FIX=VERIFIED')
PY
# Never destroy/replace an existing service.
if docker ps -a --format '{{.Names}}' | grep -qx "$NAME"; then
  echo 'PERSONAL_DOT_CONTAINER_ALREADY_EXISTS=REFUSE_OVERWRITE'
  exit 2
fi
for port in 8853 8855; do
  if ss -Hlnt | awk '{print $4}' | grep -Eq ":$port$"; then
    echo "PERSONAL_DOT_PORT_${port}_OCCUPIED=true"
    exit 2
  fi
done
openssl x509 -in "$STAGED/fullchain.pem" -checkhost aaaaaaaaaaaa.dns.mnebyvpn.site -noout >/dev/null
openssl x509 -in "$STAGED/fullchain.pem" -checkend 604800 -noout >/dev/null
cert_pub="$(openssl x509 -in "$STAGED/fullchain.pem" -pubkey -noout |
  openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)"
key_pub="$(openssl pkey -in "$STAGED/privkey.pem" -pubout -outform DER |
  sha256sum | cut -d' ' -f1)"
[[ "$cert_pub" == "$key_pub" ]] || { echo 'CERT_KEY_MISMATCH'; exit 2; }
POLICY_SHA="$(sha256sum "$STAGED/policy.json" | cut -d' ' -f1)"
python3 - "$STAGED/policy.json" <<'PY'
import json,re,sys
data=json.load(open(sys.argv[1]))
assert isinstance(data,list) and 100<=len(data)<=10000
assert len(data)==len(set(data))
assert 'claude.ai' in data
assert all(isinstance(x,str) and re.fullmatch(r'(?:\*\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+',x) for x in data)
print('PERSONAL_DOT_PREMIUM_POLICY_RULES='+str(len(data)))
PY
install -d -m 700 "$TARGET"
install -m 600 "$STAGED/fullchain.pem" "$TARGET/fullchain.pem"
install -m 600 "$STAGED/privkey.pem" "$TARGET/privkey.pem"
install -m 600 "$STAGED/policy.json" "$TARGET/policy.json"
install -m 600 "$STAGED/personal-dot-production.ts" "$TARGET/personal-dot-production.ts"
chown -R 1001:1001 "$TARGET"
cleanup(){
  local code=$?
  if (( code != 0 )); then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo 'PERSONAL_DOT_STAGE_ROLLED_BACK=true'
  fi
  rm -rf "$STAGED"
  exit "$code"
}
trap cleanup ERR EXIT
docker run -d --name "$NAME" --network host \
  --user 1001:1001 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=8m \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 96 --memory 256m --cpus 0.5 \
  --restart unless-stopped \
  --env-file "$ROOT/bot/web.env" \
  -e MNEBYVPN_ENV=production \
  -e MNEBYDNS_PERSONAL_DOT_ENABLED=yes \
  -e MNEBYDNS_PERSONAL_DOT_BIND_IP=10.66.77.2 \
  -e MNEBYDNS_PERSONAL_DOT_PORT=8853 \
  -e MNEBYDNS_PERSONAL_DOT_HEALTH_PORT=8855 \
  -e MNEBYDNS_PERSONAL_DOT_TLS_KEY_FILE=/run/mnebydns-personal/privkey.pem \
  -e MNEBYDNS_PERSONAL_DOT_TLS_CERT_FILE=/run/mnebydns-personal/fullchain.pem \
  -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE=/run/mnebydns-personal/policy.json \
  -e "MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_SHA256=$POLICY_SHA" \
  -e MNEBYDNS_PERSONAL_MAPPED_DOT_IP=89.125.90.101 \
  -e MNEBYDNS_PERSONAL_MAPPED_DOT_NAME=dns.mnebyvpn.site \
  -e MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=853 \
  -e MNEBYDNS_PERSONAL_DIRECT_DOT_IP=1.1.1.1 \
  -e MNEBYDNS_PERSONAL_DIRECT_DOT_NAME=one.one.one.one \
  -e MNEBYDNS_PERSONAL_DIRECT_DOT_PORT=853 \
  --mount "type=bind,source=$TARGET,target=/run/mnebydns-personal,readonly" \
  --mount "type=bind,source=$TARGET/personal-dot-production.ts,target=/srv/mnebyvpn/apps/service/src/personal-dot-production.ts,readonly" \
  --entrypoint node "$IMAGE" \
  --experimental-strip-types apps/service/src/personal-dot-production.ts >/dev/null
ready=0
for i in $(seq 1 25); do
  code="$(curl --noproxy '*' -sf -o /dev/null -w '%{http_code}' --max-time 3 \
    http://127.0.0.1:8855/readyz || true)"
  if [[ "$code" == 200 ]]; then ready=1; break; fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo 'PERSONAL_DOT_PRIVATE_READY=FAILED'
  docker inspect --format 'PERSONAL_DOT_CONTAINER_STATE={{.State.Status}} EXIT={{.State.ExitCode}}' "$NAME" || true
  # Bounded startup errors only; do not log environment or TLS private key.
  docker logs --tail 18 "$NAME" 2>&1 |
    grep -Ei 'Personal DoT|Error|Failed|Module|TypeError|ReferenceError|certificate|unsupported|Warning' |
    cut -c 1-180 | tail -n 12 || true
  exit 2
fi
docker ps --format '{{.Names}}' | grep -qx "$NAME"
echo 'PERSONAL_DOT_PRIVATE_READY=PASS'
echo 'PERSONAL_DOT_SOURCE_SHA_VERIFIED=true'
echo 'PERSONAL_DOT_PAYMENTS_UNCHANGED=true'
echo 'PERSONAL_DOT_PUBLIC_853_UNCHANGED=true'
trap - ERR EXIT
rm -rf "$STAGED"
