#!/usr/bin/env bash
# Guarded in-place 60s authorization cache upgrade of the EXISTING RU :8856
# personalized DoT. Its hostname, public DE Nginx SNI, legacy DE CoreDNS,
# :8853 sidecar and user entitlements remain entirely unchanged.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
phase="${1:?stage|promote|rollback|finalize|status}"
expected_sha="${2:-}"
BASE=/etc/mnebydns/personal-dot
SOURCE=/tmp/mnebydns-personal-auth60-listener-20261114.ts
TARGET="$BASE/personal-dot-listener-auth60-20261114.ts"
SERVICE=mnebydns-personal-dot-private
BACKUP=mnebydns-personal-dot-before-auth60-20261114
CANARY=mnebydns-personal-auth60-canary-20261114
SCRIPT=/usr/local/sbin/mnebydns-personal-auth60-inplace-20261114
TIMER=mnebydns-personal-auth60-revert-20261114.timer
LISTENER=/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts
PRODUCTION=/srv/mnebyvpn/apps/service/src/personal-dot-production.ts
POLICY=policy-chatgpt-two-20261114.json
IMGPATH=/srv/mnebyvpn
check_running(){
 [[ "$(docker inspect -f '{{.State.Running}}' "$SERVICE")" == true ]]
}
verify_policy(){
 python3 - "$BASE/$POLICY" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);r=json.loads(p.read_text())
assert len(r)==153 and len(set(r))==153
assert 'chatgpt.com' in r and 'auth.openai.com' in r
print('AUTH60_EXISTING_153_POLICY=PASS')
PY
}
verify_listener(){
 test -s "$TARGET"
 [[ "$(sha256sum "$TARGET" | cut -d' ' -f1)" == "$expected_sha" ]] || exit 2
 grep -Fq 'const AUTH_RECHECK_MS=60000;' "$TARGET"
 grep -Fq "reserve_personal_dns_query" "$TARGET"
 grep -Fq "finish_personal_dns_query" "$TARGET"
}
run_container(){
 local name="$1" dns_port="$2" health_port="$3" image="$4"
 docker run -d --name "$name" --network host \
   --user 1001:1001 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=8m \
   --cap-drop ALL --security-opt no-new-privileges \
   --pids-limit 96 --memory 256m --cpus 0.5 --restart unless-stopped \
   --env-file /opt/mnebyvpn/bot/web.env \
   -e MNEBYVPN_ENV=production \
   -e MNEBYDNS_PERSONAL_DOT_ENABLED=yes \
   -e MNEBYDNS_PERSONAL_DOT_BIND_IP=10.66.77.2 \
   -e MNEBYDNS_PERSONAL_DOT_PORT="$dns_port" \
   -e MNEBYDNS_PERSONAL_DOT_HEALTH_PORT="$health_port" \
   -e MNEBYDNS_PERSONAL_DOT_TLS_KEY_FILE=/run/mnebydns-personal/privkey.pem \
   -e MNEBYDNS_PERSONAL_DOT_TLS_CERT_FILE=/run/mnebydns-personal/fullchain.pem \
   -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE="/run/mnebydns-personal/$POLICY" \
   -e "MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_SHA256=$(sha256sum "$BASE/$POLICY" | cut -d' ' -f1)" \
   -e MNEBYDNS_PERSONAL_MAPPED_DOT_IP=10.66.77.1 \
   -e MNEBYDNS_PERSONAL_MAPPED_DOT_NAME=dns.mnebyvpn.site \
   -e MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=1853 \
   -e MNEBYDNS_PERSONAL_DIRECT_DOT_IP=1.1.1.1 \
   -e MNEBYDNS_PERSONAL_DIRECT_DOT_NAME=one.one.one.one \
   -e MNEBYDNS_PERSONAL_DIRECT_DOT_PORT=853 \
   --mount "type=bind,source=$BASE,target=/run/mnebydns-personal,readonly" \
   --mount "type=bind,source=$BASE/personal-dot-production.ts,target=$PRODUCTION,readonly" \
   --mount "type=bind,source=$TARGET,target=$LISTENER,readonly" \
   --entrypoint node "$image" \
   --experimental-strip-types apps/service/src/personal-dot-production.ts >/dev/null
}
check_local(){
 local port="$1" health="$2" ready=no code
 for i in $(seq 1 24); do
   code="$(curl --noproxy '*' -sf -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$health/readyz" || true)"
   if [[ "$code" == 200 ]]; then ready=yes;break;fi
   sleep 1
 done
 [[ "$ready" == yes ]] || { echo "AUTH60_READY_$port=FAILED"; return 2; }
 python3 - "$port" <<'PY'
import socket,ssl,sys
port=int(sys.argv[1])
with socket.create_connection(('10.66.77.2',port),timeout=6) as raw:
    raw.settimeout(6)
    with ssl.create_default_context().wrap_socket(raw,server_hostname='aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
        assert tls.getpeercert()
print('AUTH60_RU_LOCAL_STRICT_TLS=PASS')
PY
}
rollback(){
 systemctl stop "$TIMER" >/dev/null 2>&1 || true
 if docker ps -a --format '{{.Names}}' | grep -Fxq "$BACKUP"; then
   docker rm -f "$SERVICE" >/dev/null 2>&1 || true
   docker rename "$BACKUP" "$SERVICE"
   docker start "$SERVICE" >/dev/null
 fi
 docker rm -f "$CANARY" >/dev/null 2>&1 || true
 check_running
 echo 'AUTH60_ROLLBACK=OLD_PERSONAL_8856_RESTORED'
}
case "$phase" in
 stage)
   [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || exit 2
   [[ ! -e "$TARGET" && ! -e "$SCRIPT" ]] || exit 2
   [[ ! -e "$BACKUP" ]] || exit 2
   ! docker ps -a --format '{{.Names}}' | grep -Fxq "$CANARY"
   check_running
   verify_policy
   [[ "$(ip -o -4 addr show dev tg-relay)" == *10.66.77.2/24* ]]
   [[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$SERVICE")" == host ]]
   [[ "$(docker inspect -f '{{.Config.User}}' "$SERVICE")" == 1001:1001 ]]
   [[ "$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$SERVICE")" == unless-stopped ]]
   [[ "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE")" == *'MNEBYDNS_PERSONAL_DOT_PORT=8856'* ]]
   [[ "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE")" == *'MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=1853'* ]]
   test -s "$BASE/personal-dot-production.ts"
   test -s "$BASE/fullchain.pem"
   test -s "$BASE/privkey.pem"
   test -s /opt/mnebyvpn/bot/web.env
   test -s "$SOURCE"
   [[ "$(sha256sum "$SOURCE" | cut -d' ' -f1)" == "$expected_sha" ]]
   if ss -Hlnt | awk '{print $4}' | grep -Eq ':(8860|8861)$'; then
     echo 'AUTH60_CANARY_PORT_OCCUPIED=true'; exit 2
   fi
   image="$(docker inspect -f '{{.Image}}' "$SERVICE")"
   docker image inspect "$image" >/dev/null
   install -m 644 "$SOURCE" "$TARGET"
   verify_listener
   install -m 700 "$0" "$SCRIPT"
   trap 'docker rm -f "$CANARY" >/dev/null 2>&1 || true' ERR
   run_container "$CANARY" 8860 8861 "$image"
   check_local 8860 8861
   trap - ERR
   echo 'AUTH60_CANARY_READY=PASS_8860'
   echo 'AUTH60_OLD_PERSONAL_8856_UNCHANGED=true'
   ;;
 promote)
   [[ "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || exit 2
   verify_listener
   check_running
   [[ "$(docker inspect -f '{{.State.Running}}' "$CANARY")" == true ]]
   [[ ! -e "$BACKUP" ]] || exit 2
   image="$(docker inspect -f '{{.Image}}' "$SERVICE")"
   # Independently restore the old container if the GitHub runner disappears.
   systemd-run --quiet --unit=mnebydns-personal-auth60-revert-20261114 \
     --on-active=420s --collect /bin/bash "$SCRIPT" rollback
   systemctl is-active --quiet "$TIMER"
   docker stop "$SERVICE" >/dev/null
   docker rename "$SERVICE" "$BACKUP"
   trap rollback ERR
   run_container "$SERVICE" 8856 8857 "$image"
   check_local 8856 8857
   [[ "$(docker inspect -f '{{.State.Running}}' "$BACKUP")" == false ]]
   trap - ERR
   echo 'AUTH60_EXISTING_PERSONAL_8856=PROMOTED_WITH_ROLLBACK'
   ;;
 rollback)
   rollback
   ;;
 finalize)
   check_running
   [[ "$(docker inspect -f '{{.State.Running}}' "$BACKUP")" == false ]]
   [[ "$(docker inspect -f '{{.State.Running}}' "$CANARY")" == true ]]
   systemctl stop "$TIMER" >/dev/null 2>&1 || true
   docker rm "$BACKUP" >/dev/null
   docker rm -f "$CANARY" >/dev/null
   echo 'AUTH60_EXISTING_PERSONAL_8856=FINALIZED'
   echo 'AUTH60_TEMP_CANARY_REMOVED=true'
   ;;
 status)
   check_running
   echo 'AUTH60_PERSONAL_ORIGINAL_PORT_8856=RUNNING'
   docker inspect -f '{{range .Mounts}}{{if eq .Destination "/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts"}}AUTH60_LISTENER_OVERLAY=ACTIVE{{end}}{{end}}' "$SERVICE"
   ;;
 *) exit 2;;
esac
