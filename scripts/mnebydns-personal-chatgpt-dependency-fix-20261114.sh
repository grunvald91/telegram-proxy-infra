#!/usr/bin/env bash
# Correct existing premium route classification for ChatGPT dependencies.
# IN PLACE: same mnebydns-personal-dot-private container name and :8856.
# Preserve auth 60s listener overlay, legacy DNS, DE Nginx, server key and DB.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
phase="${1:?stage|replace|rollback|finalize|status}"
BASE=/etc/mnebydns/personal-dot
OLD="$BASE/policy-chatgpt-two-20261114.json"
NEW="$BASE/policy-chatgpt-dependencies-20261114.json"
SERVICE=mnebydns-personal-dot-private
BACKUP=mnebydns-personal-dot-private-before-chatgpt-deps-20261114
SRC="$BASE/personal-dot-listener-auth60-20261114.ts"
SCRIPT=/usr/local/sbin/mnebydns-personal-chatgpt-dependency-fix-20261114
TIMER=mnebydns-personal-chatgpt-deps-revert-20261114.timer
LISTENER=/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts
PRODUCTION=/srv/mnebyvpn/apps/service/src/personal-dot-production.ts
PORT=8856
HEALTH=8857
EXTRAS=(
  '*.chatgpt.com'
  '*.openai.com'
  '*.oaistatic.com'
  '*.oaiusercontent.com'
  '*.oaistatsig.com'
)
existing_running(){
  [[ "$(docker inspect -f '{{.State.Running}}' "$SERVICE")" == true ]]
}
check_policy(){
  python3 - "$OLD" "$NEW" <<'PY'
import json,pathlib,sys
oldpath,newpath=map(pathlib.Path,sys.argv[1:])
old=json.loads(oldpath.read_text())
new=json.loads(newpath.read_text())
extras={'*.chatgpt.com','*.openai.com','*.oaistatic.com',
        '*.oaiusercontent.com','*.oaistatsig.com'}
assert len(old)==153 and len(set(old))==153
assert len(new)==158 and len(set(new))==158
assert set(new)==set(old)|extras and not(set(old)&extras)
assert 'chatgpt.com' in new and 'auth.openai.com' in new
print('CHATGPT_DEPENDENCIES_POLICY_OLD153_NEW158=PASS')
PY
}
check_source(){
  test -s "$SRC"
  grep -Fq 'const AUTH_RECHECK_MS=60000;' "$SRC"
  grep -Fq 'reserve_personal_dns_query' "$SRC"
  grep -Fq 'finish_personal_dns_query' "$SRC"
  test -s "$BASE/personal-dot-production.ts"
}
check_old_settings(){
  existing_running
  [[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$SERVICE")" == host ]]
  [[ "$(docker inspect -f '{{.Config.User}}' "$SERVICE")" == 1001:1001 ]]
  [[ "$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$SERVICE")" == unless-stopped ]]
  local settings
  settings="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE")"
  [[ "$settings" == *'MNEBYDNS_PERSONAL_DOT_PORT=8856'* ]]
  [[ "$settings" == *'MNEBYDNS_PERSONAL_MAPPED_DOT_IP=10.66.77.1'* ]]
  [[ "$settings" == *'MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=1853'* ]]
  [[ "$settings" == *'policy-chatgpt-two-20261114.json'* ]]
  docker inspect -f '{{range .Mounts}}{{if eq .Destination "/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts"}}{{.Source}}{{end}}{{end}}' "$SERVICE" | grep -Fxq "$SRC"
  [[ "$(ip -o -4 addr show dev tg-relay)" == *10.66.77.2/24* ]]
  check_source
}
verify_ready(){
  local ready=0
  for i in $(seq 1 24); do
    local code
    code="$(curl --noproxy '*' -sf -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:$HEALTH/readyz || true)"
    if [[ "$code" == 200 ]]; then ready=1; break;fi
    sleep 1
  done
  [[ "$ready" == 1 ]] || return 2
  python3 - <<'PY'
import ssl,socket
with socket.create_connection(('10.66.77.2',8856),timeout=8) as raw:
    raw.settimeout(8)
    with ssl.create_default_context().wrap_socket(raw,server_hostname='aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
        assert tls.getpeercert()
print('CHATGPT_DEPS_EXISTING_PRIVATE_TLS=PASS')
PY
}
run_existing(){
  local image="$1"
  local digest
  digest="$(sha256sum "$NEW" | awk '{print $1}')"
  docker run -d --name "$SERVICE" --network host \
    --user 1001:1001 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=8m \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 96 --memory 256m --cpus 0.5 --restart unless-stopped \
    --env-file /opt/mnebyvpn/bot/web.env \
    -e MNEBYVPN_ENV=production \
    -e MNEBYDNS_PERSONAL_DOT_ENABLED=yes \
    -e MNEBYDNS_PERSONAL_DOT_BIND_IP=10.66.77.2 \
    -e MNEBYDNS_PERSONAL_DOT_PORT=8856 \
    -e MNEBYDNS_PERSONAL_DOT_HEALTH_PORT=8857 \
    -e MNEBYDNS_PERSONAL_DOT_TLS_KEY_FILE=/run/mnebydns-personal/privkey.pem \
    -e MNEBYDNS_PERSONAL_DOT_TLS_CERT_FILE=/run/mnebydns-personal/fullchain.pem \
    -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE=/run/mnebydns-personal/policy-chatgpt-dependencies-20261114.json \
    -e "MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_SHA256=$digest" \
    -e MNEBYDNS_PERSONAL_MAPPED_DOT_IP=10.66.77.1 \
    -e MNEBYDNS_PERSONAL_MAPPED_DOT_NAME=dns.mnebyvpn.site \
    -e MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=1853 \
    -e MNEBYDNS_PERSONAL_DIRECT_DOT_IP=1.1.1.1 \
    -e MNEBYDNS_PERSONAL_DIRECT_DOT_NAME=one.one.one.one \
    -e MNEBYDNS_PERSONAL_DIRECT_DOT_PORT=853 \
    --mount "type=bind,source=$BASE,target=/run/mnebydns-personal,readonly" \
    --mount "type=bind,source=$BASE/personal-dot-production.ts,target=$PRODUCTION,readonly" \
    --mount "type=bind,source=$SRC,target=$LISTENER,readonly" \
    --entrypoint node "$image" \
    --experimental-strip-types apps/service/src/personal-dot-production.ts >/dev/null
}
rollback(){
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  if docker ps -a --format '{{.Names}}' | grep -Fxq "$BACKUP"; then
    docker rm -f "$SERVICE" >/dev/null 2>&1 || true
    docker rename "$BACKUP" "$SERVICE"
    docker start "$SERVICE" >/dev/null
  elif [[ "$(docker inspect -f '{{.State.Running}}' "$SERVICE" 2>/dev/null)" != true ]]; then
    docker start "$SERVICE" >/dev/null
  fi
  existing_running
  echo 'CHATGPT_DEPENDENCIES_ROLLBACK=ORIGINAL_PERSONAL_RESTORED'
}
case "$phase" in
stage)
  [[ ! -f "$NEW" ]] || exit 2
  [[ ! -e "$BACKUP" ]] || exit 2
  [[ ! -e "$SCRIPT" ]] || exit 2
  check_old_settings
  docker image inspect "$(docker inspect -f '{{.Image}}' "$SERVICE")" >/dev/null
  python3 - "$OLD" "$NEW" <<'PY'
import json,pathlib,sys
src,dst=map(pathlib.Path,sys.argv[1:])
old=json.loads(src.read_text())
extras=['*.chatgpt.com','*.openai.com','*.oaistatic.com',
        '*.oaiusercontent.com','*.oaistatsig.com']
assert len(old)==153 and len(set(old))==153
assert not set(extras)&set(old)
new=sorted(old+extras)
assert len(new)==158 and len(set(new))==158
dst.write_text(json.dumps(new,separators=(',',':'))+'\n')
dst.chmod(0o600)
PY
  chown 1001:1001 "$NEW"
  check_policy
  install -m 700 "$0" "$SCRIPT"
  echo 'CHATGPT_DEPENDENCIES_STAGED_NO_LIVE_CHANGE=true'
  ;;
replace)
  check_old_settings
  check_policy
  [[ ! -e "$BACKUP" ]] || exit 2
  image="$(docker inspect -f '{{.Image}}' "$SERVICE")"
  docker image inspect "$image" >/dev/null
  systemd-run --quiet --unit=mnebydns-personal-chatgpt-deps-revert-20261114 \
    --on-active=420s --collect /bin/bash "$SCRIPT" rollback
  systemctl is-active --quiet "$TIMER"
  trap rollback ERR
  docker stop "$SERVICE" >/dev/null
  docker rename "$SERVICE" "$BACKUP"
  run_existing "$image"
  verify_ready
  [[ "$(docker inspect -f '{{.State.Running}}' "$BACKUP")" == false ]]
  trap - ERR
  echo 'CHATGPT_DEPENDENCIES_ORIGINAL_PERSONAL_8856=UPDATED'
  ;;
rollback)
  rollback
  ;;
finalize)
  existing_running
  check_policy
  [[ "$(docker inspect -f '{{.State.Running}}' "$BACKUP")" == false ]]
  envs="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE")"
  [[ "$envs" == *'policy-chatgpt-dependencies-20261114.json'* ]]
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  docker rm "$BACKUP" >/dev/null
  echo 'CHATGPT_DEPENDENCIES_PERSONAL_8856_FINALIZED=true'
  ;;
status)
  existing_running
  check_policy
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE" | grep -Fq 'policy-chatgpt-dependencies-20261114.json'
  echo 'CHATGPT_DEPENDENCIES_PERSONAL_8856=RUNNING'
  ;;
*) exit 2;;
esac
