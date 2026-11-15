#!/usr/bin/env bash
# In-place complete personal DNS policy from one canonical DE89 CoreDNS source.
# Preserve subscriber IDs, database, quota accounting, auth-cache and DoT :8856.
# Preserve auth 60s listener overlay, legacy DNS, DE Nginx, server key and DB.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
phase="${1:?stage|replace|rollback|finalize|status}"
BASE=/etc/mnebydns/personal-dot
OLD="$BASE/policy-chatgpt-dependencies-20261114.json"
NEW="$BASE/policy-derived-from-de89-20261115.json"
MANIFEST="$BASE/policy-derived-from-de89-20261115.manifest.json"
STAGED_JSON=/tmp/mnebydns-de89-personal-policy-20261115.json
STAGED_MANIFEST=/tmp/mnebydns-de89-personal-policy-20261115.manifest.json
SERVICE=mnebydns-personal-dot-private
BACKUP=mnebydns-personal-dot-private-before-de89-policy-20261115
SRC="$BASE/personal-dot-listener-auth60-20261114.ts"
SCRIPT=/usr/local/sbin/mnebydns-de89-personal-policy-sync-20261115
TIMER=mnebydns-de89-personal-policy-revert-20261115.timer
LISTENER=/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts
PRODUCTION=/srv/mnebyvpn/apps/service/src/personal-dot-production.ts
PORT=8856
HEALTH=8857
existing_running(){
  [[ "$(docker inspect -f '{{.State.Running}}' "$SERVICE")" == true ]]
}
check_policy(){
  python3 - "$OLD" "$NEW" "$MANIFEST" <<'PY'
import hashlib,json,pathlib,sys
oldpath,newpath,manifestpath=map(pathlib.Path,sys.argv[1:])
old=json.loads(oldpath.read_text())
new=json.loads(newpath.read_text())
m=json.loads(manifestpath.read_text())
assert len(old)==158 and len(set(old))==158
assert len(new)==m['new_policy_count'] and len(set(new))==len(new)
assert m['core_a_templates']>=264 and m['core_family_roots']==75
assert m['obsolete_personal_only_entries']==0 and m['original_policy_count']==158
assert m['sha256']==hashlib.sha256(newpath.read_bytes()).hexdigest()
assert {'chatgpt.com','auth.openai.com','*.chatgpt.com','*.openai.com'}<=set(new)
assert len(new)>len(old)
print('PERSONAL_DE89_POLICY_VERIFIED_COUNT='+str(len(new)),flush=True)
print('PERSONAL_DE89_POLICY_SHA256='+m['sha256'],flush=True)
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
  [[ "$settings" == *'policy-chatgpt-dependencies-20261114.json'* ]]
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
    -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE=/run/mnebydns-personal/policy-derived-from-de89-20261115.json \
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
  echo 'PERSONAL_DE89_SHARED_POLICY_ROLLBACK=ORIGINAL_PERSONAL_RESTORED'
}
case "$phase" in
stage)
  [[ ! -e "$NEW" && ! -e "$MANIFEST" && ! -e "$BACKUP" && ! -e "$SCRIPT" ]] || exit 2
  [[ -s "$STAGED_JSON" && -s "$STAGED_MANIFEST" ]] || exit 3
  check_old_settings
  install -m 600 "$STAGED_JSON" "$NEW"
  install -m 600 "$STAGED_MANIFEST" "$MANIFEST"
  chown 1001:1001 "$NEW"
  check_policy
  docker image inspect "$(docker inspect -f '{{.Image}}' "$SERVICE")" >/dev/null
  install -m 700 "$0" "$SCRIPT"
  echo 'PERSONAL_DE89_POLICY_STAGED_WITHOUT_CONTAINER_CHANGE=PASS'
  ;;
replace)
  check_old_settings
  check_policy
  [[ ! -e "$BACKUP" ]] || exit 2
  image="$(docker inspect -f '{{.Image}}' "$SERVICE")"
  docker image inspect "$image" >/dev/null
  systemd-run --quiet --unit=mnebydns-de89-personal-policy-revert-20261115 \
    --on-active=600s --collect /bin/bash "$SCRIPT" rollback
  systemctl is-active --quiet "$TIMER"
  trap rollback ERR
  docker stop "$SERVICE" >/dev/null
  docker rename "$SERVICE" "$BACKUP"
  run_existing "$image"
  verify_ready
  [[ "$(docker inspect -f '{{.State.Running}}' "$BACKUP")" == false ]]
  trap - ERR
  echo 'PERSONAL_DE89_SHARED_POLICY_EXISTING_8856=UPDATED'
  ;;
rollback)
  rollback
  ;;
finalize)
  existing_running
  check_policy
  [[ "$(docker inspect -f '{{.State.Running}}' "$BACKUP")" == false ]]
  envs="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE")"
  [[ "$envs" == *'policy-derived-from-de89-20261115.json'* ]]
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  docker rm "$BACKUP" >/dev/null
  echo 'PERSONAL_DE89_SHARED_POLICY_FINALIZED=true'
  ;;
status)
  existing_running
  check_policy
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$SERVICE" | grep -Fq 'policy-derived-from-de89-20261115.json'
  echo 'PERSONAL_DE89_SHARED_POLICY_8856=RUNNING'
  ;;
*) exit 2;;
esac
