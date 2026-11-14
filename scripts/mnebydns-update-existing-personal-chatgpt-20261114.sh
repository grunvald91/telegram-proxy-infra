#!/usr/bin/env bash
# Replace ONLY the existing RU personal DoT :8856 container with a policy
# containing two exact ChatGPT names. Preserve hostname, ports, CoreDNS, :8853.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
phase="${1:?stage|replace|rollback|finalize|cleanup}"
base=/etc/mnebydns/personal-dot
oldpolicy="$base/policy.json"
policy="$base/policy-chatgpt-two-20261114.json"
service=mnebydns-personal-dot-private
backup=mnebydns-personal-dot-private-backup-20261114
candidate=mnebydns-personal-dot-chatgpt-two
candidate_dir=/etc/mnebydns/personal-dot-chatgpt-two-20261114
host=10.66.77.2
port=8856
health=8857
original_sha=31f3fd3265d609521677ebf883881393529bf0c0a7d13bd057b15b8cb895b5d3
check_json(){
 python3 - "$policy" <<'PY'
import json,pathlib,sys
items=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert len(items)==153 and len(set(items))==153
assert 'chatgpt.com' in items and 'auth.openai.com' in items
print('EXISTING_PERSONAL_POLICY_TWO_DOMAINS=PASS')
PY
}
new_is_running(){
 [[ "$(docker inspect -f '{{.State.Running}}' "$service")" == true ]]
}
restore(){
 if docker ps -a --format '{{.Names}}' | grep -Fxq "$backup"; then
   docker rm -f "$service" >/dev/null 2>&1 || true
   docker rename "$backup" "$service"
   docker start "$service" >/dev/null
 fi
}
case "$phase" in
  stage)
    [[ ! -e "$policy" ]] || exit 2
    [[ "$(docker inspect -f '{{.State.Running}}' "$service")" == true ]]
    [[ "$(docker inspect -f '{{.State.Running}}' "$candidate")" == true ]]
    [[ "$(ip -o -4 addr show dev tg-relay)" == *10.66.77.2/24* ]]
    [[ "$(sha256sum "$oldpolicy" | awk '{print $1}')" == "$original_sha" ]] || exit 2
    [[ ! -e "$backup" ]] || exit 2
    python3 - "$oldpolicy" "$policy" <<'PY'
import json,pathlib,sys
a,b=map(pathlib.Path,sys.argv[1:])
items=json.loads(a.read_text())
assert len(items)==151 and len(set(items))==151
assert 'chatgpt.com' not in items and 'auth.openai.com' not in items
new=sorted(items+['chatgpt.com','auth.openai.com'])
assert len(new)==153
b.write_text(json.dumps(new,separators=(',',':'))+'\n')
b.chmod(0o600)
PY
    chown 1001:1001 "$policy"
    check_json
    echo 'EXISTING_PERSONAL_POLICY_STAGED_WITHOUT_LIVE_CHANGE=true'
    ;;
  replace)
    check_json
    [[ "$(docker inspect -f '{{.State.Running}}' "$candidate")" == true ]]
    new_is_running
    [[ ! -e "$backup" ]] || exit 2
    image="$(docker inspect -f '{{.Image}}' "$service")"
    docker image inspect "$image" >/dev/null
    [[ "$(ufw status)" == 'Status: active'* ]]
    [[ "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$service")" == host ]]
    [[ "$(docker inspect -f '{{.Config.User}}' "$service")" == '1001:1001' ]]
    [[ "$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$service")" == unless-stopped ]]
    [[ "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$service")" == *'MNEBYDNS_PERSONAL_DOT_PORT=8856'* ]]
    [[ "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$service")" == *'MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=1853'* ]]
    policy_sha="$(sha256sum "$policy" | awk '{print $1}')"
    docker stop "$service" >/dev/null
    docker rename "$service" "$backup"
    trap 'restore' ERR
    docker run -d --name "$service" --network host \
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
      -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE=/run/mnebydns-personal/policy-chatgpt-two-20261114.json \
      -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_SHA256="$policy_sha" \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_IP=10.66.77.1 \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_NAME=dns.mnebyvpn.site \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=1853 \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_IP=1.1.1.1 \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_NAME=one.one.one.one \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_PORT=853 \
      --mount "type=bind,source=$base,target=/run/mnebydns-personal,readonly" \
      --mount "type=bind,source=$base/personal-dot-production.ts,target=/srv/mnebyvpn/apps/service/src/personal-dot-production.ts,readonly" \
      --entrypoint node "$image" \
      --experimental-strip-types apps/service/src/personal-dot-production.ts >/dev/null
    ready=no
    for i in $(seq 1 20); do
      code="$(curl --noproxy '*' --max-time 2 -sf -o /dev/null -w '%{http_code}' http://127.0.0.1:8857/readyz || true)"
      if [[ "$code" == 200 ]]; then ready=yes;break;fi
      sleep 1
    done
    [[ "$ready" == yes ]] || exit 3
    python3 - <<'PY'
import socket,ssl
ctx=ssl.create_default_context()
with socket.create_connection(('10.66.77.2',8856),timeout=6) as plain:
    plain.settimeout(6)
    with ctx.wrap_socket(plain,server_hostname='aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
        assert tls.getpeercert()
print('EXISTING_PERSONAL_8856_TLS=PASS')
PY
    [[ "$(docker inspect -f '{{.State.Running}}' "$backup")" == false ]]
    new_is_running
    trap - ERR
    echo 'EXISTING_PERSONAL_8856_REPLACED_IN_PLACE_WITH_TWO_DOMAINS=true'
    ;;
  rollback)
    restore
    [[ "$(docker inspect -f '{{.State.Running}}' "$service")" == true ]]
    echo 'EXISTING_PERSONAL_8856_ROLLBACK=ORIGINAL_RUNNING'
    ;;
  finalize)
    new_is_running
    [[ "$(docker inspect -f '{{.State.Running}}' "$backup")" == false ]]
    check_json
    docker rm "$backup" >/dev/null
    echo 'EXISTING_PERSONAL_8856_FINALIZED=true'
    ;;
  cleanup)
    # Only remove the temporary candidate created by the prior release.
    new_is_running
    [[ -f "$candidate_dir/.owned-by-20261114" ]]
    [[ "$(docker inspect -f '{{.State.Running}}' "$candidate")" == true ]]
    docker rm -f "$candidate" >/dev/null
    if [[ "$(cat "$candidate_dir/.owned-by-20261114")" == 1 ]]; then
      ufw delete allow in on tg-relay from 10.66.77.1 to 10.66.77.2 port 8858 proto tcp >/dev/null
    fi
    rm -rf "$candidate_dir"
    echo 'TEMP_PERSONAL_8858_REMOVED=true'
    ;;
  status)
    new_is_running
    check_json
    echo "EXISTING_PERSONAL_8856=$(docker inspect -f '{{.State.Running}}' "$service")"
    echo "TEMP_8858=$(docker inspect -f '{{.State.Running}}' "$candidate" 2>/dev/null || echo ABSENT)"
    ;;
  *) exit 2;;
esac
