#!/usr/bin/env bash
# Isolated RU replacement for the personalized DoT sidecar. Do not touch live 8856/8853 or DE CoreDNS.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
action="${1:?stage/rollback}"
base=/etc/mnebydns/personal-dot
stage=/etc/mnebydns/personal-dot-chatgpt-two-20261114
name=mnebydns-personal-dot-chatgpt-two
old=mnebydns-personal-dot-private
mark="$stage/.owned-by-20261114"
rulecomment='MNEBYDNS personal ChatGPT two canary'
port=8858
health=8859
rollback(){
  docker rm -f "$name" >/dev/null 2>&1 || true
  if [[ -f "$mark" ]]; then
    if [[ "$(cat "$mark")" == 1 ]]; then
      ufw delete allow in on tg-relay from 10.66.77.1 to 10.66.77.2 port "$port" proto tcp >/dev/null || true
    fi
    rm -rf "$stage"
  fi
  echo 'PERSONAL_CHATGPT_TWO_RU_ROLLBACK=OLD_8856_PRESERVED'
}
case "$action" in
  stage)
    [[ ! -e "$stage" ]] || { echo 'PERSONAL_CHATGPT_TWO_ALREADY_STAGED'; exit 2; }
    [[ "$(docker inspect -f '{{.State.Running}}' "$old")" == true ]]
    [[ "$(docker inspect -f '{{.State.Running}}' mnebydns-personal-dot)" == true ]]
    [[ "$(ip -o -4 addr show dev tg-relay)" == *10.66.77.2/24* ]]
    [[ "$(ufw status)" == 'Status: active'* ]]
    for p in "$port" "$health"; do
      ! ss -Hlnt | awk '{print $4}' | grep -Eq ":$p$" || { echo 'PERSONAL_CHATGPT_TWO_PORT_BUSY'; exit 2; }
    done
    ! docker ps -a --format '{{.Names}}' | grep -Fxq "$name"
    for f in policy.json fullchain.pem privkey.pem personal-dot-production.ts; do test -s "$base/$f"; done
    test -s /opt/mnebyvpn/bot/web.env
    image="$(docker inspect -f '{{.Image}}' "$old")"
    docker image inspect "$image" >/dev/null
    install -d -m 700 "$stage"
    trap 'rollback' ERR
    install -m 600 "$base/fullchain.pem" "$stage/fullchain.pem"
    install -m 600 "$base/privkey.pem" "$stage/privkey.pem"
    install -m 600 "$base/personal-dot-production.ts" "$stage/personal-dot-production.ts"
    python3 - "$base/policy.json" "$stage/policy.json" <<'PY'
import json,pathlib,hashlib,sys
source=pathlib.Path(sys.argv[1]); target=pathlib.Path(sys.argv[2])
raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='31f3fd3265d609521677ebf883881393529bf0c0a7d13bd057b15b8cb895b5d3', 'Existing personal rules changed; refuse unreviewed update'
items=json.loads(raw)
assert isinstance(items,list) and len(items)==151 and len(items)==len(set(items))
assert 'chatgpt.com' not in items and 'auth.openai.com' not in items
extra={'chatgpt.com','auth.openai.com'}
updated=sorted(set(items)|extra)
assert len(updated)==153
target.write_text(json.dumps(updated,separators=(',',':'))+'\n',encoding='utf-8')
target.chmod(0o600)
assert all(x in updated for x in extra)
print('PERSONAL_CHATGPT_TWO_RULES_ADDED=2')
print('PERSONAL_CHATGPT_TWO_TOTAL_RULES=153')
PY
    policy_sha="$(sha256sum "$stage/policy.json" | cut -d' ' -f1)"
    openssl x509 -in "$stage/fullchain.pem" -checkhost aaaaaaaaaaaa.dns.mnebyvpn.site -noout >/dev/null
    chown -R 1001:1001 "$stage"
    status="$(ufw status)"
    added=0
    if [[ "$status" != *"$rulecomment"* ]]; then
      ufw allow in on tg-relay from 10.66.77.1 to 10.66.77.2 port "$port" proto tcp comment "$rulecomment" >/dev/null
      added=1
    fi
    printf '%s\n' "$added" > "$mark"
    docker run -d --name "$name" --network host \
      --user 1001:1001 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=8m \
      --cap-drop ALL --security-opt no-new-privileges \
      --pids-limit 96 --memory 256m --cpus 0.5 --restart unless-stopped \
      --env-file /opt/mnebyvpn/bot/web.env \
      -e MNEBYVPN_ENV=production \
      -e MNEBYDNS_PERSONAL_DOT_ENABLED=yes \
      -e MNEBYDNS_PERSONAL_DOT_BIND_IP=10.66.77.2 \
      -e MNEBYDNS_PERSONAL_DOT_PORT="$port" \
      -e MNEBYDNS_PERSONAL_DOT_HEALTH_PORT="$health" \
      -e MNEBYDNS_PERSONAL_DOT_TLS_KEY_FILE=/run/mnebydns-personal/privkey.pem \
      -e MNEBYDNS_PERSONAL_DOT_TLS_CERT_FILE=/run/mnebydns-personal/fullchain.pem \
      -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE=/run/mnebydns-personal/policy.json \
      -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_SHA256="$policy_sha" \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_IP=10.66.77.1 \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_NAME=dns.mnebyvpn.site \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=1853 \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_IP=1.1.1.1 \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_NAME=one.one.one.one \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_PORT=853 \
      --mount "type=bind,source=$stage,target=/run/mnebydns-personal,readonly" \
      --mount "type=bind,source=$stage/personal-dot-production.ts,target=/srv/mnebyvpn/apps/service/src/personal-dot-production.ts,readonly" \
      --entrypoint node "$image" \
      --experimental-strip-types apps/service/src/personal-dot-production.ts >/dev/null
    ready=no
    for i in $(seq 1 18); do
      code="$(curl --noproxy '*' --max-time 2 -sf -o /dev/null -w '%{http_code}' http://127.0.0.1:"$health"/readyz || true)"
      if [[ "$code" == 200 ]]; then ready=yes;break;fi
      sleep 1
    done
    [[ "$ready" == yes ]] || { echo 'PERSONAL_CHATGPT_TWO_READY=FAILED'; exit 3; }
    python3 - <<'PY'
import socket,ssl
with socket.create_connection(('10.66.77.2',8858),timeout=6) as raw:
    raw.settimeout(6)
    with ssl.create_default_context().wrap_socket(raw,server_hostname='aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
        assert tls.getpeercert()
print('PERSONAL_CHATGPT_TWO_TLS=PASS')
PY
    [[ "$(docker inspect -f '{{.State.Running}}' "$old")" == true ]]
    trap - ERR
    echo 'PERSONAL_CHATGPT_TWO_CANARY_READY=true'
    echo 'PERSONAL_CHATGPT_TWO_ORIGINAL_SIDE_CAR_UNCHANGED=true'
    ;;
  rollback)
    [[ -e "$mark" ]] || { echo 'PERSONAL_CHATGPT_TWO_NOT_OWNED'; exit 2; }
    rollback
    ;;
  status)
    if [[ -e "$mark" ]]; then
      echo "PERSONAL_CHATGPT_TWO_CANARY=$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo no)"
    else
      echo 'PERSONAL_CHATGPT_TWO_CANARY=ABSENT'
    fi
    ;;
  *) exit 2;;
esac
