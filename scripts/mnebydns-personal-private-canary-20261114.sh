#!/usr/bin/env bash
# New separate personal DoT canary; never stop or overwrite original
# mnebydns-personal-dot on 10.66.77.2:8853.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
action="${1:?stage or rollback required}"
NAME=mnebydns-personal-dot-private
TARGET=/etc/mnebydns/personal-dot
MARK=/etc/mnebydns/personal-dot/private-canary-created-by-20261114
rule_comment='MNEBYDNS private personal DoT v2'
ufw_allow(){
  ufw allow in on tg-relay from 10.66.77.1 to 10.66.77.2 port 8856 proto tcp comment "$rule_comment" >/dev/null
}
ufw_remove(){
  ufw delete allow in on tg-relay from 10.66.77.1 to 10.66.77.2 port 8856 proto tcp >/dev/null
}
case "$action" in
  stage)
    test "$(docker inspect -f '{{.State.Running}}' mnebydns-personal-dot)" = true
    test "$(ip -o -4 addr show dev tg-relay | grep -c '10.66.77.2/24')" = 1
    [[ "$(ufw status)" == 'Status: active'* ]] || exit 2
    test -s "$TARGET/fullchain.pem"
    test -s "$TARGET/privkey.pem"
    test -s "$TARGET/policy.json"
    test -s "$TARGET/personal-dot-production.ts"
    test -s /opt/mnebyvpn/bot/web.env
    [[ ! -e "$MARK" ]] || { echo 'PRIVATE_CANARY_MARK_EXISTS_REFUSE=true'; exit 2; }
    ! docker ps -a --format '{{.Names}}' | grep -qx "$NAME" ||
      { echo 'PRIVATE_CANARY_ALREADY_EXISTS_REFUSE=true'; exit 2; }
    for port in 8856 8857; do
      ! ss -Hlnt | awk '{print $4}' | grep -Eq ":$port$" ||
        { echo 'PRIVATE_CANARY_PORT_OCCUPIED=true'; exit 2; }
    done
    image="$(docker inspect -f '{{.Image}}' mnebydns-personal-dot)"
    docker image inspect "$image" >/dev/null
    # Verify full private WireGuard/TLS origin before container is created.
    python3 - <<'PY'
import socket,ssl
with socket.create_connection(('10.66.77.1',1853),timeout=6) as sock:
    sock.settimeout(6)
    with ssl.create_default_context().wrap_socket(sock,server_hostname='dns.mnebyvpn.site'):
        print('PRIVATE_CANARY_ORIGIN_TLS=PASS')
PY
    rule_added=0
    status="$(ufw status)"
    if [[ "$status" != *'MNEBYDNS private personal DoT v2'* ]]; then
      ufw_allow
      rule_added=1
    fi
    echo "$rule_added" > "$MARK"
    chmod 600 "$MARK"
    rollback_on_error(){
      docker rm -f "$NAME" >/dev/null 2>&1 || true
      if [[ -e "$MARK" ]]; then
        if [[ "$(cat "$MARK")" == 1 ]]; then ufw_remove || true; fi
        rm -f "$MARK"
      fi
    }
    trap rollback_on_error ERR
    policy_sha="$(sha256sum "$TARGET/policy.json" | cut -d' ' -f1)"
    docker run -d --name "$NAME" --network host \
      --user 1001:1001 --read-only --tmpfs /tmp:rw,nosuid,nodev,size=8m \
      --cap-drop ALL --security-opt no-new-privileges \
      --pids-limit 96 --memory 256m --cpus 0.5 \
      --restart unless-stopped \
      --env-file /opt/mnebyvpn/bot/web.env \
      -e MNEBYVPN_ENV=production \
      -e MNEBYDNS_PERSONAL_DOT_ENABLED=yes \
      -e MNEBYDNS_PERSONAL_DOT_BIND_IP=10.66.77.2 \
      -e MNEBYDNS_PERSONAL_DOT_PORT=8856 \
      -e MNEBYDNS_PERSONAL_DOT_HEALTH_PORT=8857 \
      -e MNEBYDNS_PERSONAL_DOT_TLS_KEY_FILE=/run/mnebydns-personal/privkey.pem \
      -e MNEBYDNS_PERSONAL_DOT_TLS_CERT_FILE=/run/mnebydns-personal/fullchain.pem \
      -e MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE=/run/mnebydns-personal/policy.json \
      -e "MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_SHA256=$policy_sha" \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_IP=10.66.77.1 \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_NAME=dns.mnebyvpn.site \
      -e MNEBYDNS_PERSONAL_MAPPED_DOT_PORT=1853 \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_IP=1.1.1.1 \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_NAME=one.one.one.one \
      -e MNEBYDNS_PERSONAL_DIRECT_DOT_PORT=853 \
      --mount "type=bind,source=$TARGET,target=/run/mnebydns-personal,readonly" \
      --mount "type=bind,source=$TARGET/personal-dot-production.ts,target=/srv/mnebyvpn/apps/service/src/personal-dot-production.ts,readonly" \
      --entrypoint node "$image" \
      --experimental-strip-types apps/service/src/personal-dot-production.ts >/dev/null
    ready=no
    for i in $(seq 1 22); do
      code="$(curl --noproxy '*' -sf -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8857/readyz || true)"
      if [[ "$code" == 200 ]]; then ready=yes;break;fi
      sleep 1
    done
    [[ "$ready" == yes ]] || { echo 'PRIVATE_CANARY_READY=FAIL'; exit 3; }
    python3 - <<'PY'
import socket,ssl
host='aaaaaaaaaaaa.dns.mnebyvpn.site'
with socket.create_connection(('10.66.77.2',8856),timeout=6) as raw:
    raw.settimeout(6)
    with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as tls:
        assert bool(tls.getpeercert())
print('PRIVATE_CANARY_PERSONAL_TLS=PASS')
PY
    trap - ERR
    echo 'PRIVATE_CANARY_UP=10_66_77_2_8856'
    echo 'ORIGINAL_PERSONAL_SIDE_CAR_8853_UNCHANGED=true'
    ;;
  rollback)
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    if [[ -f "$MARK" ]]; then
      if [[ "$(cat "$MARK")" == 1 ]]; then ufw_remove || true; fi
      rm -f "$MARK"
    fi
    echo 'PRIVATE_CANARY_ROLLED_BACK_OLD_STILL_RUNNING=true'
    ;;
  *) exit 2;;
esac
