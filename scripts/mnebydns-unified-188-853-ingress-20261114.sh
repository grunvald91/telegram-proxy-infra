#!/usr/bin/env bash
# DNS only: forward regular and personal DoT entering RU:853 via WG to DE:8854.
# Preserve Telegram-proxy default on RU:853 and all existing RU:443 rules.
# No TLS interception: SNI stream demux forwards raw TLS bytes unchanged.
set -Eeuo pipefail
[[ $(id -u) == 0 ]] || exit 2
phase="${1:?stage|switch|rollback|finalize|status}"
ROOT=/opt/mnebydns-unified-188-853-20261114
CONF=/etc/nginx/streams.d/01-mtproxy-stdports.conf
SCRIPT=/usr/local/sbin/mnebydns-unified-188-853-ingress-20261114
TIMER=mnebydns-unified-188-853-revert-20261114.timer
CANARY_PID=/run/mnebydns-unified-188-853-canary.pid
OLD='server { listen 853;  listen [::]:853;  proxy_pass s1_mtproxy; proxy_connect_timeout 10s; proxy_timeout 1h; proxy_socket_keepalive on; tcp_nodelay on; }'
check_old(){
  test -s "$CONF"
  [[ $(grep -Fxc "$OLD" "$CONF") == 1 ]]
  [[ ! -e "$ROOT" ]]
  [[ ! -e "$SCRIPT" ]]
  [[ -z $(ss -Hlnt 'sport = :18543') ]]
  grep -Fq 'upstream s1_mtproxy' /etc/nginx/streams.d/00-mtproxy-relay.conf
  nginx -t >/dev/null 2>&1
  systemctl is-active --quiet nginx.service
  [[ "$(ip -o -4 addr show dev tg-relay)" == *10.66.77.2/24* ]]
}
create_candidate(){
  python3 - "$CONF" "$ROOT/candidate.conf" "$ROOT/canary.conf" <<'PY'
import pathlib,sys
src,output,canary=(pathlib.Path(x) for x in sys.argv[1:])
old='server { listen 853;  listen [::]:853;  proxy_pass s1_mtproxy; proxy_connect_timeout 10s; proxy_timeout 1h; proxy_socket_keepalive on; tcp_nodelay on; }'
s=src.read_text()
assert s.splitlines().count(old)==1
assert '$mnebydns_ru853_target' not in s
new_map='''# DNS SNI to foreign existing splitter through existing WireGuard; MTProxy fallback retained.
map $ssl_preread_server_name $mnebydns_ru853_target {
    dns.mnebyvpn.site 10.66.77.1:8854;
    "~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.1:8854;
    default s1_mtproxy;
}
'''
new_server='''server {
    listen 853 so_keepalive=30s:10s:3;
    listen [::]:853 so_keepalive=30s:10s:3;
    ssl_preread on;
    proxy_pass $mnebydns_ru853_target;
    proxy_connect_timeout 6s;
    proxy_timeout 1h;
    proxy_socket_keepalive on;
    tcp_nodelay on;
}'''
candidate=new_map+s.replace(old,new_server,1)
assert candidate.count('listen 853 so_keepalive=')==1
assert candidate.count('default s1_mtproxy;')==1
output.write_text(candidate)
output.chmod(0o600)
canary_text='''load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user www-data;
worker_processes 1;
pid /run/mnebydns-unified-188-853-canary.pid;
error_log stderr warn;
events { worker_connections 256; }
stream {
  upstream s1_mtproxy { server 127.0.0.1:9443; }
'''+new_map+'''
  server {
    listen 127.0.0.1:18543;
    ssl_preread on;
    proxy_pass $mnebydns_ru853_target;
    proxy_connect_timeout 6s;
    proxy_timeout 30s;
    tcp_nodelay on;
  }
}
'''
canary.write_text(canary_text)
canary.chmod(0o600)
print('UNIFIED_RU853_CANDIDATE_PREPARED=PASS')
PY
}
verify_dot(){
  local port="$1"
  python3 - "$port" <<'PY'
import sys,ssl,socket,struct,secrets
port=int(sys.argv[1])
def connect(name):
    raw=socket.create_connection(('127.0.0.1',port),timeout=6)
    raw.settimeout(8)
    ctx=ssl.create_default_context()
    return ctx.wrap_socket(raw,server_hostname=name)
def query(tls,host):
    tx=secrets.randbelow(65535)
    q=struct.pack('!HHHHHH',tx,256,1,0,0,0)+b''.join(bytes([len(n)])+n.encode() for n in host.split('.'))+b'\0'+struct.pack('!HH',1,1)
    tls.sendall(struct.pack('!H',len(q))+q)
    h=tls.recv(2)
    if len(h)!=2:raise RuntimeError('no frame')
    n=struct.unpack('!H',h)[0]
    if not 12<=n<=16384:raise RuntimeError('bad frame')
    b=b''
    while len(b)<n:
        v=tls.recv(n-len(b))
        if not v:raise RuntimeError('truncated')
        b+=v
    assert b[:2]==q[:2] and b[3]&15==0,'bad DNS answer'
    return b
with connect('dns.mnebyvpn.site') as tls:
    for h in ('chatgpt.com','www.youtube.com','api.anthropic.com','example.org'):
        data=query(tls,h)
        print('UNIFIED_RU853_LEGACY_DOT_QUERY_PASS='+h,flush=True)
with connect('aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
    assert bool(tls.getpeercert())
    print('UNIFIED_RU853_PERSONAL_TLS_CERT_PASS=true',flush=True)
PY
}
case "$phase" in
stage)
  # Safe idempotence after a previously VERIFIED rollback: no live config
  # may be overwritten. Keep any unexpected/confirmed state untouched.
  if [[ -e "$ROOT" || -e "$SCRIPT" ]];then
    test -s "$ROOT/original.conf"
    cmp -s "$ROOT/original.conf" "$CONF"
    test ! -e "$ROOT/confirmed"
    test ! -e "$ROOT/ufw853-added"
    ! systemctl is-active --quiet "$TIMER"
    test ! -f "$CANARY_PID"
    nginx -t >/dev/null 2>&1
    rm -rf -- "$ROOT"
    rm -f -- "$SCRIPT"
    echo 'UNIFIED_RU853_PRIOR_VERIFIED_ROLLBACK_STAGING_CLEANED=true'
  fi
  check_old
  install -d -m 700 "$ROOT"
  cp -p "$CONF" "$ROOT/original.conf"
  create_candidate
  nginx -t -c "$ROOT/canary.conf" >/dev/null 2>&1
  install -m 700 "$0" "$SCRIPT"
  trap 'if test -f "$CANARY_PID";then nginx -s quit -c "$ROOT/canary.conf" >/dev/null 2>&1 || true; fi' EXIT
  nginx -c "$ROOT/canary.conf"
  for i in $(seq 1 18);do
    if ss -Hlnt 'sport = :18543' | grep -Fq '127.0.0.1:18543';then break;fi
    sleep .25
  done
  ss -Hlnt 'sport = :18543' | grep -Fq '127.0.0.1:18543'
  verify_dot 18543
  echo 'UNIFIED_RU853_CANARY_OVER_WG_TO_DE=PASS'
  ;;
switch)
  test -s "$ROOT/candidate.conf" && test -s "$ROOT/original.conf"
  cmp -s "$ROOT/original.conf" "$CONF"
  systemctl is-active --quiet nginx.service
  systemd-run --quiet --unit=mnebydns-unified-188-853-revert-20261114 \
    --on-active=1200s --collect /bin/bash "$SCRIPT" rollback
  systemctl is-active --quiet "$TIMER"
  trap 'bash "$SCRIPT" rollback || true' ERR
  cp -p "$ROOT/candidate.conf" "$CONF.unified-188.tmp"
  mv -f "$CONF.unified-188.tmp" "$CONF"
  nginx -t >/dev/null 2>&1
  nginx -s reload
  sleep 1
  # Expose only IPv4 DoT on the existing external interface; default UFW DROP blocked clients.
  # The explicit IPv4 source avoids implicitly adding any IPv6 rule.
  ufw --dry-run allow in on ens3 from 0.0.0.0/0 to 188.120.254.223 port 853 proto tcp >/dev/null
  ufw allow in on ens3 from 0.0.0.0/0 to 188.120.254.223 port 853 proto tcp comment 'MNEBYDNS public IPv4 DoT ingress' >/dev/null
  touch "$ROOT/ufw853-added"
  ufw status | grep -Fq '188.120.254.223 853/tcp'
  verify_dot 853
  cmp -s "$ROOT/candidate.conf" "$CONF"
  test "$(grep -Fc 'listen 993;' "$CONF")" -eq 1
  test "$(grep -Fc 'listen 995;' "$CONF")" -eq 1
  test "$(grep -Fc 'listen 465;' "$CONF")" -eq 1
  trap - ERR
  echo 'UNIFIED_RU853_BOTH_DNS_SNI_VIA_WG_MT_PROXY_FALLBACK=PASS'
  ;;
rollback)
  if [[ -f "$ROOT/original.conf" ]];then
    if cmp -s "$ROOT/candidate.conf" "$CONF";then
      cp -p "$ROOT/original.conf" "$CONF.rollback-20261114"
      mv -f "$CONF.rollback-20261114" "$CONF"
      nginx -t >/dev/null 2>&1
      nginx -s reload
    elif ! cmp -s "$ROOT/original.conf" "$CONF";then
      echo 'UNIFIED_RU853_ROLLBACK_CONFIG_DRIFT_REFUSED=true' >&2
      exit 4
    fi
    if [[ -f "$ROOT/ufw853-added" ]];then
      ufw delete allow in on ens3 from 0.0.0.0/0 to 188.120.254.223 port 853 proto tcp >/dev/null
      rm -f "$ROOT/ufw853-added"
      echo 'UNIFIED_RU853_FIREWALL_RULE_REMOVED=PASS'
    fi
    systemctl stop "$TIMER" >/dev/null 2>&1 || true
    cmp -s "$ROOT/original.conf" "$CONF"
    echo 'UNIFIED_RU853_ORIGINAL_MT_PROXY_853_RESTORED=PASS'
  fi
  ;;
finalize)
  cmp -s "$ROOT/candidate.conf" "$CONF"
  test -f "$ROOT/ufw853-added"
  ufw status | grep -Fq '188.120.254.223 853/tcp'
  verify_dot 853
  nginx -t >/dev/null 2>&1
  systemctl is-active --quiet nginx.service
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  touch "$ROOT/confirmed"
  echo 'UNIFIED_RU853_DNS_SNI_AND_MT_PROXY_CONFIRMED=true'
  ;;
status)
  cmp -s "$ROOT/candidate.conf" "$CONF"
  verify_dot 853
  echo 'UNIFIED_RU853_STATUS=PASS'
  ;;
*)exit 2;;
esac
