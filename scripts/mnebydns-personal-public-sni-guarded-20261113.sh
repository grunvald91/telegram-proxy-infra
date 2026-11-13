#!/usr/bin/env bash
# Public TCP/853 is never rebound; separate Nginx stream on 8854 plus reversible ingress redirect.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
PHASE="$1"
ROOT=/etc/mnebydns/personal-sni
MARK="$ROOT/owned-by-guarded-sni-release"
STREAM=mnebydns-personal-sni-stream.service
REDIRECT=mnebydns-personal-sni-redirect.service
GUARD=mnebydns-personal-sni-revert.timer
NAT=(-i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854)
BLOCK=(-i eth0 -p tcp --dport 8854 -m conntrack '!' --ctorigdstport 853 -j DROP)
nat_present(){ iptables -w -t nat -C PREROUTING "${NAT[@]}" >/dev/null 2>&1; }
block_present(){ iptables -w -C INPUT "${BLOCK[@]}" >/dev/null 2>&1; }
owned(){ [[ -f "$MARK" ]]; }

rollback(){
  if ! owned; then echo 'PERSONAL_SNI_ROLLBACK_NOT_OWNED=true'; return; fi
  systemctl stop "$GUARD" >/dev/null 2>&1 || true
  systemctl disable --now "$REDIRECT" >/dev/null 2>&1 || true
  if nat_present; then iptables -w -t nat -D PREROUTING "${NAT[@]}"; fi
  systemctl disable --now "$STREAM" >/dev/null 2>&1 || true
  if block_present; then iptables -w -D INPUT "${BLOCK[@]}"; fi
  rm -f "/etc/systemd/system/$REDIRECT" "/etc/systemd/system/$STREAM"
  systemctl daemon-reload
  rm -rf "$ROOT"
  echo 'PERSONAL_SNI_PUBLIC_853_RESTORED_TO_COREDNS=true'
}
preflight(){
  [[ "$(ip -o -4 addr show dev eth0)" == *89.125.90.101* ]] ||
    { echo 'PERSONAL_SNI_FOREIGN_IP_MISMATCH=true'; exit 2; }
  [[ "$(systemctl is-active mnebydns-dot)" == active ]] || exit 2
  [[ "$(ss -Hlntp | grep -E ':853[[:space:]]')" == *coredns* ]] || exit 2
  [[ -f /usr/lib/nginx/modules/ngx_stream_module.so ]] || exit 2
  [[ -f /opt/mnebydns-dot/Corefile ]] || exit 2
  ! ss -Hlnt | awk '{print $4}' | grep -Eq ':8854$' ||
    { echo 'PERSONAL_SNI_PROXY_PORT_OCCUPIED=true'; exit 2; }
  ! nat_present || { echo 'PERSONAL_SNI_NAT_ALREADY_ACTIVE=true'; exit 2; }
  ! block_present || { echo 'PERSONAL_SNI_BLOCK_ALREADY_PRESENT=true'; exit 2; }
  [[ ! -e "$ROOT" && ! -e "/etc/systemd/system/$STREAM" &&
     ! -e "/etc/systemd/system/$REDIRECT" ]] ||
    { echo 'PERSONAL_SNI_REFUSE_PREEXISTING_FILES=true'; exit 2; }
  python3 - <<'PY'
import ssl,socket
ctx=ssl.create_default_context()
with socket.create_connection(('10.66.77.2',8853),timeout=6) as s:
    s.settimeout(6)
    with ctx.wrap_socket(s,server_hostname='aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
        assert tls.version() in ('TLSv1.2','TLSv1.3')
print('PERSONAL_SNI_PRIVATE_TLS=PASS')
PY
}
prepare(){
  preflight
  install -d -m 700 "$ROOT"
  : > "$MARK"
  chmod 600 "$MARK"
  cat > "$ROOT/nginx.conf" <<'NGINX'
load_module /usr/lib/nginx/modules/ngx_stream_module.so;
user www-data;
worker_processes 1;
pid /run/mnebydns-personal-sni.pid;
error_log stderr warn;
events { worker_connections 4096; }
stream {
  map $ssl_preread_server_name $personal_dot_target {
    "~*^[a-z0-9]{12}[.]dns[.]mnebyvpn[.]site$" 10.66.77.2:8853;
    default 89.125.90.101:853;
  }
  server {
    listen 0.0.0.0:8854;
    ssl_preread on;
    proxy_pass $personal_dot_target;
    proxy_connect_timeout 5s;
    proxy_timeout 1h;
    proxy_socket_keepalive on;
  }
}
NGINX
  chmod 600 "$ROOT/nginx.conf"
  cat > "/etc/systemd/system/$STREAM" <<'UNIT'
[Unit]
Description=MNEBYDNS separate TCP/853 TLS SNI stream router
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/sbin/nginx -c /etc/mnebydns/personal-sni/nginx.conf -g 'daemon off;'
KillSignal=SIGQUIT
Restart=on-failure
RestartSec=2s
LimitNOFILE=16384
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
  cat > "/etc/systemd/system/$REDIRECT" <<'UNIT'
[Unit]
Description=MNEBYDNS reversible external TCP/853 SNI demux
BindsTo=mnebydns-personal-sni-stream.service
After=mnebydns-personal-sni-stream.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/sh -c '/usr/sbin/iptables -w -C INPUT -i eth0 -p tcp --dport 8854 -m conntrack ! --ctorigdstport 853 -j DROP || /usr/sbin/iptables -w -I INPUT 1 -i eth0 -p tcp --dport 8854 -m conntrack ! --ctorigdstport 853 -j DROP'
ExecStart=/bin/sh -c '/usr/sbin/iptables -w -t nat -C PREROUTING -i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854 || /usr/sbin/iptables -w -t nat -I PREROUTING 1 -i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854'
ExecStop=/bin/sh -c '/usr/sbin/iptables -w -t nat -D PREROUTING -i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854 || true'
ExecStopPost=/bin/sh -c '/usr/sbin/iptables -w -D INPUT -i eth0 -p tcp --dport 8854 -m conntrack ! --ctorigdstport 853 -j DROP || true'
[Install]
WantedBy=multi-user.target
UNIT
  nginx -t -c "$ROOT/nginx.conf"
  iptables -w -I INPUT 1 "${BLOCK[@]}"
  block_present
  systemctl daemon-reload
  systemctl start "$STREAM"
  systemctl is-active --quiet "$STREAM"
  python3 - <<'PY'
import socket,ssl,struct,random
ctx=ssl.create_default_context()
for name in ('dns.mnebyvpn.site','aaaaaaaaaaaa.dns.mnebyvpn.site'):
    raw=socket.create_connection(('127.0.0.1',8854),timeout=8)
    raw.settimeout(8)
    with ctx.wrap_socket(raw,server_hostname=name) as tls:
        assert tls.version() in ('TLSv1.2','TLSv1.3')
        if name=='dns.mnebyvpn.site':
            tid=random.randrange(1,65535)
            q=struct.pack('!HHHHHH',tid,0x0100,1,0,0,0)
            q+=b'\x07example\x03com\x00'+struct.pack('!HH',1,1)
            tls.sendall(struct.pack('!H',len(q))+q)
            hdr=tls.recv(2)
            assert len(hdr)==2
            n=struct.unpack('!H',hdr)[0]
            assert 12<=n<=65535
            response=b''
            while len(response)<n:
                chunk=tls.recv(n-len(response))
                assert chunk
                response+=chunk
            assert int.from_bytes(response[:2],'big')==tid
            assert response[2]&0x80
            print('PERSONAL_SNI_LOCAL_LEGACY_DNS=PASS')
        else:
            print('PERSONAL_SNI_LOCAL_WILDCARD_TLS=PASS')
PY
  echo 'PERSONAL_SNI_SEPARATE_PROXY_READY=PASS'
  echo 'PERSONAL_SNI_PUBLIC_853_UNCHANGED=true'
}
begin(){
  owned || exit 2
  systemctl is-active --quiet "$STREAM"
  block_present
  ! nat_present || { echo 'PERSONAL_SNI_DUPLICATE_REDIRECT_REFUSED=true'; exit 2; }
  systemd-run --quiet --unit=mnebydns-personal-sni-revert --on-active=240s --collect \
    /bin/sh -c '/usr/sbin/iptables -w -t nat -D PREROUTING -i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854 || true'
  systemctl is-active --quiet "$GUARD"
  iptables -w -t nat -I PREROUTING 1 "${NAT[@]}"
  nat_present
  echo 'PERSONAL_SNI_PUBLIC_REDIRECT=CANARY_FAIL_OPEN'
}
finalize(){
  owned || exit 2
  systemctl is-active --quiet "$STREAM"
  nat_present
  block_present
  systemctl enable "$STREAM" >/dev/null
  systemctl enable --now "$REDIRECT" >/dev/null
  systemctl is-active --quiet "$REDIRECT"
  nat_present
  systemctl stop "$GUARD" >/dev/null 2>&1 || true
  echo 'PERSONAL_SNI_PUBLIC_REDIRECT=PERSISTENT_WITH_SYSTEMD'
  echo 'PERSONAL_SNI_COREDNS_RESTARTED=false'
}
status(){
  echo "PERSONAL_SNI_STREAM=$(systemctl is-active "$STREAM" 2>/dev/null || true)"
  echo "PERSONAL_SNI_REDIRECT=$(systemctl is-active "$REDIRECT" 2>/dev/null || true)"
  echo "PERSONAL_SNI_NAT=$(nat_present && echo active || echo absent)"
  echo "PERSONAL_SNI_FILTER=$(block_present && echo active || echo absent)"
  echo "PERSONAL_SNI_ORIGINAL_DOT=$(systemctl is-active mnebydns-dot 2>/dev/null || true)"
}
case "$PHASE" in
  prepare) prepare;;
  begin) begin;;
  finalize) finalize;;
  rollback) rollback;;
  status) status;;
  *) echo 'Invalid phase'; exit 2;;
esac
