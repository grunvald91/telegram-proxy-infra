#!/usr/bin/env bash
# Move ONLY the public non-personal DoT resolver to RU-188 A responses.
# Reuses the existing foreign VPS/CoreDNS binary and RU→WG→DE HTTPS path.
# The original DE CoreDNS and personal DoT paid upstream stay unchanged.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
phase="${1:?stage|switch|rollback|finalize|status}"
BASE=/opt/mnebydns-legacy-ru188-20261114
UNIT=mnebydns-legacy-ru188-dot.service
SERVICE=mnebydns-legacy-ru188-dot
SCRIPT=/usr/local/sbin/mnebydns-legacy-ru188-isolated-cutover-20261114
TIMER=mnebydns-legacy-ru188-revert-20261114.timer
CORE=/opt/mnebydns-dot/Corefile
SNI=/etc/mnebydns/personal-sni/nginx.conf
OLD_SERVICE=mnebydns-dot.service
OLD_NGINX=mnebydns-personal-sni-stream.service
CERT_DIR=/etc/letsencrypt/live/dns.mnebyvpn.site
PRIVATE_TARGET=10.66.77.2:8856
NEW_DOT=127.0.0.1:18553
MARK="$BASE/owned.marker"
active(){ systemctl is-active --quiet "$1"; }
check_baseline(){
  active "$OLD_SERVICE"
  active "$OLD_NGINX"
  active mnebydns-personal-sni-redirect.service
  active nginx
  test -s "$CORE" && test -s "$SNI"
  [[ "$(ip -o -4 addr show dev tg-relay)" == *10.66.77.1/24* ]]
  [[ "$(grep -Fc "$PRIVATE_TARGET;" "$SNI")" == 1 ]]
  [[ "$(grep -Fc 'default 89.125.90.101:853;' "$SNI")" == 1 ]]
  test -f "$CERT_DIR/fullchain.pem" && test -f "$CERT_DIR/privkey.pem"
  test -x /opt/mnebydns-dot/coredns
  nginx -t -c "$SNI" >/dev/null 2>&1
}
check_unchanged(){
  [[ "$(sha256sum "$CORE" | cut -d' ' -f1)" == "$(cat "$BASE/original-core.sha256")" ]]
}
write_candidate(){
  python3 - "$CORE" "$BASE/Corefile" <<'PY'
from pathlib import Path
import re,sys
src=Path(sys.argv[1]).read_text()
assert src.count('tls://.:853 {')==1
assert src.count('    bind 89.125.90.101')==1
old_tls='tls /run/credentials/mnebydns-dot.service/fullchain.pem /run/credentials/mnebydns-dot.service/privkey.pem'
assert src.count(old_tls)==1
rx=r'(?m)^(\s*answer\s+"\{\{ \.Name \}\}\s+\d+\s+IN\s+A\s+)89\.125\.90\.101(")\s*$'
candidate,n=re.subn(rx,r'\g<1>188.120.254.223\2',src)
assert n==253,('Expected 253 precise mapped A rules, observed',n)
candidate=candidate.replace('tls://.:853 {','tls://.:18553 {',1)
candidate=candidate.replace('    bind 89.125.90.101','    bind 127.0.0.1',1)
candidate=candidate.replace(old_tls,'tls /run/credentials/mnebydns-legacy-ru188-dot.service/fullchain.pem /run/credentials/mnebydns-legacy-ru188-dot.service/privkey.pem',1)
assert '    forward . tls://9.9.9.9 tls://149.112.112.112 {' in candidate
assert '    reload 5s 1s' in candidate
assert '    cache 30 {' in candidate
assert candidate.count('tls://.:18553 {')==1
assert candidate.count('answer "{{ .Name }} 20 IN A 188.120.254.223"')>=253
p=Path(sys.argv[2]); p.write_text(candidate);p.chmod(0o644)
print('LEGACY_RU188_EXACT_253_A_REWRITES_STAGED=PASS')
PY
}
write_service(){
  cat > "/etc/systemd/system/$UNIT" <<'UNITFILE'
[Unit]
Description=MNEBYDNS isolated public legacy DNS (RU 188 mapped A answers)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/opt/mnebydns-dot/coredns -conf /opt/mnebydns-legacy-ru188-20261114/Corefile
WorkingDirectory=/opt/mnebydns-dot
DynamicUser=yes
LoadCredential=fullchain.pem:/etc/letsencrypt/live/dns.mnebyvpn.site/fullchain.pem
LoadCredential=privkey.pem:/etc/letsencrypt/live/dns.mnebyvpn.site/privkey.pem
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_INET AF_UNIX
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryHigh=128M
MemoryMax=192M
MemorySwapMax=0
CPUQuota=30%
TasksMax=56
LimitNOFILE=512
Restart=on-failure
RestartSec=3s
TimeoutStopSec=10s
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
UNITFILE
}
check_dns(){
  python3 - <<'PY'
import socket,ssl,struct,secrets
def q(name,kind):
    tx=secrets.randbelow(65535)
    wire=struct.pack('!HHHHHH',tx,256,1,0,0,0)+b''.join(bytes([len(p)])+p.encode() for p in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)
    with socket.create_connection(('127.0.0.1',18553),timeout=6) as raw:
        raw.settimeout(7)
        with ssl.create_default_context().wrap_socket(raw,server_hostname='dns.mnebyvpn.site') as tls:
            tls.sendall(struct.pack('!H',len(wire))+wire)
            hdr=tls.recv(2)
            if len(hdr)!=2:raise RuntimeError('frame')
            n=struct.unpack('!H',hdr)[0]
            if n<12 or n>16384:raise RuntimeError('length')
            b=b''
            while len(b)<n:
                part=tls.recv(n-len(b))
                if not part:raise RuntimeError('truncated')
                b+=part
    assert b[:2]==wire[:2] and b[3]&15==0,(name,kind)
    return b
for name in ('chatgpt.com','auth.openai.com','www.youtube.com','youtubei.googleapis.com','www.googlevideo.com','i.ytimg.com','claude.ai','api.anthropic.com','gemini.google.com','x.com','cloud.oracle.com','copilot.microsoft.com'):
    b=q(name,1)
    assert bytes([188,120,254,223]) in b,(name,'not RU188')
    for kind in (28,64,65):
        b=q(name,kind)
        assert int.from_bytes(b[6:8],'big')==0,(name,'unsuppressed qtype',kind)
assert bytes([188,120,254,223]) not in q('example.org',1)
print('LEGACY_RU188_PRIVATE_CANARY_12_DOMAINS_AND_ALT_RR=PASS',flush=True)
PY
}
rollback(){
  if [[ ! -f "$MARK" ]];then echo 'LEGACY_RU188_NOT_INSTALLED=true';return 0;fi
  if [[ -f "$BASE/switched.marker" ]];then
    local current
    current="$(sha256sum "$SNI" | cut -d' ' -f1)"
    local new
    new="$(sha256sum "$BASE/sni.after" | cut -d' ' -f1)"
    local old
    old="$(sha256sum "$BASE/sni.before" | cut -d' ' -f1)"
    if [[ "$current" == "$new" ]]; then
      cp -p "$BASE/sni.before" "$SNI.rollback-tmp-20261114"
      mv -f "$SNI.rollback-tmp-20261114" "$SNI"
      nginx -t -c "$SNI" >/dev/null
      nginx -s reload -c "$SNI"
      echo 'LEGACY_RU188_SNI_DEFAULT_RESTORED=true'
    elif [[ "$current" != "$old" ]];then
      echo 'LEGACY_RU188_SNI_DRIFT_REFUSED=true' >&2
      return 4
    fi
  fi
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$UNIT"
  systemctl daemon-reload
  [[ "$(grep -Fc 'default 89.125.90.101:853;' "$SNI")" == 1 ]]
  active "$OLD_SERVICE"
  active "$OLD_NGINX"
  check_unchanged
  echo 'LEGACY_RU188_ROLLBACK_PUBLIC_ONLY=PASS'
}
case "$phase" in
  stage)
    check_baseline
    [[ ! -e "$BASE" ]] || exit 2
    [[ ! -e "/etc/systemd/system/$UNIT" ]] || exit 2
    [[ ! -e "$SCRIPT" ]] || exit 2
    [[ -z "$(ss -Hlnt 'sport = :18553')" ]] || exit 2
    mkdir -m 700 "$BASE"
    sha256sum "$CORE" | cut -d' ' -f1 > "$BASE/original-core.sha256"
    cp -p "$SNI" "$BASE/sni.before"
    write_candidate
    python3 - "$SNI" "$BASE/sni.after" <<'PY'
from pathlib import Path
import sys
old=Path(sys.argv[1]).read_text()
assert old.count('default 89.125.90.101:853;')==1
assert old.count('10.66.77.2:8856;')==1
new=old.replace('default 89.125.90.101:853;',
                'default 127.0.0.1:18553;',1)
assert new.count('10.66.77.2:8856;')==1
p=Path(sys.argv[2]);p.write_text(new);p.chmod(0o600)
PY
    cp -p "$BASE/sni.after" "$BASE/sni.preflight"
    nginx -t -c "$BASE/sni.preflight" >/dev/null 2>&1
    install -m 700 "$0" "$SCRIPT"
    write_service
    systemctl daemon-reload
    touch "$MARK"
    trap 'rollback || true' ERR
    systemctl start "$UNIT"
    for i in $(seq 1 24);do
      if ss -Hlnt 'sport = :18553' | grep -Fq '127.0.0.1:18553';then break;fi
      sleep .5
    done
    active "$UNIT"
    ss -Hlnt 'sport = :18553' | grep -Fq '127.0.0.1:18553'
    check_dns
    check_baseline
    check_unchanged
    trap - ERR
    echo 'LEGACY_RU188_SEPARATE_DOT_READY_OLD_PUBLIC_UNCHANGED=true'
    ;;
  switch)
    test -f "$MARK" && test -s "$BASE/Corefile"
    active "$UNIT"
    check_dns
    check_baseline
    check_unchanged
    cmp -s "$BASE/sni.before" "$SNI"
    systemd-run --quiet --unit=mnebydns-legacy-ru188-revert-20261114 \
      --on-active=900s --collect /bin/bash "$SCRIPT" rollback
    active "$TIMER"
    trap 'rollback || true' ERR
    cp -p "$BASE/sni.after" "$SNI.new-20261114"
    mv -f "$SNI.new-20261114" "$SNI"
    touch "$BASE/switched.marker"
    nginx -t -c "$SNI" >/dev/null
    nginx -s reload -c "$SNI"
    sleep 1
    active "$OLD_NGINX" && active "$OLD_SERVICE" && active "$UNIT"
    [[ "$(grep -Fc 'default 127.0.0.1:18553;' "$SNI")" == 1 ]]
    [[ "$(grep -Fc "$PRIVATE_TARGET;" "$SNI")" == 1 ]]
    check_unchanged
    trap - ERR
    echo 'LEGACY_RU188_DEFAULT_PUBLIC_DOT_SWITCHED_ROLLBACK_ARMED=true'
    ;;
  rollback) rollback;;
  finalize)
    test -f "$MARK" && test -f "$BASE/switched.marker"
    active "$UNIT" && active "$OLD_NGINX" && active "$OLD_SERVICE"
    cmp -s "$BASE/sni.after" "$SNI"
    check_unchanged
    active "$TIMER"
    systemctl enable "$UNIT" >/dev/null
    systemctl stop "$TIMER" >/dev/null 2>&1 || true
    touch "$BASE/confirmed.marker"
    echo 'LEGACY_RU188_SEPARATED_PUBLIC_DEFAULT_CONFIRMED=true'
    ;;
  status)
    active "$UNIT" && active "$OLD_SERVICE" && active "$OLD_NGINX"
    cmp -s "$BASE/sni.after" "$SNI"
    check_unchanged
    check_dns
    echo 'LEGACY_RU188_SEPARATED_PUBLIC_STATUS=PASS'
    ;;
  *)exit 2;;
esac
