#!/usr/bin/env bash
# DE isolated personal SNI swap. Preserve default legacy CoreDNS, Nginx listener and the RU old sidecar.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
phase="${1:?switch/finalize/rollback/status}"
conf=/etc/mnebydns/personal-sni/nginx.conf
backup=/etc/mnebydns/personal-sni/nginx.conf.before-chatgpt-two-20261114
old='10.66.77.2:8856;'
new='10.66.77.2:8858;'
timer=mnebydns-chatgpt-two-autorevert.timer
my_path=/tmp/mnebydns-personal-chatgpt-two-switch-20261114.sh
rollback(){
  if [[ -f "$backup" ]]; then
    python3 - "$conf" "$backup" <<'PY'
import pathlib,sys
p,b=map(pathlib.Path,sys.argv[1:])
cur=p.read_bytes();original=b.read_bytes()
assert original.count(b'10.66.77.2:8856;')==1
assert original.count(b'default 89.125.90.101:853;')==1
assert cur.count(b'10.66.77.2:8858;')==1 or cur==original
p.write_bytes(original)
PY
    nginx -t -c "$conf"
    nginx -s reload -c "$conf"
    rm -f "$backup"
  fi
  systemctl stop "$timer" >/dev/null 2>&1 || true
  echo 'PERSONAL_CHATGPT_TWO_DE_ROLLBACK=ORIGINAL_8856_RESTORED'
}
case "$phase" in
 switch)
    [[ -f "$conf" && ! -e "$backup" ]]
    [[ "$(systemctl is-active mnebydns-dot)" == active ]]
    [[ "$(systemctl is-active mnebydns-personal-sni-stream.service)" == active ]]
    [[ "$(systemctl is-active mnebydns-personal-sni-redirect.service)" == active ]]
    iptables -w -t nat -C PREROUTING -i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854
    python3 - <<'PY'
import socket,ssl
context=ssl.create_default_context()
for port in (8856,8858):
    with socket.create_connection(('10.66.77.2',port),timeout=6) as raw:
        raw.settimeout(6)
        with context.wrap_socket(raw,server_hostname='aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
            assert tls.getpeercert()
print('PERSONAL_CHATGPT_TWO_DE_TO_RU_8856_AND_8858_TLS=PASS')
PY
    python3 - "$conf" "$backup" <<'PY'
import pathlib,sys
p,b=map(pathlib.Path,sys.argv[1:])
src=p.read_bytes()
assert src.count(b'10.66.77.2:8856;')==1, 'Live SNI target changed'
assert src.count(b'default 89.125.90.101:853;')==1, 'Legacy mapping must remain untouched'
assert src.count(b'listen 0.0.0.0:8854;')==1
b.write_bytes(src);b.chmod(0o600)
PY
    # Arm independent automatic rollback BEFORE changing the Nginx upstream.
    test -s "$my_path"
    systemd-run --quiet --unit=mnebydns-chatgpt-two-autorevert --on-active=420s --collect /bin/bash "$my_path" rollback
    systemctl is-active --quiet "$timer"
    python3 - "$conf" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]);s=p.read_bytes()
assert s.count(b'10.66.77.2:8856;')==1
p.write_bytes(s.replace(b'10.66.77.2:8856;',b'10.66.77.2:8858;'))
PY
    nginx -t -c "$conf"
    nginx -s reload -c "$conf"
    grep -Fq "$new" "$conf"
    echo 'PERSONAL_CHATGPT_TWO_DE_SNI_SWITCH=LIVE_8858'
    echo 'PERSONAL_CHATGPT_TWO_LEGACY_MAPPING_UNCHANGED=true'
    ;;
 finalize)
    [[ -f "$backup" ]]
    grep -Fq "$new" "$conf"
    nginx -t -c "$conf"
    systemctl stop "$timer" >/dev/null 2>&1 || true
    ! systemctl is-active --quiet "$timer"
    echo 'PERSONAL_CHATGPT_TWO_DE_SNI_SWITCH=COMMITTED_WITH_ROLLBACK_BACKUP'
    ;;
 rollback) rollback;;
 status)
    if grep -Fq "$new" "$conf"; then echo 'PERSONAL_CHATGPT_TWO_DE_SNI=8858';else echo 'PERSONAL_CHATGPT_TWO_DE_SNI=OTHER';fi
    ;;
 *) exit 2;;
esac
