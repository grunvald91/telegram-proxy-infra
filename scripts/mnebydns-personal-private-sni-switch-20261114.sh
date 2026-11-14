#!/usr/bin/env bash
# Change ONLY personal SNI upstream from old RU sidecar :8853 to
# prevalidated WireGuard-backed RU sidecar :8856. Do not disable free DNS.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
phase="${1:?switch/rollback}"
conf=/etc/mnebydns/personal-sni/nginx.conf
backup=/etc/mnebydns/personal-sni/nginx.conf.before-private-20261114
old='10.66.77.2:8853;'
new='10.66.77.2:8856;'
switch_config(){
  python3 - "$conf" "$backup" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1])
b=pathlib.Path(sys.argv[2])
src=p.read_bytes()
assert not b.exists(), 'Backup already exists'
assert src.count(b'10.66.77.2:8853;')==1, 'Old personal upstream changed'
assert src.count(b'default 89.125.90.101:853;')==1, 'Do not modify free DNS mapping'
assert b'listen 0.0.0.0:8854;' in src
b.write_bytes(src)
b.chmod(0o600)
p.write_bytes(src.replace(b'10.66.77.2:8853;',b'10.66.77.2:8856;'))
assert p.read_bytes().count(b'default 89.125.90.101:853;')==1
PY
}
rollback(){
  if [[ -f "$backup" ]]; then
    python3 - "$conf" "$backup" <<'PY'
import pathlib,sys
p,b=map(pathlib.Path,sys.argv[1:3])
src=p.read_bytes()
orig=b.read_bytes()
assert src.count(b'10.66.77.2:8856;')==1, 'Refuse unsafe rollback of edited config'
assert orig.count(b'10.66.77.2:8853;')==1
assert orig.count(b'default 89.125.90.101:853;')==1
p.write_bytes(orig)
PY
    nginx -t -c "$conf"
    nginx -s reload -c "$conf"
    rm -f "$backup"
  fi
  echo 'PERSONAL_SNI_PRIVATE_SWITCH=ROLLED_BACK_FREE_DNS_UNCHANGED'
}
case "$phase" in
  switch)
    test -s "$conf"
    [[ "$(systemctl is-active mnebydns-dot)" == active ]] || exit 2
    [[ "$(systemctl is-active mnebydns-personal-sni-stream.service)" == active ]] || exit 2
    [[ "$(systemctl is-active mnebydns-personal-sni-redirect.service)" == active ]] || exit 2
    iptables -w -t nat -C PREROUTING -i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854
    python3 - <<'PY'
import socket,ssl
with socket.create_connection(('10.66.77.2',8856),timeout=7) as raw:
    raw.settimeout(7)
    with ssl.create_default_context().wrap_socket(raw,server_hostname='aaaaaaaaaaaa.dns.mnebyvpn.site') as tls:
        assert bool(tls.getpeercert())
print('PERSONAL_NEW_RU_PRIVATE_TLS_PRECHECK=PASS')
PY
    switch_config
    trap rollback ERR
    nginx -t -c "$conf"
    nginx -s reload -c "$conf"
    trap - ERR
    echo 'PERSONAL_SNI_PRIVATE_SWITCH=RELOADED_PERSONAL_ONLY'
    echo 'PERSONAL_SNI_LEGACY_CORE_DNS_UNCHANGED=true'
    ;;
  rollback)
    rollback
    ;;
  status)
    if grep -Fq "$new" "$conf"; then
      echo 'PERSONAL_SNI_PRIVATE_UPSTREAM=10_66_77_2_8856'
    else
      echo 'PERSONAL_SNI_PRIVATE_UPSTREAM=NOT_SWITCHED'
    fi
    ;;
  *) exit 2;;
esac
