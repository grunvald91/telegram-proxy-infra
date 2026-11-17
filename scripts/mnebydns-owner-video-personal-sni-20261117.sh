#!/usr/bin/env bash
# Only the personal TLS SNI map is switched. Public free DoT and :443 are untouched.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || exit 2
[[ $# == 1 ]] || exit 2
mode="$1"
conf=/etc/mnebydns/personal-sni/nginx.conf
backup=/etc/mnebydns/personal-sni/nginx.conf.before-owner-video-20261117
old='10.66.77.2:8856;'
new='10.66.77.2:8858;'
default='default 89.125.90.101:853;'
lock=/run/lock/mnebydns-personal-owner-video-sni.lock
exec 9>"$lock"
flock -w 45 9 || { echo 'PERSONAL_SNI_LOCK_BUSY=true'; exit 2; }

check_original() {
  test -s "$conf"
  test "$(grep -Fo "$old" "$conf" | wc -l)" -eq 1
  test "$(grep -Fo "$default" "$conf" | wc -l)" -eq 1
  [[ "$(systemctl is-active mnebydns-personal-sni-stream.service)" == active ]]
  [[ "$(systemctl is-active mnebydns-personal-sni-redirect.service)" == active ]]
  nginx -t -c "$conf" >/dev/null
}
check_new_tls() {
  python3 - <<'PY'
import socket,ssl
with socket.create_connection(("10.66.77.2",8858),timeout=8) as conn:
    conn.settimeout(8)
    with ssl.create_default_context().wrap_socket(
            conn,server_hostname="aaaaaaaaaaaa.dns.mnebyvpn.site") as tls:
        assert tls.version() in ("TLSv1.2","TLSv1.3")
        assert tls.getpeercert()
print("PERSONAL_NEW_BACKEND_TLS_STRICT=PASS")
PY
}
restore() {
  test -s "$backup" || { echo 'PERSONAL_SNI_ROLLBACK_BACKUP_MISSING=true';return 2; }
  python3 - "$conf" "$backup" <<'PY'
import os,pathlib,sys
p,b=map(pathlib.Path,sys.argv[1:])
current=p.read_bytes()
orig=b.read_bytes()
assert current.count(b"default 89.125.90.101:853;")==1
assert orig.count(b"10.66.77.2:8856;")==1
assert orig.count(b"default 89.125.90.101:853;")==1
if current.count(b"10.66.77.2:8856;")==1:
    assert current==orig,"Rollback pre-switch config mismatch"
else:
    assert current.count(b"10.66.77.2:8858;")==1
    tmp=p.with_suffix(".owner-video-rollback")
    tmp.write_bytes(orig)
    os.chmod(tmp,0o600)
    os.replace(tmp,p)
PY
  nginx -t -c "$conf" >/dev/null
  nginx -s reload -c "$conf" >/dev/null
  rm -f "$backup"
  echo 'PERSONAL_SNI_BACK_TO_8856=PASS'
}
case "$mode" in
  preflight)
    check_original
    test ! -e "$backup"
    check_new_tls
    echo 'PERSONAL_SNI_SWITCH_SAFE_TO_PROCEED=true'
    ;;
  switch)
    check_original
    test ! -e "$backup"
    check_new_tls
    cp -p "$conf" "$backup"
    chmod 600 "$backup"
    trap 'restore || true' ERR
    python3 - "$conf" <<'PY'
import os,pathlib,sys
p=pathlib.Path(sys.argv[1])
content=p.read_bytes()
assert content.count(b"10.66.77.2:8856;")==1
assert content.count(b"default 89.125.90.101:853;")==1
tmp=p.with_suffix(".owner-video-next")
tmp.write_bytes(content.replace(b"10.66.77.2:8856;",b"10.66.77.2:8858;"))
os.chmod(tmp,0o600)
os.replace(tmp,p)
PY
    nginx -t -c "$conf" >/dev/null
    nginx -s reload -c "$conf" >/dev/null
    trap - ERR
    echo 'PERSONAL_SNI_NOW_8858=PASS'
    echo 'LEGACY_PUBLIC_DNS_MAPPING_UNCHANGED=true'
    ;;
  rollback)
    if [[ -e "$backup" ]]; then
      restore
    else
      test "$(grep -Fo "$old" "$conf" | wc -l)" -eq 1
      echo 'PERSONAL_SNI_ALREADY_8856=true'
    fi
    ;;
  status)
    if grep -Fq "$new" "$conf";then echo 'PERSONAL_SNI_TARGET_PORT=8858';
    elif grep -Fq "$old" "$conf";then echo 'PERSONAL_SNI_TARGET_PORT=8856';
    else echo 'PERSONAL_SNI_TARGET_PORT=UNRECOGNIZED';exit 2;fi
    test "$(grep -Fo "$default" "$conf" | wc -l)" -eq 1
    nginx -t -c "$conf" >/dev/null
    echo 'PERSONAL_LEGACY_DEFAULT_UNCHANGED=true'
    ;;
  *) exit 2;;
esac
