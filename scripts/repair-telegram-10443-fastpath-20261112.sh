#!/usr/bin/env bash
# Narrow live RU repair: 10443 -> DE nginx 443 SNI -> 127.0.0.1:9470
# Must be called only after foreign active SNI map and service preflight.
set -Eeuo pipefail
umask 077
file=/etc/nginx/streams.d/02-user-fastpath.conf
old='proxy_pass 10.66.77.1:9470;'
new='proxy_pass 10.66.77.1:443;'
changed=0
complete=0
backup=''
rollback() {
  status=$?
  trap - EXIT
  if [[ "$changed" == 1 && "$complete" != 1 && -f "$backup" ]]; then
    if ! cp -p "$backup" "$file"; then
      echo 'rollback=FAILED_CANNOT_RESTORE_BACKUP'
      exit 70
    fi
    if nginx -t >/dev/null 2>&1 && systemctl reload nginx; then
      echo 'rollback=restored_previous_fastpath_and_reloaded'
    else
      echo 'rollback=FAILED_NEEDS_MANUAL_RECOVERY'
    fi
  fi
  exit "$status"
}
trap rollback EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
test -f "$file" && test ! -L "$file"
systemctl is-active --quiet nginx
nginx -t >/dev/null 2>&1
python3 - "$file" <<'PY'
import pathlib,sys
s=pathlib.Path(sys.argv[1]).read_text()
a='proxy_pass 10.66.77.1:9470;'
b='proxy_pass 10.66.77.1:443;'
assert s.count('listen 10443 ')==1,'expected_RU_fastpath_listener_missing'
assert s.count(a)+s.count(b)==1,'unexpected_RU_fastpath_content'
assert 'proxy_connect_timeout 5s;' in s,'unexpected_fastpath_timeout'
print('ru_preflight=file_matches_single_expected_fastpath',flush=True)
PY
python3 - <<'PY'
import socket
for target in [('10.66.77.1',443),('127.0.0.1',10443),('127.0.0.1',443)]:
    with socket.create_connection(target,timeout=4): pass
print('ru_preflight=WG443_and_local10443_and_local443_TCP_accept',flush=True)
PY
if grep -Fq "$new" "$file"; then
  echo 'fastpath=already_correct'
  complete=1
  exit 0
fi
mkdir -p /root/proxy-backups
chmod 700 /root/proxy-backups
backup="$(mktemp /root/proxy-backups/telegram-fastpath-20261112.XXXXXXXX.conf)"
cp -p "$file" "$backup"
chmod 600 "$backup"
changed=1
python3 - "$file" <<'PY'
import os,pathlib,stat,sys,tempfile
p=pathlib.Path(sys.argv[1])
data=p.read_bytes()
old=b'proxy_pass 10.66.77.1:9470;'
new=b'proxy_pass 10.66.77.1:443;'
assert data.count(old)==1,'guard_expected_old_exactly_once'
st=p.stat()
fd,tmp=tempfile.mkstemp(dir=str(p.parent),prefix='.fastpath-stage-')
try:
    with os.fdopen(fd,'wb') as f:
        f.write(data.replace(old,new,1))
        f.flush()
        os.fsync(f.fileno())
    os.chown(tmp,st.st_uid,st.st_gid)
    os.chmod(tmp,stat.S_IMODE(st.st_mode))
    os.replace(tmp,p)
finally:
    if os.path.exists(tmp):os.unlink(tmp)
print('fastpath=single_destination_replaced',flush=True)
PY
nginx -t >/dev/null 2>&1
systemctl reload nginx
sleep 2
systemctl is-active --quiet nginx
nginx -t >/dev/null 2>&1
python3 - "$file" <<'PY'
import pathlib,subprocess,socket,sys
s=pathlib.Path(sys.argv[1]).read_text()
assert s.count('proxy_pass 10.66.77.1:443;')==1
assert 'proxy_pass 10.66.77.1:9470;' not in s
active=subprocess.run(['nginx','-T'],capture_output=True,text=True,timeout=10)
assert active.returncode==0
assert 'proxy_pass 10.66.77.1:443;' in active.stdout
for target in [('10.66.77.1',443),('127.0.0.1',10443),('127.0.0.1',443)]:
    with socket.create_connection(target,timeout=4): pass
print('postcheck=NGINX_config_loaded_and_WG443_10443_443_TCP_accept',flush=True)
PY
complete=1
echo 'fastpath_live_fix=SUCCESS'
echo 'backup=saved_on_RU_host'
