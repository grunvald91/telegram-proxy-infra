#!/usr/bin/env bash
# Enable exactly one independently verified DIRECT Telemt 89:9446 route in the
# private owner-only sales UI. Public MTProxy products/routers remain untouched.
set -Eeuo pipefail
umask 077
test "$(id -u)" -eq 0
SHA=5c1f7a3398ceae3888cbf4ba3d3ba86b2367d640
ROOT=/opt/mnebyvpn
BOT="$ROOT/bot"
ENV="$BOT/web.env"
WORKER=/etc/mnebyvpn-owner-mtproxy/worker.env
PROMOTE=/tmp/mnebyvpn-owner-telemt-direct-promote.sh
SOCKET=/run/mnebyvpn-owner-mtproxy/telemt.sock
NAME=mnebyvpn-bot-info
LOCK=/run/lock/mnebyvpn-owner-telemt-direct-release.lock
exec 9>"$LOCK"
flock -w 60 9
test -s "$ENV" && test -s "$WORKER" && test -s "$PROMOTE"
test "$(stat -c '%a' "$ENV")" = 600
test "$(stat -c '%a' "$WORKER")" = 600
grep -Fxq 'MNEBYVPN_OFFLINE_SALES_ENABLED=yes' "$ENV"
test "$(docker inspect -f '{{.Config.Image}}' "$NAME")" = "mnebyvpn-stage-web:$SHA"
test "$(docker inspect -f '{{.State.Running}}' "$NAME")" = true
test -r "$ROOT/releases/$SHA/packages/web/src/telegram-proxy-bonus.ts"
test -r "$ROOT/releases/$SHA/apps/service/src/manual-sales.ts"
test "$(docker inspect -f '{{.State.Running}}' mnebyvpn-dns-mtproxy-bonus-worker)" = true
test "$(docker inspect -f '{{.RestartCount}}' mnebyvpn-dns-mtproxy-bonus-worker)" = 0
test "$(docker inspect -f '{{.Config.User}}' mnebyvpn-dns-mtproxy-bonus-worker)" = '13096:13096'
postgres_id="$(docker inspect -f '{{.Id}}' mnebyvpn-stage-postgres)"
[[ "$postgres_id" =~ ^[a-f0-9]{64}$ ]]
test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' mnebyvpn-dns-mtproxy-bonus-worker)" = "container:$postgres_id"
test "$(stat -c '%u:%g:%a' "$SOCKET")" = '13096:13096:600'
systemctl is-active -q mnebyvpn-owner-telemt-tunnel
setpriv --reuid=13096 --regid=13096 --clear-groups \
  curl --noproxy '*' --unix-socket "$SOCKET" -fsS --max-time 6 \
  http://localhost/v1/system/info |
  python3 -c 'import json,sys;assert json.load(sys.stdin).get("ok") is True'
# Validate the private cipher key is the SAME on owner UI and worker.
botkey="$(sed -n 's/^WEB_DNS_MT_PROXY_BONUS_KEY=//p' "$ENV")"
workerkey="$(sed -n 's/^WEB_DNS_MT_PROXY_BONUS_KEY=//p' "$WORKER")"
[[ "$botkey" =~ ^[a-f0-9]{64}$ ]]
test "$botkey" = "$workerkey"
unset botkey workerkey
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8793/readyz)" = 200

# Idempotent, strict comparison; do not rewrite or auto-correct unexpected values.
all_ready=yes
for item in \
 MNEBYVPN_OFFLINE_MTPROXY_ISSUE_ENABLED \
 MNEBYVPN_OFFLINE_MTPROXY_ROUTES_VERIFIED \
 MNEBYVPN_OFFLINE_MTPROXY_REVOKER_VERIFIED;do
  if ! grep -Fxq "$item=yes" "$ENV";then all_ready=no;fi
done
if ! grep -Fxq 'MNEBYVPN_OFFLINE_MTPROXY_ROUTES_JSON=[{"route":"direct","host":"89.125.90.101","port":9446}]' "$ENV";then
  all_ready=no
fi
if [[ "$all_ready" = yes ]];then
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" |
    grep -Fxq 'MNEBYVPN_OFFLINE_MTPROXY_ISSUE_ENABLED=yes'
  echo 'owner_telemt_direct_only=already_enabled'
  exit 0
fi
# Build a strictly scoped new env without exposing secrets. Validate all
# existing keys and reject unexpected values/duplicates rather than overwriting.
backup="$(mktemp "$BOT/.owner-telemt-direct-backup.XXXXXXXX")"
cp -p "$ENV" "$backup"
changed=no
temp=''
rollback(){
  status=$?
  trap - ERR EXIT
  if (( status!=0 ));then
    if [[ "$changed" = yes ]];then
      cp -p "$backup" "$ENV" || true
      bash "$PROMOTE" "$SHA" || echo 'owner_telemt_direct_rollback_promote_failed=true'
      echo 'owner_telemt_direct_env_restored=true'
    fi
  fi
  if [[ -n "$temp" ]];then rm -f "$temp";fi
  rm -f "$backup"
  exit "$status"
}
trap rollback ERR EXIT
temp="$(mktemp "$BOT/.owner-telemt-direct-next.XXXXXXXX")"
python3 - "$ENV" "$temp" <<'PY'
from pathlib import Path
import sys
src=Path(sys.argv[1]);dest=Path(sys.argv[2])
updates={
 'MNEBYVPN_OFFLINE_MTPROXY_ISSUE_ENABLED':'yes',
 'MNEBYVPN_OFFLINE_MTPROXY_ROUTES_VERIFIED':'yes',
 'MNEBYVPN_OFFLINE_MTPROXY_REVOKER_VERIFIED':'yes',
 'MNEBYVPN_OFFLINE_MTPROXY_ROUTES_JSON':'[{"route":"direct","host":"89.125.90.101","port":9446}]',
}
old=src.read_text()
seen=set()
out=[]
for line in old.splitlines():
  if '=' in line:
    k,v=line.split('=',1)
    if k in updates:
      if k in seen:raise SystemExit('duplicate private owner release key')
      seen.add(k)
      if k.endswith('_ROUTES_JSON') and v!=updates[k]:
        raise SystemExit('unexpected private route config; manual review required')
      if not k.endswith('_ROUTES_JSON') and v not in ('no','yes'):
        raise SystemExit('unexpected private flag; manual review required')
      line=k+'='+updates[k]
  out.append(line)
for k,v in updates.items():
  if k not in seen:out.append(k+'='+v)
dest.write_text('\n'.join(out)+'\n')
PY
chmod 600 "$temp"
mv -f "$temp" "$ENV"
temp=''
changed=yes
bash "$PROMOTE" "$SHA"
for flag in MNEBYVPN_OFFLINE_MTPROXY_ISSUE_ENABLED \
  MNEBYVPN_OFFLINE_MTPROXY_ROUTES_VERIFIED \
  MNEBYVPN_OFFLINE_MTPROXY_REVOKER_VERIFIED;do
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" | grep -Fxq "$flag=yes"
done
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$NAME" |
  grep -Fxq 'MNEBYVPN_OFFLINE_MTPROXY_ROUTES_JSON=[{"route":"direct","host":"89.125.90.101","port":9446}]'
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8793/readyz)" = 200
trap - ERR EXIT
rm -f "$backup"
echo 'owner_telemt_direct_only=enabled_private_sales'
echo 'owner_telemt_public_proxy_flags=untouched'
echo 'owner_telemt_customer_links=not_issued'
