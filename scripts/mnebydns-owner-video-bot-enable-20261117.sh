#!/usr/bin/env bash
# Enable owner-only Smart DNS issuance AFTER successful public DoT video canary.
# Preserve the previous bot environment and use existing canary/rollback.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 && $# == 1 ]] || exit 2
phase="$1"
source_sha=f811efe2a429f1f113719489cbb588fea371c7a3
root=/opt/mnebyvpn
envfile="$root/bot/web.env"
backup="$root/bot/web.env.before-owner-video-20261117"
promoter=/tmp/mnebyvpn-main-bot-promote-owner-video-20261117.sh
lock=/run/lock/mnebydns-owner-video-bot-activate.lock
exec 9>"$lock"
flock -w 90 9 || exit 2
test -s "$envfile"
test -s "$promoter"
bash -n "$promoter"
test "$(cat "$root/staging/active_sha")" = "$source_sha"
test "$(docker inspect -f '{{.State.Running}}' mnebydns-personal-dot-private)" = true
test "$(docker inspect -f '{{.State.Running}}' mnebydns-personal-dot-private-previous-20261117)" = true
test "$(docker inspect -f '{{.Config.Image}}' mnebyvpn-bot-info)" = "mnebyvpn-stage-web:$source_sha"
docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebydns-personal-dot-private |
  grep -Fxq MNEBYDNS_PERSONAL_DOT_PORT=8858
test -f /etc/mnebydns/personal-dot/owner-video-release-20261117.json
docker exec mnebyvpn-stage-postgres psql -X -qAt -v ON_ERROR_STOP=1 \
  -U mnebyvpn_stage -d mnebyvpn_stage \
  -c "SELECT EXISTS(SELECT 1 FROM deployment_schema_migrations WHERE file_name='0130_owner_dns_video_routes.sql');" |
  grep -Fxq t
# Never echo private file content, tokens or Telegram URLs.
set_flag() {
  python3 - "$envfile" "$1" <<'PY'
import os,pathlib,sys
p=pathlib.Path(sys.argv[1]); mode=sys.argv[2]
assert mode in ('yes','no')
content=p.read_text()
lines=content.splitlines()
prefix='MNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED='
found=[n for n,line in enumerate(lines) if line.startswith(prefix)]
assert len(found)<=1,'duplicate feature flag'
if found: lines[found[0]]=prefix+mode
else: lines.append(prefix+mode)
tmp=p.with_suffix('.owner-video-next')
stat=p.stat()
with open(tmp,'w') as f:
    f.write('\n'.join(lines)+'\n')
os.chmod(tmp,stat.st_mode & 0o777)
os.chown(tmp,stat.st_uid,stat.st_gid)
os.replace(tmp,p)
PY
}
verify_bot() {
  test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8793/readyz)" = 200
  test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
    -X POST -H 'Content-Type: application/json' -d '{"update_id":100}' \
    http://127.0.0.1:8793/webhooks/telegram)" = 401
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-bot-info |
    grep -Fxq "MNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED=$1"
}
rollback_on_error() {
  code=$?
  trap - ERR
  if (( code != 0 )) && [[ -f "$backup" ]]; then
    cp -p "$backup" "$envfile"
    # If the new container had been promoted, restore the previous flag
    # using the same owned canary/rollback, never a raw docker restart.
    if docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' mnebyvpn-bot-info |
      grep -Fxq 'MNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED=yes';then
      bash "$promoter" "$source_sha" || true
    fi
    echo 'OWNER_SMART_DNS_BOT_ENV_ROLLBACK_ATTEMPTED=true'
  fi
  exit "$code"
}
case "$phase" in
  enable)
    test ! -e "$backup" || { echo 'OWNER_SMART_DNS_BACKUP_ALREADY_EXISTS=true'; exit 2; }
    cp -p "$envfile" "$backup"
    chmod 600 "$backup"
    trap rollback_on_error ERR
    set_flag yes
    bash "$promoter" "$source_sha"
    verify_bot yes
    trap - ERR
    echo 'OWNER_SMART_DNS_LINK_ISSUANCE=ENABLED'
    echo 'OWNER_VPN_LEGACY_LINKS_UNCHANGED=true'
    ;;
  disable)
    test -f "$backup" || exit 2
    cp -p "$backup" "$envfile"
    bash "$promoter" "$source_sha"
    verify_bot no
    echo 'OWNER_SMART_DNS_LINK_ISSUANCE=DISABLED'
    ;;
  status)
    verify_bot yes
    echo 'OWNER_SMART_DNS_LINK_ISSUANCE=ENABLED_VERIFIED'
    ;;
  *) exit 2;;
esac
