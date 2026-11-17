#!/usr/bin/env bash
# Explicitly enable owner-only Smart DNS video link issuance AFTER the private
# 8858 gateway has passed its blue-green deployment. No DNS/firewall changes.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo OWNER_LINK_ENABLE_REQUIRES_ROOT=true;exit 2; }
[[ $# == 1 && "$1" == enable ]] || exit 2
sha=f811efe2a429f1f113719489cbb588fea371c7a3
root=/opt/mnebyvpn
envfile="$root/bot/web.env"
backup="$root/bot/web.env.before-owner-smartdns-video-20261117"
stage="$root/staging/active_sha"
bot=mnebyvpn-bot-info
newdns=mnebydns-personal-dot-private
oldbackup=mnebydns-personal-dot-private-previous-20261117
release_state=/etc/mnebydns/personal-dot/owner-video-release-20261117.json
promoter=/tmp/mnebyvpn-main-bot-promote-owner-video-20261117.sh
lock=/run/lock/mnebydns-owner-smartdns-video-issue.lock
exec 9>"$lock"
flock -w 60 9 || { echo OWNER_LINK_ENABLE_LOCK_BUSY=true;exit 2; }
test -s "$envfile" && test -s "$stage" && test -s "$promoter"
test "$(cat "$stage")" = "$sha"
test "$(docker inspect -f '{{.Config.Image}}' "$bot")" = "mnebyvpn-stage-web:$sha"
test "$(docker inspect -f '{{.State.Running}}' "$bot")" = true
test "$(docker inspect -f '{{.State.Running}}' "$newdns")" = true
test "$(docker inspect -f '{{.State.Running}}' "$oldbackup")" = true
grep -Fxq 'MNEBYVPN_ENV=production' "$envfile"
grep -Fxq 'BOT_PUBLIC_INFO_ONLY=no' "$envfile"
grep -Eq '^TELEGRAM_WEBHOOK_SECRET_SHA256=[a-f0-9]{64}$' "$envfile"
grep -Eq '^DATABASE_URL=postgresql://' "$envfile"
test "$(stat -c '%a' "$envfile")" = 600

# Verify staged release state and new selected private endpoint.
python3 - "$release_state" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
assert p.is_file()
s=json.loads(p.read_text())
assert s['source_sha']=='f811efe2a429f1f113719489cbb588fea371c7a3'
assert s['stage_completed'] and s['promoted']
print('PRIVATE_GATEWAY_PROMOTION_VERIFIED=true')
PY
new_ports="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$newdns" | sed -n 's/^MNEBYDNS_PERSONAL_DOT_PORT=//p')"
# Blue-green reused the old env (8856) and overrode it with 8858. Docker
# may retain both lines; accept ONLY these known values in this order.
[[ "$new_ports" == 8858 || "$new_ports" == 
test "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$oldbackup" | sed -n 's/^MNEBYDNS_PERSONAL_DOT_PORT=//p')" = 8856
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8859/readyz)" = 200
test "$(docker exec mnebyvpn-stage-postgres psql -X -U mnebyvpn_stage -d mnebyvpn_stage -At -c \
  "SELECT EXISTS(SELECT 1 FROM deployment_schema_migrations WHERE file_name='0130_owner_dns_video_routes.sql');")" = t
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8793/readyz)" = 200

# Fail closed on environment drift, duplicate feature keys and previous rollout.
test ! -e "$backup" || { echo OWNER_LINK_ENABLE_BACKUP_ALREADY_EXISTS=true;exit 2; }
if grep -q '^MNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED=' "$envfile";then
  echo OWNER_LINK_ENABLE_ENV_ALREADY_SET_REFUSE=true;exit 2
fi
cp -p "$envfile" "$backup"
chmod 600 "$backup"
tmp="$(mktemp "$root/bot/.owner-smartdns-video.XXXXXXXX")"
chmod 600 "$tmp"
enabled=0
rollback(){
  code=$?
  trap - ERR
  if [[ "$enabled" == 1 ]];then
    echo OWNER_SMARTDNS_ISSUANCE_CHECK_FAILED_RESTORING=true
    cp -p "$backup" "$envfile"
    chmod 600 "$envfile"
    # Promote known-good old env using unchanged immutable release. The
    # promoter itself performs canary and container restoration on failure.
    bash "$promoter" "$sha" || {
      echo OWNER_SMARTDNS_BOT_ROLLBACK_REQUIRED=true
      return "$code"
    }
    echo OWNER_SMARTDNS_ISSUANCE_ROLLED_BACK=true
  fi
  rm -f "$tmp"
  return "$code"
}
trap rollback ERR
cp "$envfile" "$tmp"
printf '\nMNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED=yes\n' >> "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$envfile"
enabled=1
bash "$promoter" "$sha"
test "$(docker inspect -f '{{.State.Running}}' "$bot")" = true
test "$(docker inspect -f '{{.Config.Image}}' "$bot")" = "mnebyvpn-stage-web:$sha"
test "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$bot" |
  grep -Fxc MNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED=yes)" = 1
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
  http://127.0.0.1:8793/readyz)" = 200
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST \
  -H 'Content-Type: application/json' -d '{"update_id":100}' \
  http://127.0.0.1:8793/webhooks/telegram)" = 401
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
  http://127.0.0.1:8859/readyz)" = 200
trap - ERR
echo OWNER_SMARTDNS_ISSUANCE_ENABLED=true
echo OWNER_TELEGRAM_CANARY_READY=200
echo OWNER_TELEGRAM_UNSIGNED_WEBHOOK=401
echo OWNER_PRIVATE_DOT_8858_STILL_READY=200
echo OWNER_PREVIOUS_BOT_ENV_BACKUP_MODE=0600
8856\n8858' ]] ||
  { echo OWNER_NEW_DOT_PORT_CONFIG_UNEXPECTED=true;exit 2; }
echo OWNER_NEW_DOT_EFFECTIVE_PORT_8858=VERIFIED
test "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$oldbackup" | sed -n 's/^MNEBYDNS_PERSONAL_DOT_PORT=//p')" = 8856
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8859/readyz)" = 200
test "$(docker exec mnebyvpn-stage-postgres psql -X -U mnebyvpn_stage -d mnebyvpn_stage -At -c \
  "SELECT EXISTS(SELECT 1 FROM deployment_schema_migrations WHERE file_name='0130_owner_dns_video_routes.sql');")" = t
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 4 http://127.0.0.1:8793/readyz)" = 200

# Fail closed on environment drift, duplicate feature keys and previous rollout.
test ! -e "$backup" || { echo OWNER_LINK_ENABLE_BACKUP_ALREADY_EXISTS=true;exit 2; }
if grep -q '^MNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED=' "$envfile";then
  echo OWNER_LINK_ENABLE_ENV_ALREADY_SET_REFUSE=true;exit 2
fi
cp -p "$envfile" "$backup"
chmod 600 "$backup"
tmp="$(mktemp "$root/bot/.owner-smartdns-video.XXXXXXXX")"
chmod 600 "$tmp"
enabled=0
rollback(){
  code=$?
  trap - ERR
  if [[ "$enabled" == 1 ]];then
    echo OWNER_SMARTDNS_ISSUANCE_CHECK_FAILED_RESTORING=true
    cp -p "$backup" "$envfile"
    chmod 600 "$envfile"
    # Promote known-good old env using unchanged immutable release. The
    # promoter itself performs canary and container restoration on failure.
    bash "$promoter" "$sha" || {
      echo OWNER_SMARTDNS_BOT_ROLLBACK_REQUIRED=true
      return "$code"
    }
    echo OWNER_SMARTDNS_ISSUANCE_ROLLED_BACK=true
  fi
  rm -f "$tmp"
  return "$code"
}
trap rollback ERR
cp "$envfile" "$tmp"
printf '\nMNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED=yes\n' >> "$tmp"
chmod 600 "$tmp"
mv -f "$tmp" "$envfile"
enabled=1
bash "$promoter" "$sha"
test "$(docker inspect -f '{{.State.Running}}' "$bot")" = true
test "$(docker inspect -f '{{.Config.Image}}' "$bot")" = "mnebyvpn-stage-web:$sha"
test "$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$bot" |
  grep -Fxc MNEBYDNS_OWNER_SMART_DNS_LINKS_ENABLED=yes)" = 1
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
  http://127.0.0.1:8793/readyz)" = 200
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST \
  -H 'Content-Type: application/json' -d '{"update_id":100}' \
  http://127.0.0.1:8793/webhooks/telegram)" = 401
test "$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
  http://127.0.0.1:8859/readyz)" = 200
trap - ERR
echo OWNER_SMARTDNS_ISSUANCE_ENABLED=true
echo OWNER_TELEGRAM_CANARY_READY=200
echo OWNER_TELEGRAM_UNSIGNED_WEBHOOK=401
echo OWNER_PRIVATE_DOT_8858_STILL_READY=200
echo OWNER_PREVIOUS_BOT_ENV_BACKUP_MODE=0600
