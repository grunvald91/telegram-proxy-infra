#!/usr/bin/env bash
# One-off handoff from 121+46 Google+Claude+social to 174+97
# Google+Claude+Meta+TikTok+Telegram DNS-only pilot. Only uses the old pilot's own verified rollback, never overwrites
# unknown configurations. New pilot has its own persistent 30m watchdog.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/tmp/mnebydns-ci-[0-9]+$ ]] || exit 2
work="$1"
old=/opt/mnebydns-googlepilot-backups/42536213503
nginx=/etc/nginx/nginx.conf
dns=/opt/mnebydns-dot/Corefile
for f in nginx.before dns.before nginx.pilot dns.pilot rollback.sh; do
  test -s "$old/$f" || { echo "handoff_old_snapshot_missing=$f"; exit 2; }
done
if cmp -s "$old/nginx.pilot" "$nginx" &&
   cmp -s "$old/dns.pilot" "$dns"; then
  systemctl is-active --quiet mnebydns-googlepilot.service
  systemctl is-active --quiet mnebydns-four-google-watchdog-42536213503.timer
  echo "handoff_old_canary_state=ACTIVE_VERIFIED"
  bash "$old/rollback.sh" "$old"
elif cmp -s "$old/nginx.before" "$nginx" &&
     cmp -s "$old/dns.before" "$dns"; then
  echo "handoff_old_canary_state=ALREADY_ROLLED_BACK"
else
  echo "handoff_refused_unknown_production_configuration=true"
  exit 3
fi
for svc in nginx mnebydns-dot.service mnebydns-gemini.service xray.service; do
  systemctl is-active --quiet "$svc"
done
test ! -e /etc/systemd/system/mnebydns-googlepilot.service
test ! -e /etc/mnebydns-googlepilot
test -z "$(ss -H -lnt 'sport = :15449')"
cmp -s "$old/nginx.before" "$nginx"
cmp -s "$old/dns.before" "$dns"
echo "handoff_old_canary_transactionally_restored=true"
bash "$work/mnebydns-four-google-deploy.sh" "$work"
echo "handoff_new_meta_wireguard_dns_split_canary_active=true"
