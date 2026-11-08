#!/usr/bin/env bash
# Atomic rollback for owner-initiated experimental four-service MNEBYDNS canary.
# Never overwrites configurations modified by a different deployment.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-googlepilot-backups/[0-9]+$ ]] || exit 2
base="$1"
nginx=/etc/nginx/nginx.conf
dns=/opt/mnebydns-dot/Corefile
for file in nginx.before dns.before nginx.pilot dns.pilot rollback.sh; do
  test -s "$base/$file" || { echo "rollback_missing_owned_snapshot=$file"; exit 2; }
done
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 15 9 || { echo "rollback_shared_route_lock_unavailable=yes"; exit 2; }
for component in nginx dns; do
  case "$component" in nginx) live="$nginx";; dns) live="$dns";; esac
  if ! cmp -s "$base/$component.before" "$live" &&
     ! cmp -s "$base/$component.pilot" "$live"; then
    echo "rollback_refused_unrelated_config_change=$component"
    exit 3
  fi
done
systemctl stop mnebydns-googlepilot.service >/dev/null 2>&1 || true
systemctl disable mnebydns-googlepilot.service >/dev/null 2>&1 || true
# Restore exactly the two files modified by this canary.
if ! cmp -s "$base/nginx.before" "$nginx"; then
  cp -p "$base/nginx.before" "$nginx"
  nginx -t >/dev/null 2>&1 || {
    echo "rollback_original_nginx_config_invalid"; exit 4;
  }
  systemctl reload nginx
fi
if ! cmp -s "$base/dns.before" "$dns"; then
  cp -p "$base/dns.before" "$dns"
  systemctl restart mnebydns-dot.service
fi
systemctl is-active --quiet nginx
systemctl is-active --quiet mnebydns-dot.service
systemctl is-active --quiet xray.service
systemctl is-active --quiet mnebydns-gemini.service
if [[ -f /etc/systemd/system/mnebydns-googlepilot.service ]]; then
  cmp -s "$base/pilot.service" /etc/systemd/system/mnebydns-googlepilot.service || {
    echo "rollback_refused_unowned_pilot_unit"; exit 3;
  }
  rm -f /etc/systemd/system/mnebydns-googlepilot.service
fi
if [[ -d /etc/mnebydns-googlepilot ]]; then
  test "$(find /etc/mnebydns-googlepilot -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 1
  cmp -s "$base/proxy.pilot" /etc/mnebydns-googlepilot/nginx.conf
  rm -f /etc/mnebydns-googlepilot/nginx.conf
  rmdir /etc/mnebydns-googlepilot
fi
systemctl daemon-reload
test "$(ss -H -lnt 'sport = :15449' | wc -l)" -eq 0
echo "canary_rollback_completed=true"
echo "existing_Gemini_VPN_and_DoT_services_preserved=true"
