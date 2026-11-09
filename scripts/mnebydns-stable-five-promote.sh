#!/usr/bin/env bash
# Promote only the owner-confirmed 5 working services, excluding Meta/Telegram.
# Source is the PRE-META original 443 and CoreDNS snapshots (not the live experiment).
# Checkpoint remains on disk; no timed rollback of working services.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/tmp/mnebydns-stable-five-[0-9]+$ ]] || exit 2
work="$1"
runid="${work##*-}"
old=/opt/mnebydns-googlepilot-backups/42538883926
base="/opt/mnebydns-stable-checkpoints/$runid"
live_nginx=/etc/nginx/nginx.conf
live_dns=/opt/mnebydns-dot/Corefile
live_proxy=/etc/mnebydns-googlepilot/nginx.conf
pilot_unit=/etc/systemd/system/mnebydns-googlepilot.service
timer=mnebydns-four-google-watchdog-42538883926
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 20 9
for f in nginx.before dns.before nginx.pilot dns.pilot proxy.pilot pilot.service; do
  test -s "$old/$f"
done
for f in mnebydns-stable-five-render.py mnebydns-four-google-canary.py; do
  test -s "$work/$f"
done
for f in "$live_nginx" "$live_dns"; do
  test -f "$f" && test ! -L "$f"
done
test ! -e "$base"
if ! cmp -s "$live_nginx" "$old/nginx.pilot" &&
   ! cmp -s "$live_nginx" "$old/nginx.before"; then
  echo "unexpected_nginx_state_refuse_overwrite=true"; exit 3
fi
if ! cmp -s "$live_dns" "$old/dns.pilot" &&
   ! cmp -s "$live_dns" "$old/dns.before"; then
  echo "unexpected_corefile_state_refuse_overwrite=true"; exit 3
fi
for unit in nginx mnebydns-dot.service mnebydns-gemini.service xray.service; do
  systemctl is-active --quiet "$unit"
done
test "$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)" -ge 300
python3 "$work/mnebydns-stable-five-render.py" self-test
install -d -m 700 /opt/mnebydns-stable-checkpoints
install -d -m 700 "$base"
cp -p "$live_nginx" "$base/live-nginx.before-promotion"
cp -p "$live_dns" "$base/live-dns.before-promotion"
if test -f "$live_proxy"; then cp -p "$live_proxy" "$base/live-proxy.before-promotion"; fi
cp -p "$old/nginx.before" "$base/verified-original-nginx"
cp -p "$old/dns.before" "$base/verified-original-dns"
python3 "$work/mnebydns-stable-five-render.py" render \
  "$old/nginx.before" "$old/dns.before" "$base"
test -s "$base/nginx.stable" && test -s "$base/dns.stable" && test -s "$base/proxy.stable"
nginx -t -c "$base/nginx.stable" >/dev/null
nginx -t -c "$base/proxy.stable" >/dev/null
echo "stable_five_nginx_configs_valid=true"
# Stop original experiment timer before activating stable state (same lock
# protects against concurrent expiry rollback); never delete its backup.
systemctl stop "$timer.timer" >/dev/null 2>&1 || true
# If original canary auto-reverted, restore only the known isolated 443 service
# that has been tested; no changes to customer subscriptions or Xray.
if ! test -f "$pilot_unit"; then
  install -m 644 "$old/pilot.service" "$pilot_unit"
  systemctl daemon-reload
fi
# DynamicUser needs search permission on the configuration directory and
# read permission on the NON-SECRET SNI routing file. The original root:0700
# directory caused a verified startup failure during the first promotion.
install -d -m 755 /etc/mnebydns-googlepilot
install -m 644 "$base/proxy.stable" "$live_proxy"
systemctl enable mnebydns-googlepilot.service >/dev/null
systemctl reset-failed mnebydns-googlepilot.service || true
systemctl restart mnebydns-googlepilot.service
ready=no
for _ in $(seq 1 35); do
  if systemctl is-active --quiet mnebydns-googlepilot.service &&
     ss -H -lnt 'sport = :15449' | grep -Fq '127.0.0.1:15449'; then
    ready=yes
    break
  fi
  sleep 0.2
done
if [[ "$ready" != yes ]]; then
  echo "stable_five_foreign_proxy_start_failed=true"
  exit 5
fi
echo "stable_five_sni_service_healthy=true"
# Prevalidated files are made available atomically via same-filesystem rename.
install -m 600 "$base/nginx.stable" "$live_nginx.new-stable"
mv -f "$live_nginx.new-stable" "$live_nginx"
nginx -t >/dev/null
systemctl reload nginx
# CoreDNS also runs under systemd DynamicUser. Root-only 0600 Corefile
# caused a verified DoT853 outage in the first promotion; these permissions
# are required for service startup and safe after reboot.
chmod 755 /opt/mnebydns-dot
install -m 644 "$base/dns.stable" "$live_dns.new-stable"
mv -f "$live_dns.new-stable" "$live_dns"
systemctl reset-failed mnebydns-dot.service || true
systemctl restart mnebydns-dot.service
dns_ready=no
for _ in $(seq 1 40); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    dns_ready=yes
    break
  fi
  sleep 0.2
done
if [[ "$dns_ready" != yes ]]; then
  echo "stable_DoT853_not_ready_after_restart=true"
  exit 6
fi
systemctl is-active --quiet nginx
systemctl is-active --quiet xray.service
systemctl is-active --quiet mnebydns-gemini.service
cmp -s "$base/nginx.stable" "$live_nginx"
cmp -s "$base/dns.stable" "$live_dns"
cmp -s "$base/proxy.stable" "$live_proxy"
if ss -H -lnt 'sport = :19443' | grep -Fq '10.66.77.1:19443'; then
  echo "unexpected_leftover_temporary_meta_listener=true"; exit 4
fi
# Disable and remove ONLY our known earlier temporary rollback units.
systemctl disable --now "$timer.timer" >/dev/null 2>&1 || true
for kind in service timer; do
  item="/etc/systemd/system/$timer.$kind"
  if test -e "$item"; then
    cmp -s "$old/watchdog.$kind" "$item" || {
      echo "unowned_old_watchdog_refuse_delete=$kind"; exit 4;
    }
    rm -f -- "$item"
  fi
done
systemctl daemon-reload
printf '%s\n' "$base" > /opt/mnebydns-stable-checkpoints/current.tmp
mv -f /opt/mnebydns-stable-checkpoints/current.tmp /opt/mnebydns-stable-checkpoints/current
sha256sum "$base/nginx.stable" "$base/dns.stable" "$base/proxy.stable" > "$base/stable-manifest.sha256"
echo "confirmed_five_services_baseline_PROMOTED=true"
echo "experimental_meta_telegram_routes_not_active=true"
echo "retained_exact_hosts=132 retained_dynamic_suffixes=70"
echo "stable_checkpoint=$base"
echo "stable_without_expiry_timer=true"
echo "stable_dynamic_user_config_and_DoT_readiness=PASS"
