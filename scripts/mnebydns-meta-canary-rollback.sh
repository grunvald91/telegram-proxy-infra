#!/usr/bin/env bash
# Revert only the temporary Meta DNS overlay and dedicated private SNI sidecar.
# Never restore pre-Gemini snapshots or modify stable nginx/Xray/VPN.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-experiment-backups/[0-9]+$ ]] || exit 2
base="$1"
runid="$(basename "$base")"
root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
meta=/etc/mnebydns-meta-private/nginx.conf
service="mnebydns-meta-pilot-$runid"
watchdog="mnebydns-meta-revert-$runid"
for file in dns.before dns.pilot proxy.meta; do test -s "$base/$file"; done
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 20 9 || exit 3
cmp -s "$checkpoint/nginx.stable" "$nginx" || { echo meta_rollback_refuses_changed_stable_nginx=true; exit 4; }
cmp -s "$checkpoint/proxy.stable" "$proxy" || { echo meta_rollback_refuses_changed_stable_proxy=true; exit 4; }
cmp -s "$checkpoint/dns.stable" "$base/dns.before" || { echo meta_rollback_bad_baseline=true; exit 4; }
for kind in service timer; do
  item="/etc/systemd/system/$watchdog.$kind"
  if test -e "$item"; then
    cmp -s "$base/watchdog.$kind" "$item" || { echo meta_rollback_refuses_changed_timer=true; exit 4; }
  fi
done
if test -e "/etc/systemd/system/$service.service"; then
  cmp -s "$base/pilot.service" "/etc/systemd/system/$service.service" || {
    echo meta_rollback_refuses_changed_service=true; exit 4;
  }
fi
if cmp -s "$checkpoint/dns.stable" "$dns"; then
  echo meta_DNS_already_at_stable_checkpoint=true
elif cmp -s "$base/dns.pilot" "$dns"; then
  install -m 644 "$checkpoint/dns.stable" "$dns.recover-$runid"
  mv -f "$dns.recover-$runid" "$dns"
  systemctl reset-failed mnebydns-dot.service || true
  systemctl restart mnebydns-dot.service
  for i in $(seq 1 40); do
    if systemctl is-active --quiet mnebydns-dot.service &&
       ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then break; fi
    sleep .2
  done
  systemctl is-active --quiet mnebydns-dot.service
  ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
  echo meta_DNS_restored_to_five_services=true
else
  echo meta_rollback_refuses_unowned_DNS=true
  exit 4
fi
test ! -e "$meta" || cmp -s "$base/proxy.meta" "$meta" || {
  echo meta_rollback_refuses_unowned_sidecar=true
  exit 4
}
systemctl stop "$service.service" >/dev/null 2>&1 || true
if systemctl is-active --quiet "$service.service"; then
  echo meta_rollback_sidecar_still_running=true
  exit 5
fi
if test -e "$meta"; then
  rm -f -- "$meta"
  rmdir /etc/mnebydns-meta-private 2>/dev/null || true
fi
systemctl disable --now "$watchdog.timer" >/dev/null 2>&1 || true
for kind in service timer; do
  item="/etc/systemd/system/$watchdog.$kind"
  if test -e "$item"; then rm -f -- "$item"; fi
done
if test -e "/etc/systemd/system/$service.service"; then
  rm -f -- "/etc/systemd/system/$service.service"
fi
systemctl daemon-reload
cmp -s "$checkpoint/dns.stable" "$dns"
cmp -s "$checkpoint/nginx.stable" "$nginx"
cmp -s "$checkpoint/proxy.stable" "$proxy"
echo meta_canary_reverted_to_verified_five_service_checkpoint=true
echo meta_private_sidecar_stopped=true
echo working_VPN_and_existing_routes_unchanged=true
