#!/usr/bin/env bash
# Roll back only a registered temporary Meta CoreDNS overlay and private sidecar.
# This script is also run by an independent Persistent=true systemd timer.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-experiment-backups/[0-9]+$ ]] || exit 2
base="$1"
id="$(basename "$base")"
checkpoint_root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$checkpoint_root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
test -s "$checkpoint/stable-manifest.sha256"
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
live_dns=/opt/mnebydns-dot/Corefile
live_nginx=/etc/nginx/nginx.conf
live_proxy=/etc/mnebydns-googlepilot/nginx.conf
sidecar_dir=/etc/mnebydns-meta-pilot
service="mnebydns-meta-pilot-$id"
watch="mnebydns-meta-de-watchdog-$id"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 18 9 || { echo "DE_Meta_rollback_route_lock_failed=true"; exit 3; }
for kind in nginx proxy; do
  case "$kind" in
    nginx) path="$live_nginx";;
    proxy) path="$live_proxy";;
  esac
  cmp -s "$checkpoint/$kind.stable" "$path" || {
    printf 'DE_rollback_refuses_unowned_existing_%s_change=true\n' "$kind"
    exit 4
  }
done
test -s "$base/dns.pilot" && test -s "$base/proxy.meta"
if cmp -s "$checkpoint/dns.stable" "$live_dns"; then
  echo "DE_Meta_DNS_already_stable=true"
elif cmp -s "$base/dns.pilot" "$live_dns"; then
  echo "DE_Meta_DNS_pilot_verified=true"
else
  echo "DE_rollback_refuses_unowned_dns_change=true"
  exit 5
fi
for kind in service timer; do
  path="/etc/systemd/system/$watch.$kind"
  if test -e "$path"; then
    cmp -s "$base/$watch.$kind" "$path" || {
      printf 'DE_rollback_refuses_changed_watchdog_%s=true\n' "$kind"; exit 5;
    }
  fi
done
if test -e "/etc/systemd/system/$service.service"; then
  cmp -s "$base/$service.service" "/etc/systemd/system/$service.service" || {
    echo "DE_rollback_refuses_changed_sidecar_unit=true"; exit 5;
  }
fi
if test -e "$sidecar_dir/nginx.conf"; then
  cmp -s "$base/proxy.meta" "$sidecar_dir/nginx.conf" || {
    echo "DE_rollback_refuses_unowned_sidecar_config=true"; exit 5;
  }
fi
if cmp -s "$base/dns.pilot" "$live_dns"; then
  install -m 644 "$checkpoint/dns.stable" "$live_dns.new-five-stable-$id"
  mv -f "$live_dns.new-five-stable-$id" "$live_dns"
  systemctl reset-failed mnebydns-dot.service || true
  systemctl restart mnebydns-dot.service
fi
ready=no
for _ in $(seq 1 40); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then ready=yes; break; fi
  sleep .25
done
test "$ready" = yes
cmp -s "$checkpoint/dns.stable" "$live_dns"
for kind in nginx proxy; do
  if [[ "$kind" == nginx ]]; then path="$live_nginx"; else path="$live_proxy"; fi
  cmp -s "$checkpoint/$kind.stable" "$path"
done
systemctl stop "$service.service" >/dev/null 2>&1 || true
if systemctl is-active --quiet "$service.service"; then
  echo "DE_Meta_sidecar_stop_not_confirmed=true"; exit 6
fi
systemctl disable --now "$service.service" >/dev/null 2>&1 || true
systemctl disable --now "$watch.timer" >/dev/null 2>&1 || true
rm -f -- "/etc/systemd/system/$service.service" \
  "/etc/systemd/system/$watch.service" "/etc/systemd/system/$watch.timer"
if test -f "$sidecar_dir/nginx.conf"; then rm -f -- "$sidecar_dir/nginx.conf"; fi
if test -d "$sidecar_dir"; then rmdir -- "$sidecar_dir"; fi
systemctl daemon-reload
echo "DE_Meta_rollback_to_five_confirmed=true"
echo "DE_unrelated_VPN_Nginx_five_service_proxy_untouched=true"
echo "DE_Meta_private_sidecar_stopped_and_watchdog_disarmed=true"
