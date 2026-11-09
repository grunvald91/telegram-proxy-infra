#!/usr/bin/env bash
# Bounded ChatGPT + Meta canary rollback. Restore only files we own:
# exact stable-five checkpoint OR exact staged pilot; fail closed otherwise.
# Persistent watchdog runs independently from GitHub Actions runner.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-combined-backups/[0-9]+$ ]] || exit 2
base="$1"; id="$(basename "$base")"
root=/opt/mnebydns-stable-checkpoints
checkpoint="$(cat "$root/current")"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
test -s "$checkpoint/stable-manifest.sha256"
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
test -s "$base/combined-manifest.sha256"
(cd "$base" && sha256sum -c combined-manifest.sha256 >/dev/null)
service="mnebydns-combined-meta-$id"
watch="mnebydns-combined-de-watchdog-$id"
sidecar=/etc/mnebydns-meta-pilot/nginx.conf
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 18 9 || { echo "combined_DE_rollback_lock_unavailable=true"; exit 3; }
# Refuse to touch files that have changed since our pilot was installed.
for kind in nginx dns proxy; do
  case "$kind" in
    nginx) live=/etc/nginx/nginx.conf ;;
    dns) live=/opt/mnebydns-dot/Corefile ;;
    proxy) live=/etc/mnebydns-googlepilot/nginx.conf ;;
  esac
  if cmp -s "$checkpoint/$kind.stable" "$live"; then
    echo "combined_DE_already_stable_$kind=true"
  elif cmp -s "$base/$kind.pilot" "$live"; then
    echo "combined_DE_pilot_owned_$kind=true"
  else
    echo "combined_DE_refuses_unowned_change_$kind=true"
    exit 4
  fi
done
for kind in service timer; do
  file="/etc/systemd/system/$watch.$kind"
  if test -e "$file"; then
    cmp -s "$base/$watch.$kind" "$file" || {
      echo "combined_DE_refuses_unowned_watchdog_$kind=true"; exit 4;
    }
  fi
done
file="/etc/systemd/system/$service.service"
if test -e "$file"; then
  cmp -s "$base/$service.service" "$file" || {
    echo "combined_DE_refuses_unowned_sidecar_unit=true"; exit 4;
  }
fi
if test -e "$sidecar"; then
  cmp -s "$base/proxy.meta" "$sidecar" || {
    echo "combined_DE_refuses_unowned_sidecar_config=true"; exit 4;
  }
fi
# Roll back DNS immediately, before deleting German/Russian route.
if cmp -s "$base/dns.pilot" /opt/mnebydns-dot/Corefile; then
  install -m 644 "$checkpoint/dns.stable" "/opt/mnebydns-dot/Corefile.return-$id"
  mv -f "/opt/mnebydns-dot/Corefile.return-$id" /opt/mnebydns-dot/Corefile
  systemctl restart mnebydns-dot.service
fi
for _ in $(seq 1 45); do
  if systemctl is-active --quiet mnebydns-dot.service &&
    ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then break; fi
  sleep .25
done
systemctl is-active --quiet mnebydns-dot.service
cmp -s "$checkpoint/dns.stable" /opt/mnebydns-dot/Corefile
# Restore existing public shared Nginx and German backend.
if cmp -s "$base/nginx.pilot" /etc/nginx/nginx.conf; then
  install -m 644 "$checkpoint/nginx.stable" "/etc/nginx/nginx.conf.return-$id"
  mv -f "/etc/nginx/nginx.conf.return-$id" /etc/nginx/nginx.conf
  nginx -t >/dev/null
  systemctl reload nginx
fi
if cmp -s "$base/proxy.pilot" /etc/mnebydns-googlepilot/nginx.conf; then
  install -m 644 "$checkpoint/proxy.stable" "/etc/mnebydns-googlepilot/nginx.conf.return-$id"
  mv -f "/etc/mnebydns-googlepilot/nginx.conf.return-$id" /etc/mnebydns-googlepilot/nginx.conf
  systemctl restart mnebydns-googlepilot.service
fi
for kind in nginx dns proxy; do
  case "$kind" in
    nginx) live=/etc/nginx/nginx.conf ;;
    dns) live=/opt/mnebydns-dot/Corefile ;;
    proxy) live=/etc/mnebydns-googlepilot/nginx.conf ;;
  esac
  cmp -s "$checkpoint/$kind.stable" "$live"
done
for unit in nginx mnebydns-dot.service mnebydns-googlepilot.service mnebydns-gemini.service xray.service; do
  systemctl is-active --quiet "$unit"
done
systemctl stop "$service.service" >/dev/null 2>&1 || true
if systemctl is-active --quiet "$service.service"; then
  echo "combined_DE_meta_sidecar_stop_failed=true"; exit 5
fi
systemctl disable "$service.service" >/dev/null 2>&1 || true
systemctl disable --now "$watch.timer" >/dev/null 2>&1 || true
for file in "/etc/systemd/system/$service.service" \
            "/etc/systemd/system/$watch.service" "/etc/systemd/system/$watch.timer"; do
  if test -f "$file"; then rm -f -- "$file"; fi
done
if test -f "$sidecar"; then rm -f -- "$sidecar"; fi
if test -d /etc/mnebydns-meta-pilot; then
  rmdir /etc/mnebydns-meta-pilot
fi
systemctl daemon-reload
echo "combined_DE_stable_five_restored_and_verified=true"
echo "combined_DE_sidecar_and_watchdog_removed=true"
