#!/usr/bin/env bash
# Deterministic owner-only rollback target for future unverified experiments.
# Does NOT restore the pre-Gemini 2026-11-08 baseline. Always restores the
# five owner-confirmed working service routes (Gemini Claude Grok X TikTok).
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
stable_root=/opt/mnebydns-stable-checkpoints
current="$stable_root/current"
test -s "$current" && test ! -L "$current"
base="$(cat "$current")"
[[ "$base" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 2
for name in nginx dns proxy; do test -s "$base/$name.stable"; done
(cd "$base" && sha256sum -c stable-manifest.sha256 >/dev/null)
nginx=/etc/nginx/nginx.conf
dns=/opt/mnebydns-dot/Corefile
proxy=/etc/mnebydns-googlepilot/nginx.conf
if [[ $# == 1 && "$1" == --check ]]; then
  for entry in nginx dns proxy; do
    case "$entry" in
      nginx) live="$nginx";; dns) live="$dns";; proxy) live="$proxy";;
    esac
    cmp -s "$base/$entry.stable" "$live" || {
      echo "stable_checkpoint_drift=$entry"; exit 4;
    }
  done
  echo "five_service_stable_checkpoint_and_manifest_valid=true"
  exit 0
fi
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 20 9 || exit 3
if [[ $# == 0 ]]; then
  # A no-argument call is permitted only as a repair of this exact stable
  # configuration, including restarting previously failed services.
  for entry in nginx dns proxy; do
    case "$entry" in
      nginx) live="$nginx";; dns) live="$dns";; proxy) live="$proxy";;
    esac
    cmp -s "$base/$entry.stable" "$live" || {
      echo "refusing_unowned_change=$entry"; exit 4;
    }
  done
elif [[ $# == 2 && "$1" == --expected &&
        "$2" =~ ^/opt/mnebydns-experiment-backups/[0-9]+$ ]]; then
  experiment="$2"
  for entry in nginx dns proxy; do
    case "$entry" in
      nginx) live="$nginx";; dns) live="$dns";; proxy) live="$proxy";;
    esac
    # Any file must match this approved experiment or the stable checkpoint.
    cmp -s "$base/$entry.stable" "$live" ||
    cmp -s "$experiment/$entry.pilot" "$live" || {
      echo "refusing_unowned_experiment_change=$entry"; exit 4;
    }
  done
else
  echo "usage: stable-restore.sh [--expected /opt/mnebydns-experiment-backups/RUN_ID]"
  exit 2
fi
nginx -t -c "$base/nginx.stable" >/dev/null
nginx -t -c "$base/proxy.stable" >/dev/null
install -d -m 755 /etc/mnebydns-googlepilot
install -m 644 "$base/proxy.stable" "$proxy"
systemctl reset-failed mnebydns-googlepilot.service || true
systemctl restart mnebydns-googlepilot.service
for _ in $(seq 1 40); do
  if systemctl is-active --quiet mnebydns-googlepilot.service &&
     ss -H -lnt 'sport = :15449' | grep -Fq '127.0.0.1:15449'; then break; fi
  sleep 0.2
done
systemctl is-active --quiet mnebydns-googlepilot.service
ss -H -lnt 'sport = :15449' | grep -Fq '127.0.0.1:15449'
install -m 600 "$base/nginx.stable" "$nginx.new-stable"
mv -f "$nginx.new-stable" "$nginx"
nginx -t >/dev/null
systemctl reload nginx
install -d -m 755 /opt/mnebydns-dot
install -m 644 "$base/dns.stable" "$dns.new-stable"
mv -f "$dns.new-stable" "$dns"
systemctl reset-failed mnebydns-dot.service || true
systemctl restart mnebydns-dot.service
for _ in $(seq 1 40); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then break; fi
  sleep 0.2
done
systemctl is-active --quiet mnebydns-dot.service
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
for entry in nginx dns proxy; do
  case "$entry" in
    nginx) live="$nginx";; dns) live="$dns";; proxy) live="$proxy";;
  esac
  cmp -s "$base/$entry.stable" "$live"
done
echo "MNEBYDNS_rollback_target_owner_confirmed_five_services=RESTORED"
echo "Meta_Threads_Telegram_experiments_NOT_reintroduced=true"
echo "stable_checkpoint=$base"
