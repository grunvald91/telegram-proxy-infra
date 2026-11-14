#!/usr/bin/env bash
# Independent crash-safe watchdog for the one-time CoreDNS resilience upgrade.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-resilience/[0-9]{9,13}$ ]] || exit 2
base="$1"
dns=/opt/mnebydns-dot/Corefile
pointer=/opt/mnebydns-stable-checkpoints/current
test -s "$base/dns.before"
test -s "$base/dns.candidate"
test -s "$base/checkpoint.before"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 50 9 || exit 3
original="$(cat "$base/checkpoint.before")"
[[ "$original" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
current="$(cat "$pointer")"
# After a verified promotion, never revert the current owner checkpoint.
if [[ "$current" != "$original" ]]; then
  echo 'resilience_rollback_checkpoint_already_promoted_noop=true'
  exit 0
fi
(cd "$original" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$original/dns.stable" "$base/dns.before"
if cmp -s "$dns" "$base/dns.before"; then
  echo 'resilience_rollback_original_already_active=true'
  exit 0
fi
# Only a byte-identical candidate may be rolled back. Preserve unrelated edits.
cmp -s "$dns" "$base/dns.candidate" || {
  echo 'resilience_rollback_refused_unrecognized_live_config=true'
  exit 4
}
cp -p "$base/dns.before" "$dns.resilience-restore-$(basename "$base")"
mv -f "$dns.resilience-restore-$(basename "$base")" "$dns"
systemctl restart mnebydns-dot.service
for attempt in $(seq 1 45); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    cmp -s "$base/dns.before" "$dns"
    echo 'resilience_rollback_original_restored=true'
    exit 0
  fi
  sleep .2
done
echo 'resilience_rollback_dot_unavailable=true'
exit 5
