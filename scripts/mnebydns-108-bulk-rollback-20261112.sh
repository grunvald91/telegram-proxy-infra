#!/usr/bin/env bash
# Bulk-only wrapper for the established independent rollback.
# If CoreDNS died during an invalid pilot reload, the original rollback
# restores the old Corefile but its reload helper intentionally refuses to
# restart an inactive service. Recover ONLY that exact old-file state.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 && "$1" =~ ^/opt/mnebydns-owner-domain/[1-9][0-9]{8,12}$ ]] || exit 2
base="$1"
test -s "$base/rollback-original.sh"
test -s "$base/dns.before"
test -s "$base/nginx.before"
if bash "$base/rollback-original.sh" "$base"; then
  exit 0
fi
test ! -f "$base/confirmed" || { echo 'BULK_ROLLBACK_CONFIRMED_NOT_RECOVERABLE=true' >&2; exit 4; }
live_dns=/opt/mnebydns-dot/Corefile
live_nginx=/etc/nginx/nginx.conf
checkpoint="$(cat /opt/mnebydns-stable-checkpoints/current)"
[[ "$checkpoint" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 4
(cd "$checkpoint" && sha256sum -c stable-manifest.sha256 >/dev/null)
# Reject any concurrent change, any unrecognized file, or a promoted checkpoint.
cmp -s "$checkpoint/dns.stable" "$base/dns.before"
cmp -s "$checkpoint/nginx.stable" "$base/nginx.before"
cmp -s "$checkpoint/dns.stable" "$live_dns"
cmp -s "$checkpoint/nginx.stable" "$live_nginx"
cmp -s "$checkpoint/proxy.stable" /etc/mnebydns-googlepilot/nginx.conf
nginx -t >/dev/null 2>&1
systemctl is-active --quiet nginx
# Only an unhealthy/missing DoT listener justifies a single recovery restart.
if ! systemctl is-active --quiet mnebydns-dot.service ||
   ! ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
  echo 'MASS_BULK_RECOVERING_INACTIVE_DOT_WITH_VERIFIED_OLD_COREFILE=true'
  systemctl restart mnebydns-dot.service
fi
systemctl is-active --quiet mnebydns-dot.service
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
# The original rollback owns timer disarm and confirms both old config files.
bash "$base/rollback-original.sh" "$base"
echo 'MASS_BULK_DEAD_DOT_RECOVERY_VERIFIED=true'
