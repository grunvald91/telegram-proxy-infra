#!/usr/bin/env bash
# Certbot deploy hook: restart only the MNEBYDNS DoT service for its own lineage.
set -Eeuo pipefail
[[ "${RENEWED_LINEAGE:-}" == /etc/letsencrypt/live/dns.mnebyvpn.site ]] || exit 0
if ! systemctl is-active --quiet mnebydns-dot.service; then
  echo "mnebydns_not_running: no restart needed"
  exit 0
fi
systemctl restart mnebydns-dot.service
systemctl is-active --quiet mnebydns-dot.service
for attempt in {1..30}; do
  if ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    echo "mnebydns_dot_cert_reloaded=yes"
    exit 0
  fi
  sleep 0.2
done
echo "mnebydns_dot_listener_missing_after_reload" >&2
exit 1
