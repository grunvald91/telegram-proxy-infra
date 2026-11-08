#!/usr/bin/env bash
# Certbot deploy hook: restart only the MNEBYDNS DoT service for its own lineage.
set -Eeuo pipefail
[[ "$""{RENEWED_LINEAGE:-}" == /etc/letsencrypt/live/dns.mnebyvpn.site ]] || exit 0
if ! systemctl is-active --quiet mnebydns-dot.service; then
  echo "mnebydns_not_running: no restart needed"
  exit 0
fi
systemctl restart mnebydns-dot.service
systemctl is-active --quiet mnebydns-dot.service
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
echo "mnebydns_dot_cert_reloaded=yes"
