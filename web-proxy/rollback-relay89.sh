#!/usr/bin/env bash
set -euo pipefail

CDN_SITE_LINK=/etc/nginx/sites-enabled/cdn-servgo
CDN_SITE="$(readlink -f "$CDN_SITE_LINK")"
BACKUP_DIR="$(find /root/proxy-backups -maxdepth 1 -type d -name 'webproxy-*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n1 | cut -d' ' -f2-)"

if [[ -z "$BACKUP_DIR" || ! -f "$BACKUP_DIR/cdn-servgo.before" ]]; then
  echo "No WEB proxy nginx backup found" >&2
  exit 1
fi

echo "Restoring nginx from $BACKUP_DIR"
cp -a "$BACKUP_DIR/cdn-servgo.before" "$CDN_SITE"
rm -f /etc/nginx/conf.d/tproxy-web-map.conf
rm -f /etc/nginx/conf.d/tproxy-web-public-mirror.conf

nginx -t
systemctl reload nginx
systemctl is-active --quiet nginx

systemctl disable --now refresh-mtproxy-config.timer 2>/dev/null || true
systemctl disable --now tproxy-server.service 2>/dev/null || true
systemctl disable --now mtproxy.service 2>/dev/null || true
systemctl disable --now tproxy-firewall.service 2>/dev/null || true

curl --fail --silent --show-error --location --max-time 15 --output /dev/null https://cdn.servgo.ru/
echo "rollback_success=yes"
