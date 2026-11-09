#!/usr/bin/env bash
# Own-only UDP Meta QUIC rollback. Does not modify DNS, Nginx, Xray or firewall.
set -Eeuo pipefail
(( EUID==0 )) || exit 2
[[ $# == 2 && ( "$1" == ru || "$1" == de ) && "$2" =~ ^[0-9]{9,13}$ ]] || exit 2
role="$1"; id="$2"
base="/opt/mnebydns-meta-quic-$id"
unit="mnebydns-meta-quic-$role-$id"
watch="$unit-rollback"
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 30 9 || { echo "meta_quic_rollback_lock_error=true"; exit 2; }
if [[ ! -d "$base" ]]; then
  echo "meta_quic_${role}_rollback_already_absent=true"; exit 0
fi
for f in "/etc/systemd/system/$unit.service" \
         "/etc/systemd/system/$watch.service" \
         "/etc/systemd/system/$watch.timer"; do
  if [[ -e "$f" ]]; then
    cmp -s "$base/$(basename "$f")" "$f" || {
      echo "meta_quic_${role}_rollback_unit_drift_detected=true"; exit 3;
    }
  fi
done
systemctl stop "$unit.service" >/dev/null 2>&1 || true
if systemctl is-active --quiet "$unit.service"; then
  echo "meta_quic_${role}_rollback_stop_failed=true"; exit 3
fi
systemctl disable --now "$watch.timer" >/dev/null 2>&1 || true
rm -f -- "/etc/systemd/system/$unit.service" \
  "/etc/systemd/system/$watch.service" "/etc/systemd/system/$watch.timer"
systemctl daemon-reload
echo "meta_quic_${role}_rollback_complete=true"
echo "meta_quic_${role}_stable_tcp_dns_nginx_untouched=true"