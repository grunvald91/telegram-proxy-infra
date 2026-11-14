#!/usr/bin/env bash
# Finalize previously verified guarded UDP-only YouTube relay. No DNS/TCP mutations.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 2 && ( "$1" == ru || "$1" == de ) && "$2" =~ ^[0-9]{9,13}$ ]] || exit 2
role="$1"; id="$2"
base="/opt/mnebydns-youtube-quic-$id"
unit="mnebydns-youtube-quic-$role-$id"
watch="$unit-rollback"
test -s "$base/relay.py" && test -s "$base/rollback.sh"
for n in "$unit.service" "$watch.service" "$watch.timer";do
  test -s "$base/$n" && cmp -s "$base/$n" "/etc/systemd/system/$n"
done
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 30 9
systemctl is-active --quiet "$unit.service"
systemctl is-active --quiet "$watch.timer"
port=19444
[[ "$role" == de ]] || port=443
ss -H -lun "sport = :$port" | grep -q .
systemctl enable "$unit.service" >/dev/null
systemctl is-enabled --quiet "$unit.service"
systemctl disable --now "$watch.timer" >/dev/null
! systemctl is-active --quiet "$watch.timer"
systemctl is-active --quiet "$unit.service"
echo "YOUTUBE_QUIC_${role}_PERMANENT_SERVICE_ENABLED=true"
echo "YOUTUBE_QUIC_${role}_AUTOROLLBACK_DISARMED=true"
echo "YOUTUBE_QUIC_${role}_TCP_DNS_UNMODIFIED=true"
