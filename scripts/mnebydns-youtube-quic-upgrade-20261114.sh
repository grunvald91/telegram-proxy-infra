#!/usr/bin/env bash
# Guarded in-place YouTube QUIC parser upgrade, only owned relay.py changed.
# Existing TCP/443, DNS and VPN remain unchanged. Timer-backed independent rollback.
set -Eeuo pipefail
((EUID==0)) || exit 2
phase="${1:?phase}"; role="${2:?role}"; id="${3:?id}"
[[ "$role" == ru || "$role" == de ]] || exit 2
[[ "$id" =~ ^[0-9]{9,13}$ ]] || exit 2
original=/opt/mnebydns-youtube-quic-43612369808/relay.py
service=mnebydns-youtube-quic-$role-43612369808.service
root=/opt/mnebydns-youtube-quic-upgrade-$role-$id
work=/tmp/mnebydns-youtube-quic-upgrade-$id
watch=mnebydns-youtube-quic-upgrade-$role-$id
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 30 9 || exit 3
case "$phase" in
  stage)
    [[ $# == 4 ]] || exit 2
    deadline="$4"
    [[ "$deadline" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}[[:space:]][0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]UTC$ ]] || exit 2
    target="$(date -u -d "$deadline" +%s)"
    now="$(date -u +%s)"
    ((target-now>=180 && target-now<=2400)) || exit 2
    test -s "$work/relay.py"
    test -s "$work/upgrade.sh"
    test -s "$original"
    systemctl is-active --quiet "$service"
    test ! -e "$root"
    test ! -e "/etc/systemd/system/$watch.service"
    test ! -e "/etc/systemd/system/$watch.timer"
    python3 -m py_compile "$work/relay.py"
    test ! -z "$(ss -H -lun "sport = :$([[ "$role" == ru ]] && echo 443 || echo 19444)")"
    if [[ "$role" == ru ]];then systemctl is-active --quiet nginx;else systemctl is-active --quiet mnebydns-dot.service;fi
    mkdir -m 700 "$root"
    install -m 600 "$original" "$root/before.py"
    install -m 600 "$work/relay.py" "$root/after.py"
    install -m 700 "$work/upgrade.sh" "$root/upgrade.sh"
    # Preserve exact previous and proposed files for drift-safe own-only rollback.
    cat > "/etc/systemd/system/$watch.service" <<UNIT
[Unit]
Description=MNEBYDNS YouTube QUIC version restore if parser pilot not committed
[Service]
Type=oneshot
ExecStart=/bin/bash $root/upgrade.sh rollback $role $id
UNIT
    cat > "/etc/systemd/system/$watch.timer" <<UNIT
[Unit]
Description=Rollback uncommitted QUIC parser upgrade for YouTube
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$watch.service
[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    systemctl enable --now "$watch.timer" >/dev/null
    systemctl is-active --quiet "$watch.timer"
    rollback_on_error() {
      rc=$?
      trap - EXIT
      flock -u 9
      bash "$root/upgrade.sh" rollback "$role" "$id" || true
      exit "$rc"
    }
    trap rollback_on_error EXIT
    install -m 644 "$root/after.py" "$original"
    systemctl restart "$service"
    systemctl is-active --quiet "$service"
    cmp -s "$root/after.py" "$original"
    systemctl is-active --quiet "$watch.timer"
    trap - EXIT
    echo "YOUTUBE_QUIC_UPGRADE_${role}=STAGED_WITH_ROLLBACK"
    echo "YOUTUBE_QUIC_UPGRADE_${role}_DEADLINE_UTC=$deadline"
    ;;
  rollback)
    [[ $# == 3 ]] || exit 2
    if [[ ! -d "$root" ]];then echo "YOUTUBE_QUIC_UPGRADE_${role}_ROLLBACK=NOT_STAGED";exit 0;fi
    test -s "$root/after.py" && test -s "$root/before.py"
    if cmp -s "$root/after.py" "$original";then
      install -m 644 "$root/before.py" "$original"
      systemctl restart "$service"
    elif ! cmp -s "$root/before.py" "$original";then
      echo "YOUTUBE_QUIC_UPGRADE_${role}_ROLLBACK=DRIFT_REFUSE";exit 3
    fi
    systemctl is-active --quiet "$service"
    systemctl disable --now "$watch.timer" >/dev/null 2>&1 || true
    rm -f -- "/etc/systemd/system/$watch.service" "/etc/systemd/system/$watch.timer"
    systemctl daemon-reload
    echo "YOUTUBE_QUIC_UPGRADE_${role}_ROLLBACK=RESTORED"
    ;;
  commit)
    [[ $# == 3 ]] || exit 2
    test -s "$root/after.py" && test -s "$root/before.py"
    cmp -s "$root/after.py" "$original"
    systemctl is-active --quiet "$service"
    systemctl is-active --quiet "$watch.timer"
    systemctl disable --now "$watch.timer" >/dev/null
    ! systemctl is-active --quiet "$watch.timer"
    # Keep before.py and upgrader script for deliberate manual rollback.
    echo "YOUTUBE_QUIC_UPGRADE_${role}_COMMIT=SUCCESS"
    ;;
  status)
    echo "YOUTUBE_QUIC_UPGRADE_${role}_SERVICE=$(systemctl is-active "$service" || true)"
    echo "YOUTUBE_QUIC_UPGRADE_${role}_TIMER=$(systemctl is-active "$watch.timer" || true)"
    ;;
  *)exit 2;;
esac
