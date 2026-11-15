#!/usr/bin/env bash
# Guarded, independently reversible DE89 public UDP/443 ingress.
# Existing RU UDP443, DE WG UDP19444, CoreDNS, Nginx, VPN and DB untouched.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 1 ]] || exit 2
phase="$1"
BASE=/opt/mnebydns-de89-public-quic-20261115
WRAPPER="$BASE/public.py"
MANAGER="$BASE/manage.sh"
UNIT=mnebydns-de89-public-quic-20261115.service
TIMER=mnebydns-de89-public-quic-revert-20261115.timer
REVERT=mnebydns-de89-public-quic-revert-20261115.service
REMOTE_WRAPPER=/tmp/mnebydns-de89-public-quic-20261115.py
REMOTE_MANAGER=/tmp/mnebydns-de89-public-quic-guard-20261115.sh
PREVIOUS=mnebydns-youtube-quic-de-43612369808.service
SOURCE=/opt/mnebydns-youtube-quic-43612369808/relay.py
SOURCE_SHA=bde13ba42945a6489c7fdc235996ff9858961bde27e2881759dc24112122d46f
UNITFILE=/etc/systemd/system/$UNIT
TIMERFILE=/etc/systemd/system/$TIMER
REVERTFILE=/etc/systemd/system/$REVERT
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 30 9

approved_live_baseline() {
  grep -Fq '89.125.90.101/' <(ip -4 -o addr show)
  systemctl is-active --quiet nginx.service
  systemctl is-active --quiet mnebydns-dot.service
  systemctl is-active --quiet mnebydns-googlepilot.service
  systemctl is-active --quiet "$PREVIOUS"
  nginx -t >/dev/null 2>&1
  ss -H -lun 'sport = :19444' | grep -q .
  test -s "$SOURCE"
  test "$(sha256sum "$SOURCE" | cut -d ' ' -f1)" = "$SOURCE_SHA"
}
check_stage() {
  test -s "$WRAPPER" && test -s "$MANAGER" && test -s "$BASE/$UNIT"
  test ! -L "$WRAPPER" && test ! -L "$MANAGER"
  cmp -s "$WRAPPER" "$REMOTE_WRAPPER"
  cmp -s "$MANAGER" "$REMOTE_MANAGER"
  python3 -B "$WRAPPER" --self-test
}
check_public_listener() {
  systemctl is-active --quiet "$UNIT"
  ss -H -lun 'sport = :443' | grep -Fq '89.125.90.101:443'
  systemctl is-active --quiet "$PREVIOUS"
  ss -H -lun 'sport = :19444' | grep -q .
  nginx -t >/dev/null 2>&1
  systemctl is-active --quiet mnebydns-dot.service
}
rollback() {
  # Do not remove unknown operator-owned systemd files.
  if [[ -f "$UNITFILE" ]];then cmp -s "$BASE/$UNIT" "$UNITFILE" || exit 3;fi
  if [[ -f "$TIMERFILE" ]];then test -f "$BASE/$TIMER";cmp -s "$BASE/$TIMER" "$TIMERFILE" || exit 3;fi
  if [[ -f "$REVERTFILE" ]];then test -f "$BASE/$REVERT";cmp -s "$BASE/$REVERT" "$REVERTFILE" || exit 3;fi
  systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
  systemctl disable --now "$TIMER" >/dev/null 2>&1 || true
  test ! -e "$UNITFILE" || rm -f -- "$UNITFILE"
  test ! -e "$TIMERFILE" || rm -f -- "$TIMERFILE"
  test ! -e "$REVERTFILE" || rm -f -- "$REVERTFILE"
  systemctl daemon-reload
  ! ss -H -lun 'sport = :443' | grep -Fq '89.125.90.101:443'
  approved_live_baseline
  echo DE89_PUBLIC_QUIC_ROLLBACK_OWN_PORT_ONLY=PASS
}

case "$phase" in
stage)
  approved_live_baseline
  test -s "$REMOTE_WRAPPER" && test -s "$REMOTE_MANAGER"
  test ! -e "$BASE" && test ! -e "$UNITFILE" && test ! -e "$TIMERFILE" && test ! -e "$REVERTFILE"
  ! ss -H -lun 'sport = :443' | grep -q .
  python3 -m py_compile "$REMOTE_WRAPPER"
  mkdir -m 755 "$BASE"
  install -m 644 "$REMOTE_WRAPPER" "$WRAPPER"
  install -m 700 "$REMOTE_MANAGER" "$MANAGER"
  cat > "$BASE/$UNIT" <<UNITTEXT
[Unit]
Description=MNEBYDNS DE89 public allowlisted QUIC UDP443 (original private relay untouched)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 -B $WRAPPER
DynamicUser=yes
NoNewPrivileges=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=yes
PrivateDevices=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_UNIX
MemoryMax=128M
CPUQuota=35%
TasksMax=32
LimitNOFILE=1024
Restart=on-failure
RestartSec=2s
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
UNITTEXT
  chmod 644 "$BASE/$UNIT"
  check_stage
  echo DE89_PUBLIC_QUIC_STAGED_NO_UDP443_CHANGE=PASS
  ;;
apply)
  approved_live_baseline
  check_stage
  test ! -e "$UNITFILE" && test ! -e "$TIMERFILE" && test ! -e "$REVERTFILE"
  ! ss -H -lun 'sport = :443' | grep -q .
  date_limit="$(date -u -d '+15 minutes' +'%Y-%m-%d %H:%M:%S UTC')"
  cat > "$BASE/$REVERT" <<TIMER_SERVICE
[Unit]
Description=Automatically undo unconfirmed DE89 public QUIC listener
[Service]
Type=oneshot
ExecStart=/bin/bash $MANAGER rollback
TIMER_SERVICE
  cat > "$BASE/$TIMER" <<TIMER_CONFIG
[Unit]
Description=Independent persistent fail-safe DE89 QUIC rollback
[Timer]
OnCalendar=$date_limit
Persistent=true
AccuracySec=1s
Unit=$REVERT
[Install]
WantedBy=timers.target
TIMER_CONFIG
  chmod 644 "$BASE/$REVERT" "$BASE/$TIMER"
  install -m 644 "$BASE/$UNIT" "$UNITFILE"
  install -m 644 "$BASE/$TIMER" "$TIMERFILE"
  install -m 644 "$BASE/$REVERT" "$REVERTFILE"
  systemctl daemon-reload
  systemctl enable --now "$TIMER"
  systemctl is-active --quiet "$TIMER"
  trap 'flock -u 9;bash "$MANAGER" rollback || true' ERR
  systemctl start "$UNIT"
  ready=0
  for i in $(seq 1 30);do
    if check_public_listener;then ready=1;break;fi
    sleep 1
  done
  test "$ready" = 1
  test "$(systemctl is-enabled "$UNIT")" != enabled
  systemctl is-active --quiet "$TIMER"
  trap - ERR
  echo DE89_PUBLIC_QUIC_UDP443_LIVE_PENDING_H3_VERIFICATION=PASS
  echo "DE89_PUBLIC_QUIC_INDEPENDENT_ROLLBACK_DEADLINE=$date_limit"
  ;;
status)
  check_public_listener
  test -f "$UNITFILE"
  cmp -s "$UNITFILE" "$BASE/$UNIT"
  echo DE89_PUBLIC_QUIC_443_AND_PRIVATE_19444=RUNNING
  ;;
finalize)
  approved_live_baseline
  check_public_listener
  systemctl is-active --quiet "$TIMER"
  cmp -s "$BASE/$UNIT" "$UNITFILE"
  systemctl enable "$UNIT"
  systemctl is-enabled --quiet "$UNIT"
  systemctl disable --now "$TIMER"
  ! systemctl is-active --quiet "$TIMER"
  check_public_listener
  echo DE89_PUBLIC_QUIC_UDP443_BOOT_PERSISTENT=PASS
  echo DE89_PRIVATE_QUIC_19444_AND_TCP_DNS_VPN_PRESERVED=PASS
  ;;
rollback)
  rollback
  ;;
*)
  exit 2
  ;;
esac
