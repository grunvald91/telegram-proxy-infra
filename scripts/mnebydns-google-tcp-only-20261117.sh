#!/usr/bin/env bash
# Reversible, fail-closed Google/YouTube TCP-only cutover on DE89 and RU188.
# Only dedicated YouTube QUIC relay services and UDP/443 are affected.
# Does NOT edit CoreDNS, Nginx, GooglePilot, VPN, WireGuard or customer data.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 2 ]] || exit 2
ROLE="$1"
PHASE="$2"
BASE=/opt/mnebydns-google-tcp-only-20261117
MANAGER="$BASE/manager.sh"
GUARD=mnebydns-google-tcp-only-20261117.service
REVERT=mnebydns-google-tcp-only-revert-20261117.service
TIMER=mnebydns-google-tcp-only-revert-20261117.timer
TAG=MNEBYDNS_GOOGLE_TCP_ONLY_20261117
COMMITTED="$BASE/COMMITTED"

case "$ROLE" in
  de)
    ADDR=89.125.90.101
    UNITS="mnebydns-de89-public-quic-20261115.service mnebydns-youtube-quic-de-43612369808.service"
    EXPECT_SOCKET=89.125.90.101:443
    ;;
  ru)
    ADDR=188.120.254.223
    UNITS="mnebydns-youtube-quic-ru-43612369808.service"
    EXPECT_SOCKET=0.0.0.0:443
    ;;
  *) echo "TCP_ONLY_INVALID_ROLE" >&2; exit 2 ;;
esac

rule() {
  case "$1" in
    -I) iptables -w 10 -I INPUT 1 -d "$ADDR" -p udp --dport 443 -m comment --comment "$TAG" -j REJECT --reject-with icmp-port-unreachable ;;
    -C|-D) iptables -w 10 "$1" INPUT -d "$ADDR" -p udp --dport 443 -m comment --comment "$TAG" -j REJECT --reject-with icmp-port-unreachable ;;
    *) exit 2 ;;
  esac
}
rule_present() { rule -C >/dev/null 2>&1; }
firewall_on() {
  if ! rule_present; then rule -I; fi
  rule_present
}
firewall_off() {
  if rule_present; then rule -D; fi
  ! rule_present
}
# Called by systemd; must not wait on the manager's global lock.
if [[ "$PHASE" = firewall-on ]]; then firewall_on; exit; fi
if [[ "$PHASE" = firewall-off ]]; then firewall_off; exit; fi

exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 45 9

owned_service_files_absent() {
  test ! -e "/etc/systemd/system/$GUARD"
  test ! -e "/etc/systemd/system/$TIMER"
  test ! -e "/etc/systemd/system/$REVERT"
}
base_healthy() {
  ip -4 -o addr show | grep -Fq "$ADDR/"
  systemctl is-active --quiet nginx.service
  ss -Hlnpt '( sport = :443 )' | grep -q .
  ss -Hlnpt '( sport = :853 )' | grep -q .
  if [[ "$ROLE" = de ]]; then
    systemctl is-active --quiet mnebydns-dot.service
    systemctl is-active --quiet mnebydns-googlepilot.service
    ss -Hlnpt '( sport = :15449 )' | grep -Fq '127.0.0.1:15449'
  fi
}
verify_quic_original() {
  for unit in $UNITS; do
    systemctl is-active --quiet "$unit"
    test "$(systemctl is-enabled "$unit")" = enabled
  done
  ss -Hlunp '( sport = :443 )' | grep -Fq "$EXPECT_SOCKET"
  if [[ "$ROLE" = de ]]; then
    ss -Hlunp '( sport = :19444 )' | grep -Fq '10.66.77.1:19444'
  fi
}
verify_tcp_only() {
  base_healthy
  systemctl is-active --quiet "$GUARD"
  systemctl is-enabled --quiet "$GUARD"
  rule_present
  test -z "$(ss -Hlunp '( sport = :443 )')"
  for unit in $UNITS; do
    ! systemctl is-active --quiet "$unit"
    test "$(systemctl is-enabled "$unit")" = disabled
  done
  if [[ "$ROLE" = de ]]; then
    test -z "$(ss -Hlunp '( sport = :19444 )')"
  fi
}
stage() {
  base_healthy
  verify_quic_original
  ! rule_present
  owned_service_files_absent
  test ! -e "$BASE"
  test -s "/tmp/mnebydns-google-tcp-only-20261117.sh"
  test ! -L "/tmp/mnebydns-google-tcp-only-20261117.sh"
  bash -n "/tmp/mnebydns-google-tcp-only-20261117.sh"
  mkdir -m 700 "$BASE"
  install -m 700 "/tmp/mnebydns-google-tcp-only-20261117.sh" "$MANAGER"
  cat > "$BASE/$GUARD" <<EOF
[Unit]
Description=MNEBYDNS Google TCP-only UDP443 targeted rejection ($ROLE)
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash $MANAGER $ROLE firewall-on
ExecStop=/bin/bash $MANAGER $ROLE firewall-off
TimeoutStartSec=15s
TimeoutStopSec=15s
[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$BASE/$GUARD"
  echo "TCP_ONLY_ROLE=$ROLE STAGED_NO_LIVE_CHANGES=PASS"
}
apply() {
  base_healthy
  verify_quic_original
  ! rule_present
  test -s "$MANAGER"
  test -f "$BASE/$GUARD"
  test ! -e "$COMMITTED"
  owned_service_files_absent
  deadline="$(date -u -d '+20 minutes' '+%Y-%m-%d %H:%M:%S UTC')"
  cat > "$BASE/$REVERT" <<EOF
[Unit]
Description=Automatic Google TCP-only tentative-cutover rollback ($ROLE)
[Service]
Type=oneshot
ExecStart=/bin/bash $MANAGER $ROLE rollback
EOF
  cat > "$BASE/$TIMER" <<EOF
[Unit]
Description=MNEBYDNS Google TCP-only independent 20-minute rollback ($ROLE)
[Timer]
OnCalendar=$deadline
Persistent=true
AccuracySec=1s
Unit=$REVERT
[Install]
WantedBy=timers.target
EOF
  chmod 644 "$BASE/$REVERT" "$BASE/$TIMER"
  install -m 644 "$BASE/$REVERT" "/etc/systemd/system/$REVERT"
  install -m 644 "$BASE/$TIMER" "/etc/systemd/system/$TIMER"
  install -m 644 "$BASE/$GUARD" "/etc/systemd/system/$GUARD"
  systemctl daemon-reload
  systemctl enable --now "$TIMER"
  systemctl is-active --quiet "$TIMER"
  # Explicit ICMP port unreachable rather than silently blackholing QUIC.
  systemctl enable --now "$GUARD"
  for unit in $UNITS; do
    systemctl disable --now "$unit"
  done
  verify_tcp_only
  systemctl is-active --quiet "$TIMER"
  echo "TCP_ONLY_ROLE=$ROLE APPLIED_GUARDED=PASS"
  echo "TCP_ONLY_ROLE=$ROLE WATCHDOG_DEADLINE=$deadline"
}
rollback() {
  if [[ -e "$COMMITTED" ]]; then
    echo "TCP_ONLY_ROLE=$ROLE ROLLBACK_SKIPPED_COMMITTED=true"
    return 0
  fi
  restore
}
restore() {
  test -f "$BASE/$GUARD"
  if systemctl is-active --quiet "$GUARD"; then
    systemctl disable --now "$GUARD"
  else
    systemctl disable "$GUARD" >/dev/null 2>&1 || true
  fi
  firewall_off
  for unit in $UNITS; do
    systemctl enable --now "$unit"
  done
  systemctl disable --now "$TIMER" >/dev/null 2>&1 || true
  rm -f -- "/etc/systemd/system/$GUARD" \
    "/etc/systemd/system/$TIMER" "/etc/systemd/system/$REVERT"
  systemctl daemon-reload
  rm -f -- "$COMMITTED"
  base_healthy
  verify_quic_original
  echo "TCP_ONLY_ROLE=$ROLE ORIGINAL_QUIC_RESTORED=PASS"
}
finalize() {
  verify_tcp_only
  systemctl is-active --quiet "$TIMER"
  touch "$COMMITTED"
  chmod 600 "$COMMITTED"
  # COMMITTED prevents a late watchdog from undoing a successful cutover.
  systemctl disable --now "$TIMER"
  verify_tcp_only
  echo "TCP_ONLY_ROLE=$ROLE PERSISTENT_COMMITTED=PASS"
}
case "$PHASE" in
  stage) stage ;;
  apply) apply ;;
  status) verify_tcp_only; echo "TCP_ONLY_ROLE=$ROLE ACTIVE=PASS" ;;
  finalize) finalize ;;
  rollback) rollback ;;
  undo) restore ;;
  *) echo TCP_ONLY_INVALID_PHASE >&2; exit 2 ;;
esac
