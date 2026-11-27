#!/usr/bin/env bash
# Route only DoT requests made by the dedicated VPN Xray UID to DE89 or RU188
# public DoT addresses back through the EXISTING local SNI demux at :8854.
# No Nginx, Xray, WireGuard, certificates, subscribers, or UDP changes.
set -Eeuo pipefail
umask 077

MODE="${1:-status}"
ROOT=/var/lib/mnebydns-vpn-dot-selfroute-20261115
ROOT="${MNEBYDNS_DOT_SELFROUTE_ROOT:-$ROOT}"
MARK="$ROOT/installed"
OWNER=mnebyvpn-xray
OWNER="${MNEBYDNS_DOT_SELFROUTE_OWNER:-$OWNER}"
DE_IP="${MNEBYDNS_DOT_SELFROUTE_DE_IP:-89.125.90.101}"
RU_IP="${MNEBYDNS_DOT_SELFROUTE_RU_IP:-188.120.254.223}"
IP="$DE_IP"
TARGET_IPS=("$DE_IP" "$RU_IP")
ROUTER_PORT=8854
ROUTER_PORT="${MNEBYDNS_DOT_SELFROUTE_ROUTER_PORT:-$ROUTER_PORT}"
DOT_PORT="${MNEBYDNS_DOT_SELFROUTE_DOT_PORT:-853}"
CONF="${MNEBYDNS_DOT_SELFROUTE_CONF:-/etc/mnebydns/personal-sni/nginx.conf}"
SYSTEMD_DIR="${MNEBYDNS_DOT_SELFROUTE_SYSTEMD_DIR:-/etc/systemd/system}"
IPTABLES_BIN="${MNEBYDNS_DOT_SELFROUTE_IPTABLES_BIN:-/usr/sbin/iptables}"
EXT_IFACE="${MNEBYDNS_DOT_SELFROUTE_EXT_IFACE:-eth0}"
SCRIPT="${MNEBYDNS_DOT_SELFROUTE_SCRIPT:-/opt/mnebydns-vpn-dot-selfroute-20261115/manage.sh}"
SERVICE=mnebydns-vpn-dot-selfroute-20261115.service
TIMER=mnebydns-vpn-dot-selfroute-autorevert-20261115.timer
log() { printf 'VPN_DOT_SELFROUTE_%s=%s\n' "$1" "$2"; }

rule() {
  local target_ip="${1:-$DE_IP}"
  local uid
  uid="$(id -u "$OWNER")"
  test "$uid" -gt 0
  IP="$target_ip"
  RULE=(-p tcp -d "$IP"/32 --dport 853 -m owner --uid-owner "$uid" -j REDIRECT --to-ports "$ROUTER_PORT")
}
present() {
  rule "${1:-$DE_IP}"
  iptables -w -t nat -C OUTPUT "${RULE[@]}" >/dev/null 2>&1
}
sync_manage_script() {
  local self_real target_real tmp
  self_real="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  target_real="$(readlink -f "$SCRIPT" 2>/dev/null || printf '%s' "$SCRIPT")"
  if [[ -f "$0" && "$self_real" != "$target_real" ]]; then
    if [[ ! -e "$SCRIPT" ]] || ! cmp -s "$0" "$SCRIPT"; then
      mkdir -p -m 0700 "$(dirname "$SCRIPT")"
      tmp="$(mktemp "$(dirname "$SCRIPT")/.manage.XXXXXXXX")"
      cp "$0" "$tmp"
      chmod 0700 "$tmp"
      mv -f "$tmp" "$SCRIPT"
      log SCRIPT_UPDATED "$SCRIPT"
    fi
  fi
}
tcp_probe() {
  local ip="$1" port="$2" host="$3" mode="$4"
  runuser -u "$OWNER" -- python3 - "$ip" "$port" "$host" "$mode" <<'PY'
import socket,ssl,sys
ip,port,sni,mode=sys.argv[1:]
try:
    with socket.create_connection((ip,int(port)),timeout=7) as raw:
        raw.settimeout(7)
        with ssl.create_default_context().wrap_socket(raw,server_hostname=sni) as conn:
            assert conn.version()
except ssl.SSLCertVerificationError:
    if mode!="mismatch":
        raise
    print("VPN_DOT_SELFROUTE_EXPECTED_CERT_MISMATCH=true",flush=True)
else:
    if mode!="valid":
        raise RuntimeError("Unexpected TLS result")
    print("VPN_DOT_SELFROUTE_VALID_CERT=true",flush=True)
PY
}
probe_both() {
  local target_ip
  for target_ip in "${TARGET_IPS[@]}"; do
    tcp_probe "$target_ip" "$DOT_PORT" aaaaaaaaaaaa.dns.mnebyvpn.site valid
    tcp_probe "$target_ip" "$DOT_PORT" dns.mnebyvpn.site valid
  done
}
preflight() {
  rule "$DE_IP"
  test -x "$IPTABLES_BIN"
  test -r "$CONF"
  test -f "$SCRIPT"
  test -f "$SYSTEMD_DIR/$SERVICE"
  for svc in mnebydns-personal-sni-stream.service mnebydns-personal-sni-redirect.service mnebydns-dot.service mnebyvpn-vpn-provisioner.service; do
    systemctl is-active --quiet "$svc"
  done
  grep -Fq 'listen 0.0.0.0:8854;' "$CONF"
  grep -Fq 'default 89.125.90.101:853;' "$CONF"
  { grep -Fq '10.66.77.2:8858;' "$CONF" || grep -Fq '10.66.77.2:8856;' "$CONF"; }
  ss -H -lntp | grep -E ":${ROUTER_PORT}[[:space:]]" | grep -q nginx
  iptables -w -t nat -C PREROUTING -i "$EXT_IFACE" -d "$DE_IP" -p tcp --dport 853 -j REDIRECT --to-ports "$ROUTER_PORT"
}
rollback_rule() {
  if ! test -f "$MARK"; then log RULE_SKIPPED UNOWNED;return 0;fi
  local target_ip
  for target_ip in "${TARGET_IPS[@]}"; do
    rule "$target_ip"
    if present "$target_ip"; then
      iptables -w -t nat -D OUTPUT "${RULE[@]}"
    fi
  done
  log RULE_REMOVED YES
}
rollback() {
  # systemd ExecStop invokes rollback-rule, so do not recurse into service stop.
  systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
  rollback_rule
  rm -f "$MARK"
  log ROLLBACK COMPLETE
}
ensure() {
  sync_manage_script
  preflight
  test -f "$MARK" || { log ERROR MISSING_OWNERSHIP_MARKER; exit 3; }
  local inserted_ips=()
  local target_ip
  for target_ip in "${TARGET_IPS[@]}"; do
    rule "$target_ip"
    if ! present "$target_ip"; then
      iptables -w -t nat -I OUTPUT 1 "${RULE[@]}"
      inserted_ips+=("$target_ip")
    fi
  done
  if ! probe_both; then
    for target_ip in "${inserted_ips[@]}"; do
      rule "$target_ip"
      iptables -w -t nat -D OUTPUT "${RULE[@]}" >/dev/null 2>&1 || true
    done
    log ERROR POSTBOOT_CERT_VERIFICATION_FAILED
    exit 3
  fi
  log ACTIVE CONFIRMED
}
apply() {
  sync_manage_script
  preflight
  mkdir -p -m 0700 "$ROOT"
  if test -f "$MARK" || present "$DE_IP" || present "$RU_IP"; then log ERROR DUPLICATE_OR_FOREIGN_RULE;exit 3;fi
  # Verify correct failing condition, not an arbitrary timeout, before changing NAT.
  tcp_probe "$DE_IP" "$DOT_PORT" dns.mnebyvpn.site valid
  tcp_probe 127.0.0.1 "$ROUTER_PORT" aaaaaaaaaaaa.dns.mnebyvpn.site valid
  tcp_probe "$DE_IP" "$DOT_PORT" aaaaaaaaaaaa.dns.mnebyvpn.site mismatch
  systemd-run --quiet --unit=mnebydns-vpn-dot-selfroute-autorevert-20261115 --on-active=4m --collect /bin/bash "$SCRIPT" rollback
  systemctl is-active --quiet "$TIMER"
  log AUTO_ROLLBACK ARMED_4M
  # Any nonzero exit will delete only the rules this script added.
  trap 'rollback' ERR
  : > "$MARK"
  local target_ip
  for target_ip in "${TARGET_IPS[@]}"; do
    rule "$target_ip"
    iptables -w -t nat -I OUTPUT 1 "${RULE[@]}"
    present "$target_ip"
  done
  probe_both
  systemctl daemon-reload
  systemctl enable --now "$SERVICE"
  systemctl is-active --quiet "$SERVICE"
  for target_ip in "${TARGET_IPS[@]}"; do
    present "$target_ip"
  done
  probe_both
  systemctl stop "$TIMER"
  trap - ERR
  log INSTALLED PERSISTENT_AND_VERIFIED
}
status() {
  local de_active=0 ru_active=0
  if present "$DE_IP"; then de_active=1; fi
  if present "$RU_IP"; then ru_active=1; fi
  if (( de_active && ru_active )); then
    log RULE ACTIVE
  elif (( ! de_active && ! ru_active )); then
    log RULE ABSENT
  else
    log RULE PARTIAL
  fi
  log RULE_DE "$( (( de_active )) && echo ACTIVE || echo ABSENT )"
  log RULE_RU "$( (( ru_active )) && echo ACTIVE || echo ABSENT )"
  if test -f "$MARK"; then log MARK PRESENT;else log MARK ABSENT;fi
  if systemctl is-enabled --quiet "$SERVICE"; then log BOOT ENABLED;else log BOOT DISABLED;fi
}
case "$MODE" in
  apply) apply ;;
  ensure) ensure ;;
  rollback) rollback ;;
  rollback-rule) rollback_rule ;;
  status) status ;;
  *) echo 'usage: manage.sh apply|ensure|rollback|rollback-rule|status' >&2;exit 2 ;;
esac
