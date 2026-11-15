#!/usr/bin/env bash
# Route only DoT requests made by the dedicated VPN Xray UID to this server's
# public address back through the EXISTING local SNI demux at :8854.
# No Nginx, Xray, WireGuard, certificates, subscribers, or UDP changes.
set -Eeuo pipefail
umask 077

MODE="${1:-status}"
ROOT=/var/lib/mnebydns-vpn-dot-selfroute-20261115
MARK="$ROOT/installed"
OWNER=mnebyvpn-xray
IP=89.125.90.101
ROUTER_PORT=8854
SCRIPT=/opt/mnebydns-vpn-dot-selfroute-20261115/manage.sh
SERVICE=mnebydns-vpn-dot-selfroute-20261115.service
TIMER=mnebydns-vpn-dot-selfroute-autorevert-20261115.timer
log() { printf 'VPN_DOT_SELFROUTE_%s=%s\n' "$1" "$2"; }

rule() {
  local uid
  uid="$(id -u "$OWNER")"
  test "$uid" -gt 0
  RULE=(-p tcp -d "$IP"/32 --dport 853 -m owner --uid-owner "$uid" -j REDIRECT --to-ports "$ROUTER_PORT")
}
present() { iptables -w -t nat -C OUTPUT "${RULE[@]}" >/dev/null 2>&1; }
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
    if mode=="mismatch":
        raise RuntimeError("Expected pre-fix certificate mismatch, got valid TLS; refuse to change routing")
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
  tcp_probe "$IP" 853 aaaaaaaaaaaa.dns.mnebyvpn.site valid
  tcp_probe "$IP" 853 dns.mnebyvpn.site valid
}
preflight() {
  rule
  test -x /usr/sbin/iptables
  test -r /etc/mnebydns/personal-sni/nginx.conf
  test -f "$SCRIPT"
  test -f "/etc/systemd/system/$SERVICE"
  for svc in mnebydns-personal-sni-stream.service mnebydns-personal-sni-redirect.service mnebydns-dot.service mnebyvpn-vpn-provisioner.service; do
    systemctl is-active --quiet "$svc"
  done
  grep -Fq 'listen 0.0.0.0:8854;' /etc/mnebydns/personal-sni/nginx.conf
  grep -Fq 'default 89.125.90.101:853;' /etc/mnebydns/personal-sni/nginx.conf
  grep -Fq '10.66.77.2:8856;' /etc/mnebydns/personal-sni/nginx.conf
  ss -H -lntp | grep -E ':8854[[:space:]]' | grep -q nginx
  iptables -w -t nat -C PREROUTING -i eth0 -d "$IP" -p tcp --dport 853 -j REDIRECT --to-ports "$ROUTER_PORT"
}
rollback_rule() {
  rule
  if ! test -f "$MARK"; then log RULE_SKIPPED UNOWNED;return 0;fi
  if present; then
    iptables -w -t nat -D OUTPUT "${RULE[@]}"
  fi
  rm -f "$MARK"
  log RULE_REMOVED YES
}
rollback() {
  # systemd ExecStop invokes rollback-rule, so do not recurse into service stop.
  systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
  rollback_rule
  log ROLLBACK COMPLETE
}
ensure() {
  preflight
  test -f "$MARK" || { log ERROR MISSING_OWNERSHIP_MARKER; exit 3; }
  local inserted=0
  if ! present; then
    iptables -w -t nat -I OUTPUT 1 "${RULE[@]}"
    inserted=1
  fi
  if ! probe_both; then
    if (( inserted )); then iptables -w -t nat -D OUTPUT "${RULE[@]}" || true;fi
    log ERROR POSTBOOT_CERT_VERIFICATION_FAILED
    exit 3
  fi
  log ACTIVE CONFIRMED
}
apply() {
  preflight
  mkdir -p -m 0700 "$ROOT"
  if test -f "$MARK" || present; then log ERROR DUPLICATE_OR_FOREIGN_RULE;exit 3;fi
  # Verify correct failing condition, not an arbitrary timeout, before changing NAT.
  tcp_probe "$IP" 853 dns.mnebyvpn.site valid
  tcp_probe 127.0.0.1 8854 aaaaaaaaaaaa.dns.mnebyvpn.site valid
  tcp_probe "$IP" 853 aaaaaaaaaaaa.dns.mnebyvpn.site mismatch
  systemd-run --quiet --unit=mnebydns-vpn-dot-selfroute-autorevert-20261115 --on-active=4m --collect /bin/bash "$SCRIPT" rollback
  systemctl is-active --quiet "$TIMER"
  log AUTO_ROLLBACK ARMED_4M
  # Any nonzero exit will delete only the rule this script added.
  trap 'rollback' ERR
  : > "$MARK"
  iptables -w -t nat -I OUTPUT 1 "${RULE[@]}"
  present
  probe_both
  systemctl daemon-reload
  systemctl enable --now "$SERVICE"
  systemctl is-active --quiet "$SERVICE"
  present
  probe_both
  systemctl stop "$TIMER"
  trap - ERR
  log INSTALLED PERSISTENT_AND_VERIFIED
}
status() {
  rule
  if present; then log RULE ACTIVE;else log RULE ABSENT;fi
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
