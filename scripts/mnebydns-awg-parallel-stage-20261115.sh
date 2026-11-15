#!/usr/bin/env bash
# Temporary 2026-11-15 AWG side-by-side probe. NEVER modifies tg-relay or any production route.
set -Eeuo pipefail
umask 077
ROLE="${2:?role DE or RU}"
[[ "$ROLE" == DE || "$ROLE" == RU ]] || exit 2
DIR=/opt/mnebydns-awg-stage-20261115
BIN="$DIR/bin"
CONF="$DIR/awgtest0.conf"
UNIT=mneby-awg-stage-rollback-20261115
if [[ "$ROLE" == DE ]]; then
  MY_IP=89.125.90.101; PEER_IP=188.120.254.223; PORT=56783
else
  MY_IP=188.120.254.223; PEER_IP=89.125.90.101; PORT=56784
fi
rule=(-p udp -s "$PEER_IP" -d "$MY_IP" --dport "$PORT" -m comment --comment mneby_awg_stage_20261115 -j ACCEPT)
cleanup() {
  if [[ -f "$CONF" ]] && ip link show awgtest0 >/dev/null 2>&1; then
    "$BIN/awg-quick" down "$CONF" >/dev/null 2>&1 || ip link delete awgtest0 >/dev/null 2>&1 || true
  fi
  if iptables -C INPUT "${rule[@]}" >/dev/null 2>&1; then
    iptables -D INPUT "${rule[@]}"
  fi
  systemctl stop "$UNIT.timer" >/dev/null 2>&1 || true
  rm -rf -- "$DIR" "/tmp/mneby-awg-bundle-20261115.tar.gz" "/tmp/mneby-awg-config-20261115.conf"
  echo AWG_STAGE_"$ROLE"_CLEANED=true
}
case "${1:-}" in
  cleanup)
    cleanup ;;
  stage)
    [[ ! -e "$DIR" ]] || { echo AWG_STAGE_ALREADY_EXISTS=true; exit 2; }
    ! ip link show awgtest0 >/dev/null 2>&1 || { echo AWG_STAGE_INTERFACE_COLLISION=true; exit 2; }
    test -s /tmp/mneby-awg-config-20261115.conf
    test -s /tmp/mneby-awg-bundle-20261115.tar.gz
    ! ss -H -lun | grep -Eq ":($PORT)[[:space:]]" || { echo AWG_STAGE_UDP_PORT_OCCUPIED=true; exit 2; }
    ! ip -4 route show 10.66.78.0/30 | grep -q . || { echo AWG_STAGE_ROUTE_COLLISION=true; exit 2; }
    mkdir -p "$BIN"
    tar -xzf /tmp/mneby-awg-bundle-20261115.tar.gz -C "$BIN"
    (cd "$BIN" && sha256sum -c SHA256SUMS >/dev/null)
    chmod 700 "$BIN/amneziawg-go" "$BIN/awg" "$BIN/awg-quick"
    cp /tmp/mneby-awg-config-20261115.conf "$CONF"
    chmod 600 "$CONF"
    install -m 0700 /tmp/mneby-awg-manage-20261115.sh "$DIR/manage.sh"
    if ! systemd-run --quiet --unit="$UNIT" --on-active=6min "$DIR/manage.sh" cleanup "$ROLE"; then
      echo AWG_STAGE_ROLLBACK_TIMER_FAILED=true
      cleanup
      exit 3
    fi
    if ! iptables -C INPUT "${rule[@]}" >/dev/null 2>&1; then
      iptables -I INPUT 1 "${rule[@]}"
    fi
    # Keep the diagnostic log on the remote host, but report only whitelisted
    # error classes. No user/session keys or config lines go to Actions logs.
    log="$(mktemp)"
    if ! timeout 45s env PATH="$BIN:$PATH" WG_QUICK_USERSPACE_IMPLEMENTATION="$BIN/amneziawg-go" "$BIN/awg-quick" up "$CONF" >"$log" 2>&1; then
      echo AWG_STAGE_UP_FAILED=true
      for pattern in "Operation not supported" "Unknown device" "Unable to" "Failed" "Error" "invalid" "unrecognized" "permission denied" "No such file" "not found" "failed to"; do
        if grep -iq "$pattern" "$log"; then
          echo "AWG_STAGE_ERROR_CLASS=$pattern"
        fi
      done
      echo "AWG_STAGE_LOG_LINES=$(wc -l < "$log")"
      python3 - "$log" <<'PY'
import sys,re,pathlib
for line in pathlib.Path(sys.argv[1]).read_text(errors="replace").splitlines()[:35]:
    line=re.sub(r'(?i)(PrivateKey|PublicKey|HeaderProtectionKey)\s*=\s*\S+',r'\1=<redacted>',line)
    line=re.sub(r'\b[A-Za-z0-9+/]{40,}={0,2}\b','<redacted>',line)
    line=re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b','<ip>',line)
    print("AWG_STAGE_SAFE_LOG="+line[:250],flush=True)
PY
      rm -f "$log"
      cleanup
      exit 4
    fi
    rm -f "$log"
    ip -4 -br addr show awgtest0 | sed -E 's/([0-9]{1,3}\.){3}[0-9]{1,3}/<address>/g'
    echo AWG_STAGE_"$ROLE"_UP=true ;;
  status)
    test -d "$DIR"
    ip -j addr show awgtest0 | python3 -c 'import sys,json;d=json.load(sys.stdin)[0];print("AWG_STAGE_LINK="+json.dumps({"mtu":d["mtu"],"up":d["operstate"]!="DOWN"}))'
    PATH="$BIN:$PATH" "$BIN/awg" show awgtest0 latest-handshakes | awk '{if ($2>0) print "AWG_STAGE_HANDSHAKE_PRESENT=true"; else print "AWG_STAGE_HANDSHAKE_PRESENT=false"}'
    ;;
  *) echo 'usage: stage|status|cleanup role' >&2; exit 2 ;;
esac
