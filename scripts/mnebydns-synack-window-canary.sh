#!/usr/bin/env bash
# Optional, bounded canary on RU VPS. No service restarts. Always removes its own rule.
set -Eeuo pipefail
[[ $# -eq 1 ]] || { echo 'Usage: sudo MNEBYDNS_CANARY=YES bash scripts/mnebydns-synack-window-canary.sh CLIENT_PUBLIC_IPV4' >&2; exit 2; }
[[ "${MNEBYDNS_CANARY:-}" == YES ]] || { echo 'Explicit MNEBYDNS_CANARY=YES required' >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo 'Root required on isolated test host' >&2; exit 2; }
CLIENT="$1"
SERVER="188.120.254.223"
PORT=443
QUEUE=211
DURATION=120
python3 - "$CLIENT" "$SERVER" <<'PY'
import ipaddress,sys
client,server=map(ipaddress.ip_address,sys.argv[1:])
if client.version != 4 or server.version != 4 or not client.is_global or not server.is_global or client==server:
    raise SystemExit('Client and server must be distinct public IPv4 addresses')
PY
command -v iptables >/dev/null
command -v timeout >/dev/null
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RULE=(-s "$SERVER" -d "$CLIENT" -p tcp --sport "$PORT" --tcp-flags SYN,ACK SYN,ACK -m comment --comment MNEBYDNS_SYNACK_CANARY -j NFQUEUE --queue-num "$QUEUE" --queue-bypass)
# Fail closed against duplicate/stale experiments on the selected tuple.
if iptables -w -t mangle -C OUTPUT "${RULE[@]}" 2>/dev/null; then
    echo 'Existing canary rule detected, refusing to overlap' >&2
    exit 3
fi
cleanup() { iptables -w -t mangle -D OUTPUT "${RULE[@]}" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
iptables -w -t mangle -I OUTPUT 1 "${RULE[@]}"
echo "CANARY active for ${DURATION}s: ${SERVER}:443 -> ${CLIENT}, queue ${QUEUE}; no persistent changes"
# timeout closes the daemon and triggers shell rule cleanup, including signal termination.
timeout --signal=INT --kill-after=5s "${DURATION}s" python3 "$SCRIPT_DIR/mnebydns_synack_window_canary.py" \
    --server "$SERVER" --client "$CLIENT" --port "$PORT" --queue "$QUEUE" --window 4 || status=$?
[[ "${status:-0}" -eq 124 ]] && status=0
exit "${status:-0}"
