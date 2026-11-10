#!/usr/bin/env bash
# Strictly isolated 18443/TCP canary; independent systemd timer removes rule.
set -Eeuo pipefail
SERVER=188.120.254.223
PORT=18443
QUEUE=211
DURATION=120
WATCHDOG=150
TAG=MNEBYDNS_SYNACK_CANARY_211
UNIT=mnebydns-synack-rollback-211
usage() { echo 'Usage: sudo MNEBYDNS_CANARY=YES bash scripts/mnebydns-synack-window-canary.sh CLIENT_PUBLIC_IPV4' >&2; exit 2; }
[[ $# -eq 1 ]] || usage
[[ "$(id -u)" -eq 0 ]] || { echo 'Root required' >&2; exit 2; }
CLIENT="$1"
python3 - "$CLIENT" "$SERVER" <<'PY'
import ipaddress,sys
c,s=map(ipaddress.ip_address,sys.argv[1:])
if c.version != 4 or s.version != 4 or not c.is_global or not s.is_global or c==s:
    raise SystemExit('Distinct public IPv4 addresses required')
PY
RULE=(-s "$SERVER" -d "$CLIENT" -p tcp --sport "$PORT" --tcp-flags SYN,ACK SYN,ACK -m comment --comment "$TAG" -j NFQUEUE --queue-num "$QUEUE" --queue-bypass)
remove_rule() {
    if iptables -w -t mangle -C OUTPUT "${RULE[@]}" 2>/dev/null; then
        iptables -w -t mangle -D OUTPUT "${RULE[@]}"
    fi
}
# Emergency manual cleanup, independent of the environment variable.
if [[ "${MNEBYDNS_ROLLBACK:-}" == YES ]]; then
    remove_rule
    echo 'Scoped NFQUEUE rule removed if present'
    exit 0
fi
[[ "${MNEBYDNS_CANARY:-}" == YES ]] || usage
for bin in iptables systemd-run systemctl timeout flock python3; do
    command -v "$bin" >/dev/null || { echo "Missing $bin" >&2; exit 2; }
done
exec 9>/run/lock/mnebydns-synack-canary.lock
flock -n 9 || { echo 'Canary already active' >&2; exit 3; }
if systemctl is-active --quiet "$UNIT.timer"; then
    echo 'Previous rollback timer still active: refuse overlap' >&2
    exit 3
fi
if iptables -w -t mangle -S OUTPUT | grep -F -- "$TAG" >/dev/null; then
    echo 'Existing tagged canary rule detected; refuse overlap' >&2
    exit 3
fi
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="$(mktemp -d /run/mnebydns-synack.XXXXXXXX)"
LISTENER_PID=''
QUEUE_PID=''
cleanup() {
    trap - EXIT INT TERM HUP
    remove_rule || echo 'WARNING: immediate rollback failed; independently scheduled watchdog must remove it' >&2
    [[ -z "$QUEUE_PID" ]] || kill "$QUEUE_PID" 2>/dev/null || true
    [[ -z "$LISTENER_PID" ]] || kill "$LISTENER_PID" 2>/dev/null || true
    [[ -z "$QUEUE_PID" ]] || wait "$QUEUE_PID" 2>/dev/null || true
    [[ -z "$LISTENER_PID" ]] || wait "$LISTENER_PID" 2>/dev/null || true
    rm -rf -- "$WORKDIR"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
python3 "$SCRIPT_DIR/mnebydns_synack_listener.py" --bind "$SERVER" --port "$PORT" \
    --client "$CLIENT" --ready-file "$WORKDIR/listener.ready" &
LISTENER_PID=$!
python3 "$SCRIPT_DIR/mnebydns_synack_window_canary.py" --server "$SERVER" --client "$CLIENT" \
    --port "$PORT" --queue "$QUEUE" --window 4 --ready-file "$WORKDIR/queue.ready" &
QUEUE_PID=$!
ready=0
for _ in {1..60}; do
    if [[ -f "$WORKDIR/listener.ready" && -f "$WORKDIR/queue.ready" ]]; then ready=1; break; fi
    if ! kill -0 "$LISTENER_PID" 2>/dev/null || ! kill -0 "$QUEUE_PID" 2>/dev/null; then break; fi
    sleep .1
done
[[ "$ready" == 1 ]] && kill -0 "$LISTENER_PID" 2>/dev/null && kill -0 "$QUEUE_PID" 2>/dev/null || {
    echo 'Test listener or FAIL_OPEN queue initialization failed; no firewall rule installed' >&2
    exit 4
}
# The rollback command is self-contained and does not depend on the repo file.
IPTABLES_BIN="$(type -P iptables)"
[[ "$IPTABLES_BIN" == /* ]] || { echo "iptables must be an absolute executable" >&2; exit 3; }
ROLLBACK_CMD="$IPTABLES_BIN -w -t mangle -D OUTPUT -s $SERVER -d $CLIENT -p tcp --sport $PORT --tcp-flags SYN,ACK SYN,ACK -m comment --comment $TAG -j NFQUEUE --queue-num $QUEUE --queue-bypass 2>/dev/null || true"
systemd-run --quiet --collect --unit "$UNIT" --on-active="${WATCHDOG}s" /usr/bin/bash -c "$ROLLBACK_CMD"
# Timer is installed BEFORE any packet enters NFQUEUE.
iptables -w -t mangle -I OUTPUT 1 "${RULE[@]}"
echo "CANARY on dedicated ${SERVER}:${PORT}, allowed source ${CLIENT}, duration ${DURATION}s; rollback scheduled at ${WATCHDOG}s"
echo "Try: curl -vk --connect-to i.instagram.com:443:${SERVER}:${PORT} https://i.instagram.com/"
sleep "$DURATION"
