#!/usr/bin/env bash
# Run from an already SSH-authorized Codespace, NOT from GitHub Actions.
# Baseline -> narrowly scoped remote bypass -> test -> rollback check.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
REMOTE="root@188.120.254.223"
KNOWN="$ROOT/ops/mnebydns-owner-ssh-known_hosts"
SOURCE="$ROOT/scripts/mnebydns_instagram_queue210_synack_ab.py"
[[ -f "$KNOWN" && -f "$SOURCE" ]] || { echo 'Check out the experiment PR branch first' >&2; exit 2; }
for bin in ssh python3 grep date mktemp; do command -v "$bin" >/dev/null; done
SSH_OPTS=(
    -T -o BatchMode=yes -o ConnectTimeout=12 -o StrictHostKeyChecking=yes
    -o HostKeyAlgorithms=ssh-ed25519
    -o "UserKnownHostsFile=$KNOWN" -o GlobalKnownHostsFile=/dev/null
    -o UpdateHostKeys=no -o LogLevel=ERROR
)

# The source seen by RU SSH is the test peer, without relying on a generic IP API.
PEER="$(ssh "${SSH_OPTS[@]}" "$REMOTE" 'printf "%s" "${SSH_CONNECTION%% *}"')"
python3 - "$PEER" <<'PY'
import ipaddress,sys
if not ipaddress.IPv4Address(sys.argv[1]).is_global:
    raise SystemExit("SSH peer must be a public IPv4 address")
PY
echo "remote_ssh_authorized=true"
echo "peer_scope=ssh_observed_public_ipv4"

# Test TCP/443 only; no TLS credentials or Instagram payload are sent.
probe() {
    python3 - "$1" <<'PY'
import socket,sys,time
label=sys.argv[1]
results=[]
for i in range(3):
    try:
        with socket.create_connection(("188.120.254.223",443),timeout=2.8):
            results.append("connected")
    except OSError as e:
        results.append(type(e).__name__)
    time.sleep(0.2)
print(label+"_results="+",".join(results),flush=True)
print(label+"_connected="+str("connected" in results).lower(),flush=True)
PY
}
echo "phase=BASELINE"
BASELINE="$(probe baseline)"
printf '%s\n' "$BASELINE"
if grep -q 'baseline_connected=true' <<< "$BASELINE"; then
    echo "A/B test not needed: baseline 443 already connected from this peer"
    exit 0
fi

RUN_ID="$(date +%Y%m%d%H%M%S)"
LOG="$(mktemp)"
REMOTE_PID=""
cleanup() {
    [[ -z "$REMOTE_PID" ]] || kill "$REMOTE_PID" 2>/dev/null || true
    rm -f -- "$LOG"
}
trap cleanup EXIT
echo "phase=ISOLATED_SYNACK_BYPASS"
ssh "${SSH_OPTS[@]}" "$REMOTE" "python3 - '$PEER' '$RUN_ID'" < "$SOURCE" > "$LOG" 2>&1 &
REMOTE_PID=$!
READY=0
for i in $(seq 1 100); do
    if grep -q 'synack_ab_test=READY' "$LOG" 2>/dev/null; then READY=1; break; fi
    if ! kill -0 "$REMOTE_PID" 2>/dev/null; then break; fi
    sleep 0.2
done
if [[ "$READY" != 1 ]]; then
    cat "$LOG"
    echo "test_setup=FAILED_NO_FIREWALL_CHANGE_SHOULD_BE_ASSUMED" >&2
    exit 1
fi
ACTIVE="$(probe bypass)"
printf '%s\n' "$ACTIVE"
wait "$REMOTE_PID"
REMOTE_PID=""
cat "$LOG"
grep -q 'synack_ab_immediate_cleanup=DONE' "$LOG" ||
    grep -q 'synack_ab_immediate_cleanup=ALREADY_REMOVED' "$LOG" || {
        echo "rollback_verification=FAILED" >&2
        exit 1
    }
# Read-only audit, exact test comment must be absent after cleanup.
if ssh "${SSH_OPTS[@]}" "$REMOTE" 'nft -a list chain inet telegram_nfqws post' |
    grep -Fq "MNEBY_IG_SYNACK_AB_${RUN_ID}"; then
    echo "rollback_verification=FAILED_STALE_RULE" >&2
    exit 1
fi
echo "rollback_verification=PASS"
echo "phase=AFTER_ROLLBACK"
probe restored
echo "A_B_RESULT_COMPLETE"
