#!/usr/bin/env bash
# Real nftables generator restart test, ONLY in disposable Linux netns.
set -Eeuo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root in CI"; exit 2; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NS="mg$(date +%s)$$"
TMP="$(mktemp -d)"
cleanup() { ip netns del "$NS" 2>/dev/null || true; rm -rf -- "$TMP"; }
trap cleanup EXIT
ip netns add "$NS"
python3 "$ROOT/scripts/mnebydns_nfqws_synack_guard_render.py" \
    "$ROOT/legacy-mtproxy/live-snapshot/server188/usr/local/sbin/telegram-nfqws-rules" >"$TMP/generator.sh"
sh -n "$TMP/generator.sh"
printf '203.0.113.5\n' > "$TMP/invalid-peer"
printf '8.8.4.4\n' > "$TMP/valid-peer"
# One root-owned public IPv4 fixture, not a real connection.
run_apply() {
    MNEBYDNS_SYNACK_CANARY_FILE="$1" ip netns exec "$NS" sh "$TMP/generator.sh" apply
}
run_apply "$TMP/valid-peer"
FIRST="$(ip netns exec "$NS" nft -a list chain inet telegram_nfqws post)"
grep -q 'MNEBYDNS_SYNACK_CANARY_PEER_V1' <<< "$FIRST"
grep -q 'ip daddr 8.8.4.4' <<< "$FIRST"
# Invalid peer fails BEFORE nft table deletion.
if run_apply "$TMP/invalid-peer" 2>"$TMP/invalid.log"; then
    echo "FAIL: invalid peer accepted" >&2; exit 1
fi
SECOND="$(ip netns exec "$NS" nft -a list chain inet telegram_nfqws post)"
grep -q 'MNEBYDNS_SYNACK_CANARY_PEER_V1' <<< "$SECOND"
grep -q 'queue.*210' <<< "$SECOND"
# A group/world writable allow-file or symlink also must abort before flushing.
chmod 666 "$TMP/valid-peer"
if run_apply "$TMP/valid-peer" 2>"$TMP/insecure.log"; then
    echo "FAIL: writable peer file accepted" >&2; exit 1
fi
chmod 600 "$TMP/valid-peer"
ln -s "$TMP/valid-peer" "$TMP/symlink-peer"
if run_apply "$TMP/symlink-peer" 2>"$TMP/symlink.log"; then
    echo "FAIL: symlink peer file accepted" >&2; exit 1
fi
grep -q 'MNEBYDNS_SYNACK_CANARY_PEER_V1' <<< "$(ip netns exec "$NS" nft -a list chain inet telegram_nfqws post)"
# Reapply simulates ExecStartPost after restart.
run_apply "$TMP/valid-peer"
THIRD="$(ip netns exec "$NS" nft -a list chain inet telegram_nfqws post)"
[[ "$(grep -c 'MNEBYDNS_SYNACK_CANARY_PEER_V1' <<< "$THIRD")" -eq 1 ]]
mapfile -t MATCH < <(grep -E 'MNEBYDNS_SYNACK_CANARY_PEER_V1|queue.*210' <<< "$THIRD")
[[ "${#MATCH[@]}" -eq 2 ]]
[[ "${MATCH[0]}" == *"MNEBYDNS_SYNACK_CANARY_PEER_V1"* ]]
[[ "${MATCH[1]}" == *"queue"* ]]
# With no opt-in file, behavior reverts to original generator.
MNEBYDNS_SYNACK_CANARY_FILE="$TMP/absent" ip netns exec "$NS" sh "$TMP/generator.sh" apply
FOURTH="$(ip netns exec "$NS" nft -a list chain inet telegram_nfqws post)"
! grep -q 'MNEBYDNS_SYNACK_CANARY_PEER_V1' <<< "$FOURTH"
grep -q 'queue.*210' <<< "$FOURTH"
echo "nfqws_restart_guard=PASS"
echo "nfqws_invalid_config_does_not_flush=PASS"
echo "nfqws_original_queue210_preserved=PASS"
echo "nfqws_opt_out_restores_original_behavior=PASS"
