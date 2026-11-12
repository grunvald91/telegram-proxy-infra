#!/usr/bin/env bash
# Privileged kernel grammar smoke test ONLY in fresh ephemeral Linux netns.
set -Eeuo pipefail
[[ "$(id -u)" -eq 0 ]] || exit 2
NS="mnebyab$$"
cleanup() { ip netns del "$NS" 2>/dev/null || true; }
trap cleanup EXIT
ip netns add "$NS"
ip netns exec "$NS" nft -f - <<'NFT'
table inet telegram_nfqws {
    chain post {
        type filter hook postrouting priority srcnat; policy accept;
        meta mark & 0x1 == 0x1 tcp sport 443 queue flags bypass to 210
    }
}
NFT
TAG="MNEBY_IG_SYNACK_AB_202611101122"
RULE="insert rule inet telegram_nfqws post ip saddr 188.120.254.223 ip daddr 203.0.113.45 tcp sport 443 tcp flags & (syn | ack) == (syn | ack) counter return comment \"$TAG\""
printf '%s\n' "$RULE" | ip netns exec "$NS" nft --check -f -
printf '%s\n' "$RULE" | ip netns exec "$NS" nft -f -
LIST="$(ip netns exec "$NS" nft -a list chain inet telegram_nfqws post)"
grep -Fq "comment \"$TAG\"" <<< "$LIST"
mapfile -t ROWS < <(grep -E 'tcp sport 443|queue flags bypass' <<< "$LIST")
[[ "${#ROWS[@]}" -eq 2 ]]
[[ "${ROWS[0]}" == *"return comment \"$TAG\""* ]]
[[ "${ROWS[1]}" == *"queue flags bypass to 210"* ]]
HANDLE="$(grep -F "comment \"$TAG\"" <<< "$LIST" | sed -nE 's/.*# handle ([0-9]+).*/\1/p')"
[[ "$HANDLE" =~ ^[0-9]+$ ]]
ip netns exec "$NS" nft delete rule inet telegram_nfqws post handle "$HANDLE"
! ip netns exec "$NS" nft -a list chain inet telegram_nfqws post | grep -Fq "$TAG"
echo "nft_queue210_scoped_rule_syntax=PASS"
echo "nft_queue210_rule_order=PASS"
echo "nft_queue210_handle_rollback=PASS"
