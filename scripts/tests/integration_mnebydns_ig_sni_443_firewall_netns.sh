#!/usr/bin/env bash
# Tests exact 443 rules on disposable isolated Linux network namespace ONLY.
# Never connects to a public IP, changes server, or sends a packet to Meta.
set -Eeuo pipefail
trap 'echo "ig443_kernel_test_failed_at_line=$LINENO" >&2' ERR
(( EUID == 0 )) || { echo 'root required in isolated CI runner' >&2; exit 2; }
cd "$(dirname "$0")/../.."
NS="ig443-ci-$$"
DIR="$(mktemp -d)"
cleanup(){
  ip netns del "$NS" >/dev/null 2>&1 || true
  rm -rf -- "$DIR"
}
trap cleanup EXIT
ip netns add "$NS"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" nft -f - <<'NFT'
add table inet telegram_nfqws
add chain inet telegram_nfqws post { type filter hook postrouting priority 0; policy accept; }
add rule inet telegram_nfqws post oifname "ens3" tcp sport 443 ct reply packets 1-20 meta mark and 0x40000000 == 0 counter queue num 210 bypass
NFT
python3 - "$DIR/rule.nft" <<'PY'
import importlib.util,sys
from pathlib import Path
p=Path("scripts/mnebydns_ig_sni_443_field_canary.py")
spec=importlib.util.spec_from_file_location("canary",p)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
Path(sys.argv[1]).write_text(m.nft_rule("9.9.9.9","MNEBY_IG_FRAG443_42999999999"))
PY
ip netns exec "$NS" nft --check -f "$DIR/rule.nft"
ip netns exec "$NS" nft -f "$DIR/rule.nft"
ip netns exec "$NS" nft -a list chain inet telegram_nfqws post > "$DIR/nft-live"
grep -F 'MNEBY_IG_FRAG443_42999999999' "$DIR/nft-live" >/dev/null
grep -E 'queue.*210.*bypass' "$DIR/nft-live" >/dev/null
ip netns exec "$NS" iptables -w -t mangle -I OUTPUT 1 \
  -s 188.120.254.223 -d 9.9.9.9 -p tcp --sport 443 \
  --tcp-flags SYN,ACK SYN,ACK -m comment --comment MNEBY_IG_FRAG443_42999999999 \
  -j NFQUEUE --queue-num 211 --queue-bypass
ip netns exec "$NS" iptables -w -t mangle -C OUTPUT \
  -s 188.120.254.223 -d 9.9.9.9 -p tcp --sport 443 \
  --tcp-flags SYN,ACK SYN,ACK -m comment --comment MNEBY_IG_FRAG443_42999999999 \
  -j NFQUEUE --queue-num 211 --queue-bypass
echo 'ig443_real_kernel_syntax_and_exact_210_211_rules=PASS'
ip netns exec "$NS" iptables -w -t mangle -D OUTPUT \
  -s 188.120.254.223 -d 9.9.9.9 -p tcp --sport 443 \
  --tcp-flags SYN,ACK SYN,ACK -m comment --comment MNEBY_IG_FRAG443_42999999999 \
  -j NFQUEUE --queue-num 211 --queue-bypass
ip netns exec "$NS" nft -a list chain inet telegram_nfqws post > "$DIR/before-remove"
HANDLE="$(grep -F 'MNEBY_IG_FRAG443_42999999999' "$DIR/before-remove" | sed -n -E 's/.*# handle ([0-9]+).*/\1/p')"
[[ "$HANDLE" =~ ^[0-9]+$ ]]
ip netns exec "$NS" nft delete rule inet telegram_nfqws post handle "$HANDLE"
ip netns exec "$NS" nft -a list chain inet telegram_nfqws post > "$DIR/after-remove"
! grep -Fq 'MNEBY_IG_FRAG443_' "$DIR/after-remove"
grep -E 'queue.*210.*bypass' "$DIR/after-remove" >/dev/null
! ip netns exec "$NS" iptables -w -t mangle -S OUTPUT | grep -Fq 'MNEBY_IG_FRAG443_'
echo 'ig443_kernel_scoped_rollback_and_original_queue210=PASS'
