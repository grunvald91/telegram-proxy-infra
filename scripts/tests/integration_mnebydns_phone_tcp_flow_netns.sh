#!/usr/bin/env bash
# Real kernel 5-tuple nft matching in isolated network namespaces ONLY.
set -Eeuo pipefail
[[ "$(id -u)" -eq 0 ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NS="mpf$$"; NC="mpc$$"
TMP="$(mktemp -d)"
PID=""
cleanup() {
    [[ -z "$PID" ]] || kill "$PID" 2>/dev/null || true
    ip netns del "$NC" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT
ip netns add "$NS"
ip netns add "$NC"
ip link add "mps$$" type veth peer name "mpc$$"
ip link set "mps$$" netns "$NS"
ip link set "mpc$$" netns "$NC"
ip -n "$NS" link set "mps$$" name ens3
ip -n "$NS" address add 188.120.254.223/32 dev ens3
ip -n "$NC" address add 8.8.4.4/32 dev "mpc$$"
ip -n "$NC" address add 1.1.1.1/32 dev "mpc$$"
ip -n "$NS" link set lo up
ip -n "$NS" link set ens3 up
ip -n "$NC" link set lo up
ip -n "$NC" link set "mpc$$" up
ip -n "$NS" route add 8.8.4.4/32 dev ens3
ip -n "$NS" route add 1.1.1.1/32 dev ens3
ip -n "$NC" route add 188.120.254.223/32 dev "mpc$$"
ip netns exec "$NS" nft -f - <<'NFT'
table inet telegram_nfqws {
 chain post {
   type filter hook postrouting priority 101; policy accept;
   oifname "ens3" tcp sport 443 ct reply packets 1-20 meta mark & 0x40000000 == 0 counter queue num 210 bypass
 }
}
NFT
RULE="$(python3 - "$ROOT" <<'PY'
import importlib.util,sys
from pathlib import Path
path=Path(sys.argv[1])/"scripts/mnebydns_phone_tcp_flow_probe.py"
spec=importlib.util.spec_from_file_location("phone",path)
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
print(p.nft_rule("8.8.4.4",51413,"MNEBY_PHONE_TCP_202611101122"),end="")
PY
)"
printf '%s\n' "$RULE" | ip netns exec "$NS" nft --check -f -
printf '%s\n' "$RULE" | ip netns exec "$NS" nft -f -
ip netns exec "$NS" python3 -u - "$TMP/ready" <<'PY' &
import socket,sys
s=socket.socket()
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("188.120.254.223",443));s.listen(5)
open(sys.argv[1],"w").write("READY\n")
s.settimeout(9)
for i in range(3):
    with s.accept()[0] as conn:
        conn.sendall(b"TEST\n")
s.close()
PY
PID=$!
for i in $(seq 1 70); do
    [[ -f "$TMP/ready" ]] && break
    kill -0 "$PID" 2>/dev/null || exit 1
    sleep .1
done
[[ -f "$TMP/ready" ]]
ip netns exec "$NC" python3 - <<'PY'
import socket
for source,port in [("8.8.4.4",51413),("8.8.4.4",51414),("1.1.1.1",51413)]:
    with socket.socket() as s:
        s.bind((source,port))
        s.settimeout(5)
        s.connect(("188.120.254.223",443))
        assert s.recv(20)==b"TEST\n"
PY
wait "$PID";PID=""
CHAIN="$(ip netns exec "$NS" nft -a list chain inet telegram_nfqws post)"
ROW="$(grep 'MNEBY_PHONE_TCP_202611101122' <<< "$CHAIN")"
COUNT="$(sed -nE 's/.*counter packets ([0-9]+) bytes.*/\1/p' <<< "$ROW")"
[[ "$COUNT" == 1 ]] || { echo "Wrong 5-tuple guard hit count: $COUNT" >&2; exit 1; }
HANDLE="$(sed -nE 's/.*# handle ([0-9]+).*/\1/p' <<< "$ROW")"
[[ "$HANDLE" =~ ^[0-9]+$ ]]
ip netns exec "$NS" nft delete rule inet telegram_nfqws post handle "$HANDLE"
! ip netns exec "$NS" nft -a list chain inet telegram_nfqws post | grep -q MNEBY_PHONE_TCP_
ip netns exec "$NS" nft -a list chain inet telegram_nfqws post | grep -q 'queue.*210'
echo "phone_five_tuple_rule_matches_exactly_one_synack=PASS"
echo "phone_other_nat_source_ports_untouched=PASS"
echo "phone_original_queue210_rule_preserved=PASS"
echo "phone_nft_handle_rollback=PASS"
