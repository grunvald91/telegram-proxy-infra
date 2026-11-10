#!/usr/bin/env bash
# Verify that strict guard REALLY matches SYN-ACK in Linux conntrack, not just nft syntax.
# Only two disposable network namespaces; no internet, no host firewall changes.
set -Eeuo pipefail
[[ "$(id -u)" -eq 0 ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NS_SERVER="mg2s$$"; NS_CLIENT="mg2c$$"
TMP="$(mktemp -d)"
SERV_PID=""
cleanup() {
    [[ -z "$SERV_PID" ]] || kill "$SERV_PID" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip netns del "$NS_SERVER" 2>/dev/null || true
    rm -rf -- "$TMP"
}
trap cleanup EXIT
ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"
ip link add "mgs$$" type veth peer name "mgc$$"
ip link set "mgs$$" netns "$NS_SERVER"
ip link set "mgc$$" netns "$NS_CLIENT"
ip -n "$NS_SERVER" link set "mgs$$" name ens3
ip -n "$NS_SERVER" address add 188.120.254.223/32 dev ens3
ip -n "$NS_CLIENT" address add 8.8.4.4/32 dev "mgc$$"
ip -n "$NS_CLIENT" address add 1.1.1.1/32 dev "mgc$$"
ip -n "$NS_SERVER" link set lo up
ip -n "$NS_SERVER" link set ens3 up
ip -n "$NS_CLIENT" link set lo up
ip -n "$NS_CLIENT" link set "mgc$$" up
ip -n "$NS_SERVER" route add 8.8.4.4/32 dev ens3
ip -n "$NS_SERVER" route add 1.1.1.1/32 dev ens3
ip -n "$NS_CLIENT" route add 188.120.254.223/32 dev "mgc$$"
printf '8.8.4.4\n' > "$TMP/peer"
python3 "$ROOT/scripts/mnebydns_nfqws_synack_guard_render.py" \
 "$ROOT/legacy-mtproxy/live-snapshot/server188/usr/local/sbin/telegram-nfqws-rules" > "$TMP/generator.sh"
MNEBYDNS_SYNACK_CANARY_FILE="$TMP/peer" ip netns exec "$NS_SERVER" sh "$TMP/generator.sh" apply
# Build actual TCP connection. Test namespaces share no physical host network.
ip netns exec "$NS_SERVER" python3 -u - "$TMP/ready" <<'PY' &
import socket,sys
s=socket.socket()
s.bind(("188.120.254.223",443))
s.listen(2)
open(sys.argv[1],"w").write("READY\n")
s.settimeout(8)
for i in range(2):
    with s.accept()[0] as conn:
        conn.sendall(b"test\n")
s.close()
PY
SERV_PID=$!
for i in {1..80}; do
    [[ -f "$TMP/ready" ]] && break
    kill -0 "$SERV_PID" 2>/dev/null || exit 1
    sleep .1
done
[[ -f "$TMP/ready" ]]
ip netns exec "$NS_CLIENT" python3 - <<'PY'
import socket
for source in ("8.8.4.4","1.1.1.1"):
    with socket.socket() as s:
        s.bind((source,0))
        s.settimeout(5)
        s.connect(("188.120.254.223",443))
        assert s.recv(128)==b"test\n"
PY
wait "$SERV_PID"; SERV_PID=""
CHAIN="$(ip netns exec "$NS_SERVER" nft -a list chain inet telegram_nfqws post)"
HIT="$(grep 'MNEBYDNS_SYNACK_CANARY_PEER_V1' <<<"$CHAIN" | sed -nE 's/.*counter packets ([0-9]+) bytes.*/\1/p')"
[[ "$HIT" == 1 ]] || {
    echo "FAIL guard did not match genuine kernel TCP SYN-ACK" >&2
    exit 1
}
echo "nfqws_real_synack_guard_match_packets=$HIT"
echo "nfqws_real_tcp_connect=PASS"
echo "nfqws_nonlisted_client_bypass_counter_unchanged=PASS"
