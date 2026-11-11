#!/usr/bin/env bash
# Disposable Linux namespaces ONLY. No changes to live VPS or Internet.
set -Eeuo pipefail
(( EUID == 0 )) || { echo root_required; exit 2; }
for bin in ip nft tcpdump ethtool python3; do command -v "$bin" >/dev/null; done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PROBE="$ROOT/scripts/tests/mnebydns_ig_w4_ack_netns_probe.py"
TMP="$(mktemp -d)"
SERV="ignfts_$$"
CLNT="ignftc_$$"
V1="ignfs$$"
V2="ignfc$$"
SPID=''
CPID=''
cleanup(){
  set +e
  [[ -z "$CPID" ]] || { kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; }
  [[ -z "$SPID" ]] || { kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null; }
  ip netns del "$CLNT" 2>/dev/null
  ip netns del "$SERV" 2>/dev/null
  rm -rf -- "$TMP"
  true
}
trap cleanup EXIT
ip netns add "$SERV"
ip netns add "$CLNT"
ip link add "$V1" type veth peer name "$V2"
ip link set "$V1" netns "$SERV"
ip link set "$V2" netns "$CLNT"
ip -n "$SERV" addr add 192.0.2.1/24 dev "$V1"
ip -n "$CLNT" addr add 192.0.2.2/24 dev "$V2"
ip -n "$SERV" link set lo up
ip -n "$CLNT" link set lo up
ip -n "$SERV" link set "$V1" up
ip -n "$CLNT" link set "$V2" up
ip netns exec "$SERV" ethtool -K "$V1" tx off tso off gso off gro off
ip netns exec "$CLNT" ethtool -K "$V2" tx off tso off gso off gro off
ip netns exec "$SERV" ethtool -k "$V1" | grep -q 'tx-checksumming: off'
ip netns exec "$CLNT" ethtool -k "$V2" | grep -q 'tx-checksumming: off'

ip netns exec "$SERV" python3 -u "$PROBE" listener --count 4 --ready "$TMP/listener.ready" &
SPID=$!
for _ in {1..80}; do
    [[ -s "$TMP/listener.ready" ]] && break
    kill -0 "$SPID" || exit 1
    sleep .1
done
[[ -s "$TMP/listener.ready" ]] || exit 1

capture() {
  local variant="$1"
  local ready="$TMP/$variant.capture-ready"
  ip netns exec "$SERV" python3 -u "$PROBE" capture --interface "$V1" \
    --pcap "$TMP/$variant.pcap" --ready "$ready" > "$TMP/$variant.capturelog" 2>&1 &
  CPID=$!
  for i in {1..60}; do
    [[ -s "$ready" ]] && break
    kill -0 "$CPID" 2>/dev/null || { cat "$TMP/$variant.capturelog"; exit 1; }
    sleep .1
  done
  [[ -s "$ready" ]] || { cat "$TMP/$variant.capturelog"; exit 1; }
  ip netns exec "$CLNT" python3 -u "$PROBE" client
  sleep .8
  kill -TERM "$CPID" 2>/dev/null || true
  wait "$CPID" 2>/dev/null || true
  CPID=''
  cat "$TMP/$variant.capturelog"
  python3 "$PROBE" verify --pcap "$TMP/$variant.pcap" --variant "$variant"
}
echo 'nft_win4_probe=reference'
capture reference
cat > "$TMP/nft.rules" <<'NFT'
add table inet mneby_ig_win4_netns
add chain inet mneby_ig_win4_netns output { type filter hook output priority mangle; policy accept; }
add rule inet mneby_ig_win4_netns output ip saddr 192.0.2.1 tcp sport 443 tcp flags & (syn | ack) == (syn | ack) counter tcp window set 4
NFT
ip netns exec "$SERV" nft --check -f "$TMP/nft.rules"
ip netns exec "$SERV" nft -f "$TMP/nft.rules"
echo 'nft_win4_probe=clamped'
capture clamped
ip netns exec "$SERV" nft -a list table inet mneby_ig_win4_netns | grep -F 'tcp window set 4'
ip netns exec "$SERV" nft delete table inet mneby_ig_win4_netns
cat > "$TMP/ack.nft" <<'NFT'
add table inet mneby_ig_win4_netns
add chain inet mneby_ig_win4_netns output { type filter hook output priority mangle; policy accept; }
add rule inet mneby_ig_win4_netns output ip saddr 192.0.2.1 tcp sport 443 ct original packets < 64 tcp flags & ack == ack counter tcp window set 4
NFT
ip netns exec "$SERV" nft --check -f "$TMP/ack.nft"
ip netns exec "$SERV" nft -f "$TMP/ack.nft"
echo 'nft_win4_probe=ack_until_64_client_packets'
capture clamped
ip netns exec "$SERV" nft -a list table inet mneby_ig_win4_netns | grep -F 'ct original packets < 64'
ip netns exec "$SERV" nft delete table inet mneby_ig_win4_netns
echo 'nft_win4_probe=restored'
capture failbypass
! ip netns exec "$SERV" nft list table inet mneby_ig_win4_netns >/dev/null 2>&1
wait "$SPID"
SPID=''
echo 'nft_win4_synack_and_early_ack_test=PASS'
