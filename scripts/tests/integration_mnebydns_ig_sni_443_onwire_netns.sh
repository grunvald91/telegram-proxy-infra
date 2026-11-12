#!/usr/bin/env bash
# 443 NFQUEUE packet-byte test: only local isolated IPv4 veth namespaces.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
for bin in ip iptables tcpdump ethtool python3; do command -v "$bin" >/dev/null; done
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
SERVER="ig443s_$$"
CLIENT="ig443c_$$"
SVETH="igs$$"
CVETH="igc$$"
SPID=''
QPID=''
CPID=''
cleanup() {
  set +e
  test -z "$CPID" || { kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; }
  test -z "$QPID" || { kill "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null; }
  test -z "$SPID" || { kill "$SPID" 2>/dev/null; wait "$SPID" 2>/dev/null; }
  ip netns del "$CLIENT" 2>/dev/null
  ip netns del "$SERVER" 2>/dev/null
  rm -rf -- "$WORK"
  true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
grep -qx 'PORT = 18443' "$ROOT/scripts/mnebydns_synack_netns_probe.py"
sed 's/^PORT = 18443$/PORT = 443/' "$ROOT/scripts/mnebydns_synack_netns_probe.py" > "$WORK/probe443.py"
grep -qx 'PORT = 443' "$WORK/probe443.py"
export PYTHONPATH="$ROOT/scripts"
ip netns add "$SERVER"
ip netns add "$CLIENT"
ip link add "$SVETH" type veth peer name "$CVETH"
ip link set "$SVETH" netns "$SERVER"
ip link set "$CVETH" netns "$CLIENT"
ip -n "$SERVER" address add 192.0.2.1/24 dev "$SVETH"
ip -n "$CLIENT" address add 192.0.2.2/24 dev "$CVETH"
ip -n "$SERVER" link set "$SVETH" up
ip -n "$CLIENT" link set "$CVETH" up
ip -n "$SERVER" link set lo up
ip -n "$CLIENT" link set lo up
ip netns exec "$SERVER" ethtool -K "$SVETH" tx off tso off gso off gro off
ip netns exec "$CLIENT" ethtool -K "$CVETH" tx off tso off gso off gro off
ip netns exec "$SERVER" ethtool -k "$SVETH" | grep -q 'tx-checksumming: off'
ip netns exec "$CLIENT" ethtool -k "$CVETH" | grep -q 'tx-checksumming: off'
ip netns exec "$SERVER" python3 -u "$WORK/probe443.py" listener --count 3 --ready "$WORK/listener.ready" &
SPID=$!
for _ in {1..70}; do
  test -s "$WORK/listener.ready" && break
  kill -0 "$SPID" 2>/dev/null || exit 1
  sleep .1
done
test -s "$WORK/listener.ready"
capture() {
  variant="$1"
  pcap="$WORK/$variant.pcap"
  ip netns exec "$CLIENT" tcpdump -i "$CVETH" -s 0 -U -w "$pcap" 'tcp and port 443' >/dev/null 2>&1 &
  CPID=$!
  sleep .6
  kill -0 "$CPID"
  ip netns exec "$CLIENT" python3 -u "$WORK/probe443.py" client
  sleep .6
  kill "$CPID" 2>/dev/null || true
  wait "$CPID" 2>/dev/null || true
  CPID=''
  python3 "$WORK/probe443.py" verify --pcap "$pcap" --variant "$variant"
}
echo 'ig443_onwire=reference'
capture reference
ip netns exec "$SERVER" env PYTHONPATH="$ROOT/scripts" READY="$WORK/queue.ready" python3 -u -c '
import os
from mnebydns_nfq_failopen import run_queue
from mnebydns_ig_sni_443_fragment_worker import transform
run_queue(211, lambda p: transform(p, peer="192.0.2.2", server="192.0.2.1"),
          ready_file=os.environ["READY"])
' &
QPID=$!
for _ in {1..70}; do
  test -s "$WORK/queue.ready" && break
  kill -0 "$QPID" 2>/dev/null || exit 1
  sleep .1
done
test -s "$WORK/queue.ready"
ip netns exec "$SERVER" iptables -w -t mangle -I OUTPUT 1 -s 192.0.2.1 -d 192.0.2.2 -p tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 211 --queue-bypass
echo 'ig443_onwire=window4'
capture clamped
kill "$QPID"
wait "$QPID" 2>/dev/null || true
QPID=''
echo 'ig443_onwire=failopen'
capture failbypass
ip netns exec "$SERVER" iptables -w -t mangle -D OUTPUT -s 192.0.2.1 -d 192.0.2.2 -p tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 211 --queue-bypass
wait "$SPID"
SPID=''
echo 'ig443_native_nfqueue_443_segment4_checksum_failopen=PASS'
