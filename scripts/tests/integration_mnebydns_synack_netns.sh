#!/usr/bin/env bash
# Runs ONLY inside newly created Linux network namespaces on a disposable CI VM.
# No firewall rules outside the test server namespace. Requires CAP_NET_ADMIN.
set -Eeuo pipefail
[[ "$(id -u)" -eq 0 ]] || { echo 'Run as root on disposable CI runner' >&2; exit 2; }
for bin in ip iptables tcpdump python3 timeout; do command -v "$bin" >/dev/null; done
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROBE="$ROOT/scripts/mnebydns_synack_netns_probe.py"
WORK="$(mktemp -d)"
NS_SERVER="mdns_srv_$$"
NS_CLIENT="mdns_cli_$$"
VETH_SERVER="mns$$"
VETH_CLIENT="mnc$$"
SERVER_PID=''
QUEUE_PID=''
CAP_PID=''
cleanup() {
    set +e
    [[ -z "$CAP_PID" ]] || kill "$CAP_PID" 2>/dev/null
    [[ -z "$QUEUE_PID" ]] || kill "$QUEUE_PID" 2>/dev/null
    [[ -z "$SERVER_PID" ]] || kill "$SERVER_PID" 2>/dev/null
    [[ -z "$CAP_PID" ]] || wait "$CAP_PID" 2>/dev/null
    [[ -z "$QUEUE_PID" ]] || wait "$QUEUE_PID" 2>/dev/null
    [[ -z "$SERVER_PID" ]] || wait "$SERVER_PID" 2>/dev/null
    ip netns del "$NS_CLIENT" 2>/dev/null
    ip netns del "$NS_SERVER" 2>/dev/null
    rm -rf -- "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"
ip link add "$VETH_SERVER" type veth peer name "$VETH_CLIENT"
ip link set "$VETH_SERVER" netns "$NS_SERVER"
ip link set "$VETH_CLIENT" netns "$NS_CLIENT"
ip -n "$NS_SERVER" address add 192.0.2.1/24 dev "$VETH_SERVER"
ip -n "$NS_CLIENT" address add 192.0.2.2/24 dev "$VETH_CLIENT"
ip -n "$NS_SERVER" link set "$VETH_SERVER" up
ip -n "$NS_CLIENT" link set "$VETH_CLIENT" up
ip -n "$NS_SERVER" link set lo up
ip -n "$NS_CLIENT" link set lo up

# This listener cannot serve Internet traffic (192.0.2.0/24 in an isolated ns).
ip netns exec "$NS_SERVER" python3 -u "$PROBE" listener --count 3 --ready "$WORK/listener.ready" &
SERVER_PID=$!
for _ in {1..70}; do
    [[ -s "$WORK/listener.ready" ]] && break
    kill -0 "$SERVER_PID" 2>/dev/null || { echo 'Listener exited' >&2; exit 1; }
    sleep .1
done
[[ -s "$WORK/listener.ready" ]] || { echo 'Listener never ready' >&2; exit 1; }

capture() {
    local variant="$1"
    local pcap="$WORK/${variant}.pcap"
    ip netns exec "$NS_CLIENT" tcpdump -i "$VETH_CLIENT" -s 0 -U -w "$pcap" 'tcp and port 18443' >/dev/null 2>&1 &
    CAP_PID=$!
    sleep .6
    kill -0 "$CAP_PID" || { echo 'tcpdump failed' >&2; exit 1; }
    ip netns exec "$NS_CLIENT" python3 -u "$PROBE" client
    sleep .6
    kill "$CAP_PID" 2>/dev/null || true
    wait "$CAP_PID" 2>/dev/null || true
    CAP_PID=''
    python3 "$PROBE" verify --pcap "$pcap" --variant "$variant"
}

echo 'KERNEL-NETNS: reference path (no queue, original TCP SYN-ACK)'
capture reference

# Native libnetfilter_queue and kernel NFQA_CFG_F_FAIL_OPEN must be functional.
ip netns exec "$NS_SERVER" python3 -u "$PROBE" worker --ready "$WORK/queue.ready" &
QUEUE_PID=$!
for _ in {1..70}; do
    [[ -s "$WORK/queue.ready" ]] && break
    kill -0 "$QUEUE_PID" 2>/dev/null || { echo 'NFQUEUE worker exited; kernel FAIL_OPEN unavailable' >&2; exit 1; }
    sleep .1
done
[[ -s "$WORK/queue.ready" ]] || { echo 'Native NFQUEUE not ready' >&2; exit 1; }
RULE=(-s 192.0.2.1 -d 192.0.2.2 -p tcp --sport 18443 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 211 --queue-bypass)
ip netns exec "$NS_SERVER" iptables -w -t mangle -I OUTPUT 1 "${RULE[@]}"
ip netns exec "$NS_SERVER" iptables -w -t mangle -C OUTPUT "${RULE[@]}"

echo 'KERNEL-NETNS: modified SYN-ACK via native libnetfilter_queue'
capture clamped

# Queue daemon is stopped while the exact namespace rule is still installed.
# --queue-bypass must preserve ordinary TCP connectivity with no listener.
kill "$QUEUE_PID"
wait "$QUEUE_PID" 2>/dev/null || true
QUEUE_PID=''
echo 'KERNEL-NETNS: bypass after queue-handler termination'
capture failbypass

ip netns exec "$NS_SERVER" iptables -w -t mangle -D OUTPUT "${RULE[@]}"
if ip netns exec "$NS_SERVER" iptables -w -t mangle -C OUTPUT "${RULE[@]}" 2>/dev/null; then
    echo 'FAIL: scoped queue rule survived rollback' >&2
    exit 1
fi
wait "$SERVER_PID"
SERVER_PID=''
echo 'KERNEL-NETNS=PASS native NFQUEUE, on-wire SYN-ACK+checksum, handler-death bypass, rollback'
