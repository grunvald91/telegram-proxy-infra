#!/usr/bin/env python3
"""Observe rejected-name QUIC admissions on RU188 for a bounded window.

No proxy changes or packet files. Client endpoint tuples exist only in memory
to reconstruct a ClientHello and suppress established-flow packets. Output
contains aggregate domain counts, never client addresses or application data.
"""
import collections
import datetime
import hashlib
import importlib.util
import json
import pathlib
import re
import socket
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
UNIT = 'mnebydns-youtube-quic-ru-43612369808.service'
LIVE = pathlib.Path('/opt/mnebydns-youtube-quic-43612369808/relay.py')
EXPECTED = 'bde13ba42945a6489c7fdc235996ff9858961bde27e2881759dc24112122d46f'


def emit(key, value):
    print(key + '=' + json.dumps(value, sort_keys=True), flush=True)


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def counters():
    p = subprocess.run(['journalctl', '--no-pager', '-o', 'cat', '-u', UNIT,
                        '-n', '8'], text=True, capture_output=True, timeout=10,
                       check=True)
    lines = [x for x in p.stdout.splitlines() if 'youtube_quic_ru_active=' in x]
    return dict((k, int(v)) for k, v in re.findall(r'([a-z_]+)=(\d+)', lines[-1])) if lines else {}


def load_relay():
    if hashlib.sha256(LIVE.read_bytes()).hexdigest() != EXPECTED:
        raise RuntimeError('Live relay changed; inspect before observing')
    spec = importlib.util.spec_from_file_location('rejected_sni_live', LIVE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def observe(mod, seconds):
    stats = collections.Counter()
    denied = collections.Counter()
    allowed = collections.Counter()
    pending = {}
    admitted = {}
    unknown = set()
    rejected_flows = collections.defaultdict(set)
    destination = socket.inet_aton('188.120.254.223')
    with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,
                       socket.htons(0x0800)) as sniffer:
        sniffer.settimeout(0.25)
        emit('RU_REJECT_OBSERVATION_START_UTC', timestamp())
        emit('RU_REJECT_OBSERVATION_READY_SECONDS', seconds)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                packet, surface = sniffer.recvfrom(16384)
            except socket.timeout:
                continue
            if len(packet) < 28 or packet[0] >> 4 != 4 or packet[9] != 17:
                continue
            ihl = (packet[0] & 15) * 4
            if ihl < 20 or len(packet) < ihl + 8 or packet[16:20] != destination:
                continue
            frag = struct.unpack_from('!H', packet, 6)[0]
            if frag & 0x1fff:
                stats['noninitial_ipv4_fragments'] += 1
                continue
            sport, dport, size = struct.unpack_from('!HHH', packet, ihl)
            if dport != 443 or surface[0] == 'lo':
                continue
            stats['inbound_udp443_datagrams'] += 1
            if size < 8 or len(packet) < ihl + size:
                stats['truncated_udp_datagrams'] += 1
                continue
            data = packet[ihl + 8:ihl + size]
            key = (packet[12:16], sport)
            now = time.monotonic()
            if key in admitted and now - admitted[key] <= mod.IDLE_SECONDS:
                admitted[key] = now
                stats['observed_established_flow_datagrams'] += 1
                continue
            admitted.pop(key, None)
            if len(data) < 20 or len(data) > mod.MAX_DATAGRAM:
                stats['invalid_size_without_domain'] += 1
                continue
            if len(pending) + len(admitted) + len(unknown) > 2048:
                stats['observer_capacity_limit'] += 1
                break
            fragments = mod.initial_crypto_fragments(data)
            if not fragments:
                # A passive observer can join a pre-existing connection.
                # Such ciphertext must not be called a new proxy rejection.
                unknown.add(key)
                stats['unreadable_or_preexisting_flow_datagrams'] += 1
                pending.pop(key, None)
                continue
            state = pending.get(key)
            if state is None or now - state['created'] > 17:
                state = {'created': now, 'pieces': {}, 'packets': 0, 'bytes': 0}
                pending[key] = state
            state['packets'] += 1
            state['bytes'] += len(data)
            if state['packets'] > 8 or state['bytes'] > mod.MAX_PENDING_BYTES:
                stats['initial_assembly_capacity_limit'] += 1
                pending.pop(key, None)
                continue
            conflict = False
            for offset, content in fragments:
                previous = state['pieces'].get(offset)
                if previous is not None and previous != content:
                    conflict = True
                state['pieces'][offset] = content
            if conflict:
                stats['conflicting_initial_fragments'] += 1
                pending.pop(key, None)
                continue
            hello, complete = mod.contiguous_hello(state['pieces'])
            if not complete:
                continue
            pending.pop(key, None)
            name = mod.tls_hello_sni(hello)
            if not name:
                stats['complete_hello_without_readable_sni'] += 1
                continue
            if mod.allowed(name):
                admitted[key] = now
                allowed[name] += 1
            else:
                # A complete disallowed SNI is a policy denial, even when the
                # same handshake is retried. Counts mean attempts, not users.
                denied[name] += 1
                rejected_flows[name].add(key)
                if key in unknown:
                    stats['denied_sni_with_preexisting_flow_uncertainty'] += 1
        stats['incomplete_initial_flows_at_end'] = len(pending)
        emit('RU_REJECT_OBSERVATION_END_UTC', timestamp())
    rows = [{'hostname': name, 'hello_attempts': count,
             'distinct_flow_count': len(rejected_flows[name])}
            for name, count in sorted(denied.items())]
    emit('RU_REJECTED_SNI_JSON', rows)
    emit('RU_REJECT_UNIQUE_HOSTS', len(rows))
    emit('RU_REJECT_OBSERVATION_STATS', dict(stats))
    emit('RU_ALLOWED_NEW_HELLO_COUNT', sum(allowed.values()))


def main():
    seconds = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    if not 5 <= seconds <= 120:
        raise SystemExit('Observation must be 5..120 seconds')
    subprocess.run(['systemctl', 'is-active', '--quiet', UNIT], check=True)
    mod = load_relay()
    before = counters()
    emit('RU_REJECT_COUNTERS_BEFORE', before)
    observe(mod, seconds)
    # Housekeeping emits the actual rejection counters every 12 seconds.
    time.sleep(13)
    after = counters()
    emit('RU_REJECT_COUNTERS_AFTER', after)
    emit('RU_REJECT_COUNTER_DELTAS', {k: after[k] - before.get(k, 0)
         for k in after if k != 'youtube_quic_ru_active'})
    emit('RU_REJECT_OBSERVATION_SOURCE_STILL_MATCHES',
         hashlib.sha256(LIVE.read_bytes()).hexdigest() == EXPECTED)
    emit('RU_REJECT_OBSERVATION_READONLY_COMPLETE', True)


if __name__ == '__main__':
    main()
