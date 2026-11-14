#!/usr/bin/env python3
"""Bounded, read-only video-path inspection; print aggregates, never client IPs.

Only public TLS ClientHello/QUIC Initial metadata is inspected in memory.
Application data, credentials, DNS queries and packet captures are not stored.
Run concurrently on the two existing nodes during an Android playback attempt.
"""
import collections
import importlib.util
import json
import pathlib
import re
import socket
import ssl
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def emit(key, value):
    print(key + '=' + json.dumps(value, sort_keys=True), flush=True)


def run(args, timeout=12):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ''


def category(name):
    for suffix in ('googlevideo.com', 'youtube.com', 'ytimg.com', 'ggpht.com',
                   'googleapis.com', 'google.com', 'gvt1.com'):
        if name == suffix or name.endswith('.' + suffix):
            return suffix
    return 'other'


def relay_module():
    path = '/opt/mnebydns-youtube-quic-43612369808/relay.py'
    spec = importlib.util.spec_from_file_location('video_relay', path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def counters(role):
    unit = 'mnebydns-youtube-quic-' + role.lower() + '-43612369808.service'
    data = run(['journalctl', '--no-pager', '-o', 'cat', '-u', unit,
                '--since', '15 minutes ago', '-n', '1000'])
    lines = [x for x in data.splitlines() if '_active=' in x]
    # Print only numeric counters, never arbitrary journal messages.
    emit(role + '_QUIC_COUNTERS', [dict(re.findall(r'([a-z_]+)=(\d+)', x))
                                 for x in lines[-3:]])
    emit(role + '_QUIC_SERVICE', run(['systemctl', 'is-active', unit]).strip())


def inventory(role):
    for unit in ('nginx', 'mnebydns-dot', 'mnebydns-googlepilot', 'telegram-nfqws'):
        emit(role + '_SERVICE_' + unit, run(['systemctl', 'is-active', unit]).strip())
    for path in ('/etc/nginx/nginx.conf', '/etc/mnebydns-googlepilot/nginx.conf'):
        try:
            text = pathlib.Path(path).read_text()
        except OSError:
            continue
        # These lines are routing policy, not runtime client data.
        selected = [x.strip() for x in text.splitlines() if not x.lstrip().startswith('#')
                    and any(z in x for z in ('googlevideo', 'youtube', 'ytimg',
                                           'resolver ', 'proxy_connect_timeout',
                                           'proxy_timeout', 'proxy_buffer_size'))]
        emit(role + '_ROUTING_' + pathlib.Path(path).parent.name, selected[:30])
    core = pathlib.Path('/opt/mnebydns-dot/Corefile')
    if core.is_file():
        lines = core.read_text().splitlines()
        selected = []
        for i, line in enumerate(lines):
            if 'googlevideo' in line or 'youtubei' in line:
                selected.extend(x.strip() for x in lines[max(0, i - 1):i + 5])
        emit(role + '_VIDEO_DNS_POLICY', selected[:60])
    for path in ('/var/log/nginx/error.log', '/var/log/mnebydns-googlepilot-error.log'):
        if not pathlib.Path(path).is_file():
            continue
        tail = run(['tail', '-n', '300', path])
        emit(role + '_ERROR_COUNTS_' + pathlib.Path(path).name,
             {s: tail.count(s) for s in ('timed out', 'Connection refused',
              'Network is unreachable', 'could not be resolved', 'no live upstreams')})
    rules = run(['nft', '-a', 'list', 'chain', 'inet', 'telegram_nfqws', 'post'])
    emit(role + '_NFQUEUE_443_RULES', [re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_REDACTED', x.strip())
         for x in rules.splitlines() if 'tcp sport 443' in x and 'queue' in x][:6])
    ping = run(['ping', '-n', '-c', '6', '-i', '0.3', '-W', '1', '-s', '1200',
                '10.66.77.1' if role == 'RU' else '10.66.77.2'], timeout=10)
    emit(role + '_WG_PING', [x for x in ping.splitlines()
                            if 'packet loss' in x or 'min/avg/max' in x])


def observe(role, seconds, mod):
    stats = collections.Counter()
    hellos = collections.Counter()
    google_services = collections.Counter()
    tcp = {}
    quic = {}
    video_hosts = set()
    ports = {443, 15449, 19444}
    # ETH_P_ALL is needed to observe outgoing packets as well as ingress.
    s = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    s.settimeout(0.25)
    deadline = time.monotonic() + seconds

    def found(name, label):
        if not name:
            return
        kind = category(name)
        hellos[label + '_' + kind] += 1
        if kind in ('googleapis.com', 'google.com', 'googlevideo.com'):
            google_services[label + '_' + name] += 1
        if kind == 'googlevideo.com' and re.fullmatch(r'[a-z0-9.-]{1,253}', name):
            video_hosts.add(name)

    emit(role + '_OBSERVE_READY_SECONDS', seconds)
    try:
        while time.monotonic() < deadline:
            try:
                packet, addr = s.recvfrom(12288)
            except socket.timeout:
                continue
            if len(packet) < 28 or packet[0] >> 4 != 4:
                continue
            ihl = (packet[0] & 15) * 4
            if ihl < 20 or len(packet) < ihl + 8:
                continue
            if struct.unpack_from('!H', packet, 6)[0] & 0x3fff:
                stats['ipv4_fragment_seen'] += 1
                continue
            proto = packet[9]
            if proto not in (6, 17):
                continue
            body = packet[ihl:]
            sport, dport = struct.unpack_from('!HH', body)
            if sport not in ports and dport not in ports:
                continue
            iface = 'wg' if addr[0] == 'tg-relay' else ('lo' if addr[0] == 'lo' else 'public')
            direction = 'to' if dport in ports else 'from'
            port = dport if dport in ports else sport
            label = iface + '_' + str(port) + '_' + direction
            key = (packet[12:20], sport, dport)
            stats[label + '_packets'] += 1
            if len(tcp) + len(quic) > 2048:
                tcp.clear()
                quic.clear()
            if proto == 6:
                if len(body) < 20:
                    continue
                offset = (body[12] >> 4) * 4
                if offset < 20 or offset > len(body):
                    continue
                flags = body[13]
                for bit, tag in ((2, 'syn'), (4, 'rst'), (1, 'fin')):
                    if flags & bit:
                        stats[label + '_' + tag] += 1
                data = body[offset:]
                stats[label + '_payload_bytes'] += len(data)
                if direction != 'to' or not data:
                    continue
                seq = struct.unpack_from('!I', body, 4)[0]
                state = tcp.get(key)
                if state is None and data.startswith(b'\x16\x03'):
                    state = (seq, {})
                    tcp[key] = state
                if state:
                    start, pieces = state
                    delta = (seq - start) & 0xffffffff
                    if delta > 8192:
                        continue
                    pieces[delta] = data[:8192]
                    assembled = bytearray()
                    for pos, content in sorted(pieces.items()):
                        if pos > len(assembled):
                            break
                        assembled.extend(content[max(0, len(assembled) - pos):])
                    if len(assembled) >= 5:
                        size = int.from_bytes(assembled[3:5], 'big')
                        if size <= 8192 and len(assembled) >= size + 5:
                            found(mod.tls_hello_sni(bytes(assembled[5:5 + size])), label + '_tcp')
                            tcp.pop(key, None)
            else:
                data = body[8:]
                stats[label + '_udp_bytes'] += len(data)
                stats[label + '_udp_length_' + str(len(data))] += 1
                if direction != 'to' or len(data) < 5 or not data[0] & 0x80:
                    continue
                version = data[1:5].hex()
                stats[label + '_udp_version_' + version] += 1
                fragments = mod.initial_crypto_fragments(data)
                if not fragments:
                    stats[label + '_initial_unreadable'] += 1
                    continue
                parts = quic.setdefault(key, {})
                parts.update(fragments)
                hello, complete = mod.contiguous_hello(parts)
                if complete:
                    name = mod.tls_hello_sni(hello)
                    found(name, label + '_quic')
                    if name and not mod.allowed(name):
                        stats[label + '_hello_not_allowlisted_' + category(name)] += 1
                    quic.pop(key, None)
    finally:
        s.close()
    emit(role + '_TRAFFIC', dict(stats))
    emit(role + '_HELLO_CATEGORIES', dict(hellos))
    emit(role + '_PUBLIC_GOOGLE_SERVICE_HELLOS', dict(google_services))
    emit(role + '_VIDEO_HOST_COUNT', len(video_hosts))
    return video_hosts


def probe(role, hosts):
    for index, name in enumerate(['youtubei.googleapis.com', 'www.youtube.com'] + sorted(hosts)[:2]):
        for label, ip in [('loopback', '127.0.0.1')] + ([('wg_de', '10.66.77.1')] if role == 'RU' else []):
            started = time.monotonic()
            try:
                with socket.create_connection((ip, 443), timeout=5) as raw:
                    raw.settimeout(5)
                    with ssl.create_default_context().wrap_socket(raw, server_hostname=name):
                        result = 'TLS_OK'
            except (OSError, ssl.SSLError) as ex:
                result = type(ex).__name__
            emit(role + '_TLS_' + str(index) + '_' + category(name) + '_' + label,
                 {'result': result, 'seconds': round(time.monotonic() - started, 3)})


def main():
    role = sys.argv[1]
    if role not in ('RU', 'DE'):
        raise SystemExit('role must be RU or DE')
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 90
    if not 5 <= seconds <= 120:
        raise SystemExit('observation must be 5..120 seconds')
    mod = relay_module()
    inventory(role)
    counters(role)
    hosts = observe(role, seconds, mod)
    counters(role)
    probe(role, hosts)
    emit(role + '_READONLY_COMPLETE', True)


if __name__ == '__main__':
    main()
