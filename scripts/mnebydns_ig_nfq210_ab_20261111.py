#!/usr/bin/env python3
"""DE TCP443 NFQUEUE210 narrow A/B/A canary: source-scoped, short, revert-only.

Only marks DE TCP443 replies to the specific authenticated SSH peer so the
existing queue210 bitmask rule skips them during phase B. Does not alter
Nginx, CoreDNS, DNS records, packet payload, or other peer traffic.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

DE = '89.125.90.101'
TABLE = 'mneby_ig_q210_ab_20261111'
UNIT = 'mneby-ig-q210-ab-20261111'
MARK_BIT = 0x40000000
WINDOW = 16
STABLE = Path('/opt/mnebydns-stable-checkpoints/current')
NGINX = Path('/etc/nginx/nginx.conf')
CORE = Path('/opt/mnebydns-dot/Corefile')


def run(args, *, input=None, timeout=20, check=True):
    p = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} exit={p.returncode}')
    return p


def stable_config():
    current = Path(STABLE.read_text().strip())
    if not current.is_dir():
        raise RuntimeError('stable directory missing')
    for live, file in ((NGINX, 'nginx.stable'), (CORE, 'dns.stable')):
        if not (current / file).is_file() or live.read_bytes() != (current / file).read_bytes():
            raise RuntimeError('stable config drift: ' + file)
    return True


def queue_priority():
    j = json.loads(run(['nft', '-j', 'list', 'ruleset'], timeout=20).stdout)['nftables']
    chains = [x['chain'] for x in j if 'chain' in x and
              x['chain'].get('family') == 'inet' and
              x['chain'].get('table') == 'telegram_nfqws' and
              x['chain'].get('name') == 'post']
    if len(chains) != 1 or chains[0].get('hook') != 'postrouting':
        raise RuntimeError('queue hook changed')
    priority = int(chains[0]['prio'])
    rules = [x['rule'] for x in j if 'rule' in x and
             x['rule'].get('family') == 'inet' and
             x['rule'].get('table') == 'telegram_nfqws' and
             x['rule'].get('chain') == 'post']
    target = [rule for rule in rules if any(
        e.get('queue', {}).get('num') == 210 for e in rule.get('expr', []))]
    if len(target) != 1:
        raise RuntimeError('unique NFQUEUE210 rule missing')
    expressions = target[0]['expr']
    if not any('match' in e and str(MARK_BIT) in json.dumps(e) for e in expressions):
        raise RuntimeError('NFQUEUE210 mark-exclusion not verified')
    if not any('match' in e and '443' in json.dumps(e) for e in expressions):
        raise RuntimeError('NFQUEUE210 TCP443 guard missing')
    return priority


def peer_from_ssh():
    tokens = os.environ.get('SSH_CONNECTION', '').split()
    if len(tokens) != 4:
        raise RuntimeError('SSH_CONNECTION peer unavailable')
    ip = ipaddress.ip_address(tokens[0])
    if ip.version != 4 or not ip.is_global or str(ip) == DE:
        raise RuntimeError('SSH peer must be distinct public IPv4')
    return str(ip)


def candidate(peer, priority):
    return (f'add table inet {TABLE}\n'
            f'add chain inet {TABLE} post {{ type filter hook postrouting priority {priority - 1}; policy accept; }}\n'
            f'add rule inet {TABLE} post oifname "eth0" ip saddr {DE} ip daddr {peer} '
            'tcp sport 443 meta mark set meta mark | 0x40000000 counter '
            'comment "MNEBY_IG_Q210_AB_ONLY_PEER"\n')


def parse_summary(output, peer):
    counters = dict(syn=0, synack=0, client_ack=0, client_rst=0, server_rst=0)
    for line in output.splitlines():
        flags = re.search(r'\bFlags \[([^\]]+)\]', line)
        if not flags:
            continue
        fl = flags.group(1)
        inbound = re.search(r'\bIP ' + re.escape(peer) + r'\.\d+\s*>\s*' + re.escape(DE) + r'\.443:', line)
        outbound = re.search(r'\bIP ' + re.escape(DE) + r'\.443\s*>\s*' + re.escape(peer) + r'\.\d+:', line)
        if inbound:
            if 'S' in fl and '.' not in fl:
                counters['syn'] += 1
            if '.' in fl and 'S' not in fl:
                counters['client_ack'] += 1
            if 'R' in fl:
                counters['client_rst'] += 1
        if outbound:
            if 'S' in fl and '.' in fl:
                counters['synack'] += 1
            if 'R' in fl:
                counters['server_rst'] += 1
    return counters


def sample(phase, peer):
    command = ['tcpdump', '-i', 'any', '-n', '-nn', '-l', '-tt', '-s', '96', '-c', '200',
               f'tcp and host {peer} and host {DE} and port 443']
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.4)
    if process.poll() is not None:
        raise RuntimeError('tcpdump not started')
    print(f'ab_phase_{phase}=READY', flush=True)
    try:
        time.sleep(WINDOW)
    finally:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            output, stderr = process.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            output, stderr = process.communicate(timeout=3)
    summary = parse_summary(output, peer)
    for key, n in summary.items():
        print(f'ab_{phase}_{key}={n}', flush=True)
    print(f'ab_{phase}_capture_sanitized=true', flush=True)
    return summary


def table_exists():
    return run(['nft', 'list', 'table', 'inet', TABLE], check=False).returncode == 0


def cleanup():
    if table_exists():
        run(['nft', 'delete', 'table', 'inet', TABLE], timeout=15)
    ok = not table_exists()
    print('ab_cleanup=' + ('PASS' if ok else 'FAILED'), flush=True)
    if not ok:
        raise RuntimeError('nft table was not removed')


def main():
    if len(sys.argv) == 2 and sys.argv[1] == 'self-test':
        example = ('12:00 eth0 In IP 198.51.100.45.49100 > 89.125.90.101.443: Flags [S], length 0\n'
                   '12:00 eth0 Out IP 89.125.90.101.443 > 198.51.100.45.49100: Flags [S.], length 0\n'
                   '12:00 eth0 In IP 198.51.100.45.49100 > 89.125.90.101.443: Flags [.], length 0\n'
                   '12:00 eth0 In IP 198.51.100.46.49100 > 89.125.90.101.443: Flags [S], length 0\n')
        assert parse_summary(example, '198.51.100.45') == dict(syn=1, synack=1, client_ack=1, client_rst=0, server_rst=0)
        assert 'ip daddr 198.51.100.45' in candidate('198.51.100.45', 100)
        assert 'postrouting priority 99' in candidate('198.51.100.45', 100)
        assert 'meta mark set meta mark | 0x40000000' in candidate('198.51.100.45', 100)
        assert parse_summary(example, '198.51.100.46') == dict(syn=1, synack=0, client_ack=0, client_rst=0, server_rst=0)
        assert parse_summary('', '198.51.100.45')['syn'] == 0
        print('ab_local_self_test=PASS')
        return
    if os.geteuid() != 0 or os.environ.get('MNEBY_IG_AB_APPROVED') != 'YES':
        raise RuntimeError('requires root and explicit one-shot consent')
    address = run(['ip', '-4', '-o', 'addr', 'show']).stdout
    if not re.search(r'\s' + re.escape(DE) + r'/', address):
        raise RuntimeError('wrong server')
    for svc in ('nginx.service', 'mnebydns-dot.service', 'mnebydns-googlepilot.service'):
        if run(['systemctl', 'is-active', '--quiet', svc], check=False).returncode:
            raise RuntimeError('baseline service inactive: ' + svc)
    stable_config()
    if table_exists():
        raise RuntimeError('old A/B table exists')
    for name in ('mneby_ig_w4_20261111', 'mneby_ig_lite_w4_20261111_v5'):
        if run(['nft', 'list', 'table', 'inet', name], check=False).returncode == 0:
            raise RuntimeError('another Instagram canary active')
    if run(['systemctl', 'is-active', '--quiet', UNIT + '.timer'], check=False).returncode == 0:
        raise RuntimeError('old watchdog still armed')
    peer = peer_from_ssh()
    priority = queue_priority()
    print('ab_existing_nfqueue210_priority_verified=true', flush=True)
    rules = candidate(peer, priority)
    run(['nft', '--check', '-f', '-'], input=rules)
    print('ab_candidate_nft_syntax_verified=true')
    a = sample('A1', peer)
    if a['syn'] == 0:
        print('ab_peer_ip_match=FAILED_ABORT_BEFORE_CHANGE', flush=True)
        raise RuntimeError('probe source differs from SSH public peer: invalid A/B')
    print('ab_peer_ip_match=CONFIRMED', flush=True)
    run(['systemd-run', '--quiet', '--collect', '--unit', UNIT, '--on-active=95s',
         '/usr/sbin/nft', 'delete', 'table', 'inet', TABLE])
    if run(['systemctl', 'is-active', '--quiet', UNIT + '.timer'], check=False).returncode:
        raise RuntimeError('independent rollback watchdog absent')
    print('ab_independent_rollback_armed=true', flush=True)
    try:
        run(['nft', '-f', '-'], input=rules)
        if not table_exists():
            raise RuntimeError('A/B table installation not visible')
        b = sample('B', peer)
        table = run(['nft', '-a', 'list', 'table', 'inet', TABLE]).stdout
        hit = re.search(r'counter packets (\d+) bytes', table)
        if hit is None:
            raise RuntimeError('A/B mark counter missing')
        print('ab_B_marked_packets=' + hit.group(1), flush=True)
        cleanup()
        a2 = sample('A2', peer)
    finally:
        cleanup()
    stable_config()
    for svc in ('nginx.service', 'mnebydns-dot.service', 'mnebydns-googlepilot.service'):
        if run(['systemctl', 'is-active', '--quiet', svc], check=False).returncode:
            raise RuntimeError('postcheck service inactive: ' + svc)
    print('ab_config_original=true', flush=True)
    print('ab_services_active=true', flush=True)
    print('ab_android_validation=NOT_TESTED', flush=True)
    print('ab_interpretation=TRANSPORT_ONLY_COMPARE_A1_B_A2', flush=True)


if __name__ == '__main__':
    main()
