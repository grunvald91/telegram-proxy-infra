#!/usr/bin/env python3
"""Restore managed service A-addresses while preserving the complete DNS policy.

Fail closed on any drift. The previous and candidate Corefiles must differ
only by managed A-answer replacements. Validate the original 253-address
cutover, then include the 11 earlier RU service routes in the recovery.
No keys or policy
contents are printed. The existing guarded stage/checkpoint scripts do the
actual mutation, independent rollback and promotion.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

OLD = Path('/opt/mnebydns-fastpath/43603843149')
LIVE = Path('/opt/mnebydns-dot/Corefile')
ANSWER = re.compile(r'(?m)^(\s*answer\s+"\{\{ \.Name \}\}\s+\d+\s+IN\s+A\s+)(89\.125\.90\.101)(")\s*$')
RU_ANSWER = re.compile(r'(?m)^(\s*answer\s+"\{\{ \.Name \}\}\s+\d+\s+IN\s+A\s+)(188\.120\.254\.223)("[ \t]*)$')
RECOVERED_ANSWER = re.compile(r'(?m)^(\s*answer\s+"\{\{ \.Name \}\}\s+\d+\s+IN\s+A\s+)(89\.125\.90\.101)("[ \t]*)$')
SELECTED = ['www.youtube.com', 'youtubei.googleapis.com', 'www.googlevideo.com',
            'i.ytimg.com', 'chatgpt.com', 'claude.ai']


def restored(previous, cutover, live):
    verified, count = ANSWER.subn(lambda m: m.group(1) + '188.120.254.223' + m.group(3), previous)
    if count != 253 or verified != cutover:
        raise RuntimeError('ORIGINAL_CUTOVER_IS_NOT_THE_EXPECTED_253_A_ONLY_CHANGES')
    if live != cutover:
        raise RuntimeError('LIVE_DNS_DRIFT_REQUIRES_REVIEW_NO_CHANGE')
    if previous.count('template IN A ') != cutover.count('template IN A '):
        raise RuntimeError('DNS_TEMPLATE_STRUCTURE_DRIFT')
    candidate, recovered = RU_ANSWER.subn(lambda m: m.group(1) + '89.125.90.101' + m.group(3), live)
    if recovered != 264:
        raise RuntimeError('EXPECTED_264_CURRENT_MANAGED_A_ANSWERS')
    check, restored_count = RECOVERED_ANSWER.subn(lambda m: m.group(1) + '188.120.254.223' + m.group(3), candidate)
    if restored_count != 264 or check != live:
        raise RuntimeError('RECOVERY_CHANGED_NON_ADDRESS_POLICY')
    return candidate, recovered


def resource(role):
    available = next((int(x.split()[1]) // 1024 for x in Path('/proc/meminfo').read_text().splitlines()
                      if x.startswith('MemAvailable:')), None)
    print(role + '_RESOURCE=' + json.dumps({'load': os.getloadavg(), 'cpus': os.cpu_count(),
                                          'memory_available_mib': available}), flush=True)
    for unit in ['nginx', 'mnebydns-dot', 'mnebydns-googlepilot', 'mnebyvpn-vpn-provisioner',
                 'xray', 'mnebydns-youtube-quic-' + role.lower() + '-43612369808']:
        r = subprocess.run(['systemctl', 'is-active', unit], capture_output=True, text=True, timeout=5)
        print(role + '_SERVICE_' + unit + '=' + r.stdout.strip(), flush=True)
    config = Path('/etc/mnebyvpn/xray-canary.json')
    if config.is_file():
        data = json.loads(config.read_text())
        print(role + '_VPN_SHAPE=' + json.dumps({
            'inbounds': [{'protocol': x.get('protocol'), 'network': x.get('streamSettings', {}).get('network'),
                          'sniffing_enabled': x.get('sniffing', {}).get('enabled', False),
                          'route_only': x.get('sniffing', {}).get('routeOnly')}
                         for x in data.get('inbounds', [])],
            'outbound_protocols': [x.get('protocol') for x in data.get('outbounds', [])],
            'references_ru188': '188.120.254.223' in config.read_text()}), flush=True)
    r = subprocess.run(['ps', '-eo', 'comm=,pcpu=,pmem='], capture_output=True, text=True, timeout=5)
    rows = []
    for line in r.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] in ('xray', 'python3', 'nginx', 'nfqws2', 'telemt'):
            try:
                rows.append({'process': fields[0], 'cpu_percent': float(fields[1]), 'memory_percent': float(fields[2])})
            except ValueError:
                pass
    print(role + '_PROCESSES=' + json.dumps(sorted(rows, key=lambda x: x['cpu_percent'], reverse=True)[:12]), flush=True)


def plan(work):
    previous = (OLD / 'dns.before').read_text()
    cutover = (OLD / 'dns.pilot').read_text()
    current = LIVE.read_text()
    candidate, count = restored(previous, cutover, current)
    for name, content in [('dns.before', current), ('dns.pilot', candidate)]:
        p = work / name
        if p.exists():
            raise RuntimeError('REFUSE_EXISTING_PLAN_FILE')
        p.write_text(content)
        p.chmod(0o600)
    value = {'read_only': True, 'selected': SELECTED, 'selected_count': len(SELECTED),
             'expected_mapped_ipv4': '89.125.90.101', 'a_changes': count,
             'original_cutover_a_changes': 253, 'earlier_ru_a_routes': 11,
             'sha_before': hashlib.sha256(current.encode()).hexdigest(),
             'sha_pilot': hashlib.sha256(candidate.encode()).hexdigest()}
    (work / 'plan.json').write_text(json.dumps(value, indent=2) + '\n')
    (work / 'plan.json').chmod(0o600)
    print('RECOVERY_A_ONLY_PLAN=' + json.dumps(value, sort_keys=True), flush=True)


def selftest():
    old = '\n'.join('    answer "{{ .Name }} 20 IN A 89.125.90.101"' for _ in range(253)) + '\n'
    old += '\n'.join('    answer "{{ .Name }} 20 IN A 188.120.254.223"' for _ in range(11)) + '\n# unrelated policy\n'
    cutover = ANSWER.sub(lambda m: m.group(1) + '188.120.254.223' + m.group(3), old)
    candidate, count = restored(old, cutover, cutover)
    assert count == 264 and '188.120.254.223' not in candidate
    assert candidate.endswith('# unrelated policy\n')
    assert ANSWER.sub(lambda m: m.group(1) + '188.120.254.223' + m.group(3), candidate) == cutover
    for args in [(old, cutover, cutover + '# new policy\n'),
                 (old, cutover + '# unexpected cutover\n', cutover),
                 (old.replace('89.125.90.101', '89.125.90.102', 1), cutover, cutover)]:
        try:
            restored(*args)
        except RuntimeError:
            continue
        raise AssertionError('Unrecognized drift was accepted')
    print('RECOVERY_ALL_264_A_AND_POLICY_DRIFT_TESTS=PASS')


if __name__ == '__main__':
    phase = sys.argv[1]
    if phase == 'selftest':
        selftest()
    elif phase == 'resource' and sys.argv[2] in ('RU', 'DE'):
        resource(sys.argv[2])
    elif phase == 'plan':
        folder = Path(sys.argv[2])
        if not re.fullmatch(r'/tmp/mnebydns-fastpath-[1-9][0-9]{8,12}', str(folder)):
            raise SystemExit('INVALID_WORK_FOLDER')
        plan(folder)
    else:
        raise SystemExit('INVALID_PHASE')
