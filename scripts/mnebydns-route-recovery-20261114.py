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
import socket
import ssl
import struct
import time

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
    if role == 'DE':
        pid = int(subprocess.check_output(['systemctl','show','--value','-p','MainPID','mnebydns-dot.service'],text=True).strip())
        args = Path('/proc/' + str(pid) + '/cmdline').read_bytes().split(b'\0')
        args = [x.decode() for x in args if x]
        if '-conf' in args:
            config = Path(args[args.index('-conf') + 1])
            if not config.is_absolute():
                config = Path('/proc/' + str(pid) + '/cwd').resolve() / config
        else:
            config = Path('/proc/' + str(pid) + '/cwd').resolve() / 'Corefile'
        print('DE_COREDNS_CONFIG_SOURCE=' + str(config), flush=True)
        print('DE_COREDNS_CONFIG_MATCHES_MANAGED_FILE=' + str(config.samefile(LIVE)), flush=True)
        print('DE_COREDNS_MANAGED_SHA256=' + hashlib.sha256(LIVE.read_bytes()).hexdigest(), flush=True)
        visible = Path('/proc/' + str(pid) + '/root') / str(config).lstrip('/')
        outside = LIVE.stat()
        inside = visible.stat()
        print('DE_COREDNS_PROCESS_VIEW=' + json.dumps({
            'same_inode': (outside.st_dev,outside.st_ino)==(inside.st_dev,inside.st_ino),
            'visible_sha256':hashlib.sha256(visible.read_bytes()).hexdigest(),
            'has_reload': 'reload 5s 1s' in visible.read_text(),
            'stdout':str(Path('/proc/' + str(pid) + '/fd/1').readlink())}), flush=True)
        properties = subprocess.check_output(['systemctl','show','mnebydns-dot.service',
            '-p','ReadOnlyPaths','-p','BindReadOnlyPaths','-p','RootDirectory',
            '-p','ProtectSystem','-p','PrivateMounts','-p','StandardOutput'],text=True)
        for line in properties.splitlines():
            print('DE_COREDNS_HARDENING=' + line, flush=True)
        for line in Path('/proc/' + str(pid) + '/mountinfo').read_text().splitlines():
            if '/opt/mnebydns-dot' in line:
                print('DE_COREDNS_MOUNT=' + line[:650], flush=True)
        journal = subprocess.run(['journalctl','--no-pager','-o','cat','-u','mnebydns-dot.service',
                                  '--since','25 minutes ago','-n','150'],capture_output=True,text=True,timeout=10).stdout
        for line in journal.splitlines():
            if 'plugin/reload' in line:
                print('DE_COREDNS_RELOAD=' + line[:500], flush=True)
        for ip in ['89.125.90.101','188.120.254.223']:
            print('DE_CURRENT_PUBLIC_DNS=' + json.dumps({'ingress':ip,'answers': dns_answers(ip,'www.youtube.com')}), flush=True)


def dns_answers(ip, host):
    def exact(s, n):
        value = b''
        while len(value) < n:
            block = s.recv(n - len(value))
            if not block:
                raise EOFError('short DNS response')
            value += block
        return value
    q = struct.pack('!HHHHHH', 0x4987, 256, 1, 0, 0, 0) + b''.join(bytes([len(x)]) + x.encode() for x in host.split('.')) + b'\0' + struct.pack('!HH', 1, 1)
    with socket.create_connection((ip,853),timeout=6) as raw:
        raw.settimeout(8)
        with ssl.create_default_context().wrap_socket(raw,server_hostname='dns.mnebyvpn.site') as tls:
            tls.sendall(len(q).to_bytes(2,'big') + q)
            data = exact(tls,int.from_bytes(exact(tls,2),'big'))
    def skip(off):
        for _ in range(128):
            n = data[off]
            if n & 192 == 192:
                return off + 2
            if n == 0:
                return off + 1
            off += n + 1
        raise ValueError('bad DNS name')
    off = 12
    for _ in range(struct.unpack_from('!H',data,4)[0]):
        off = skip(off) + 4
    result = []
    for _ in range(struct.unpack_from('!H',data,6)[0]):
        off = skip(off)
        kind, cls, ttl, n = struct.unpack_from('!HHIH',data,off)
        off += 10
        if kind == 1 and cls == 1 and n == 4:
            result.append(socket.inet_ntoa(data[off:off+n]))
        off += n
    return {'rcode':data[3] & 15,'a':result}


def verify(expected):
    if expected not in ('188.120.254.223','89.125.90.101'):
        raise ValueError('UNAPPROVED_EXPECTED_ADDRESS')
    deadline = time.monotonic() + 45
    last = {}
    while time.monotonic() < deadline:
        success = True
        for ip in ['89.125.90.101','188.120.254.223']:
            for host in SELECTED:
                if time.monotonic() >= deadline:
                    success = False
                    break
                try:
                    value = dns_answers(ip,host)
                except (OSError,EOFError,ValueError) as error:
                    value = {'error':type(error).__name__}
                last[ip + '/' + host] = value
                if value.get('rcode') != 0 or value.get('a') != [expected]:
                    success = False
        if success:
            print('RECOVERY_BOTH_PUBLIC_DOT_ENDPOINTS_VERIFIED=' + expected, flush=True)
            return
        print('RECOVERY_DNS_PROPAGATION=' + json.dumps(last,sort_keys=True), flush=True)
        time.sleep(2)
    raise RuntimeError('PUBLIC_DNS_DID_NOT_CONVERGE_' + json.dumps(last,sort_keys=True))


def restart_candidate(base):
    if os.geteuid() != 0 or not re.fullmatch(r'/opt/mnebydns-fastpath/[1-9][0-9]{8,12}',str(base)):
        raise RuntimeError('INVALID_RESTART_CONTEXT')
    current = Path('/opt/mnebydns-stable-checkpoints/current').read_text().strip()
    expected = (base / 'checkpoint.before').read_text().strip()
    if current != expected or not re.fullmatch(r'/opt/mnebydns-stable-checkpoints/[0-9]+',current):
        raise RuntimeError('RESTART_REFUSES_CHECKPOINT_DRIFT')
    stable = Path(current)
    subprocess.run(['sha256sum','-c','stable-manifest.sha256'],cwd=stable,
                   capture_output=True,check=True,timeout=10)
    for name, path in [('dns',base / 'dns.before'),('nginx',Path('/etc/nginx/nginx.conf')),
                       ('proxy',Path('/etc/mnebydns-googlepilot/nginx.conf'))]:
        if (stable / (name + '.stable')).read_bytes() != path.read_bytes():
            raise RuntimeError('RESTART_REFUSES_BASELINE_DRIFT')
    if LIVE.read_bytes() != (base / 'dns.pilot').read_bytes():
        raise RuntimeError('RESTART_REFUSES_CANDIDATE_DRIFT')
    plan_value = json.loads((base / 'plan.json').read_text())
    if hashlib.sha256(LIVE.read_bytes()).hexdigest() != plan_value['sha_pilot']:
        raise RuntimeError('RESTART_REFUSES_HASH_DRIFT')
    subprocess.run(['systemctl','is-active','--quiet','mnebydns-fastpath-rollback-' + base.name + '.timer'],check=True,timeout=5)
    subprocess.run(['systemctl','restart','mnebydns-dot.service'],check=True,timeout=25)
    subprocess.run(['systemctl','is-active','--quiet','mnebydns-dot.service'],check=True,timeout=5)
    print('RECOVERY_OWN_DNS_CONTROLLED_RESTART=COMPLETE',flush=True)


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
    elif phase == 'verify':
        verify(sys.argv[2])
    elif phase == 'restart':
        restart_candidate(Path(sys.argv[2]))
    elif phase == 'plan':
        folder = Path(sys.argv[2])
        if not re.fullmatch(r'/tmp/mnebydns-fastpath-[1-9][0-9]{8,12}', str(folder)):
            raise SystemExit('INVALID_WORK_FOLDER')
        plan(folder)
    else:
        raise SystemExit('INVALID_PHASE')
