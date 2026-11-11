#!/usr/bin/env python3
"""Read-only inspection of live DE NFQUEUE210 worker and SYN-ACK handling.

Only prints booleans, counts and service state; no IPs, keys, file contents,
process arguments, packet data, or server modifications.
"""
from __future__ import annotations
import json
import os
import pathlib
import re
import subprocess
import sys

DE = '89.125.90.101'
CONFIG = pathlib.Path('/etc/zapret2/telegram-nfqws.conf')
UNITS = ('telegram-foreign-nfqws.service', 'telegram-nfqws.service')

def call(args, timeout=12):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)

def parse_flags(data):
    options=[ln.strip() for ln in data.splitlines() if ln.strip() and not ln.lstrip().startswith('#')]
    return dict(queue210='--qnum=210' in options,
                tcp443='--filter-tcp=443' in options,
                synack_split=any(x=='--lua-desync=synack_split' for x in options),
                payload_empty='--payload=empty' in options,
                payload_serverhello=any('tls_server_hello' in x for x in options),
                fake_reply=any(x.startswith('--lua-desync=fake:') for x in options))

def inspect_nft():
    p=call(['nft','-j','list','ruleset'])
    if p.returncode:
        raise RuntimeError('nft inspect failed')
    rules=json.loads(p.stdout)['nftables']
    matches=[]
    for entry in rules:
        r=entry.get('rule',{})
        if r.get('family')!='inet' or r.get('table')!='telegram_nfqws' or r.get('chain')!='post':
            continue
        if any(e.get('queue',{}).get('num')==210 for e in r.get('expr',[])):
            matches.append(r)
    if len(matches)!=1:
        print('nfq_live_nft_unique_queue210=false',flush=True)
        return
    r=matches[0]
    encoded=json.dumps(r['expr'])
    print('nfq_live_nft_unique_queue210=true',flush=True)
    for key,term in [('tcp_sport443','"sport"'),('ct_reply','"reply"'),('mark_guard','"mark"'),
                     ('eth0_route','"eth0"'),('queue_bypass','"bypass"')]:
        print('nfq_live_nft_'+key+'='+str(term in encoded).lower(),flush=True)
    c=[e['counter']['packets'] for e in r['expr'] if 'counter' in e]
    print('nfq_live_nft_queue_counter_present='+str(len(c)==1).lower(),flush=True)

def inspect_queue():
    file=pathlib.Path('/proc/net/netfilter/nfnetlink_queue')
    if not file.is_file():
        print('nfq_live_kernel_queue210_present=false',flush=True)
        return
    rows=[row.split() for row in file.read_text().splitlines()]
    hit=[r for r in rows if r and r[0]=='210']
    print('nfq_live_kernel_queue210_present='+str(len(hit)==1).lower(),flush=True)
    if len(hit)==1 and len(hit[0])>=7:
        print('nfq_live_kernel_queue210_pending='+hit[0][2],flush=True)
        print('nfq_live_kernel_queue210_kernel_dropped='+hit[0][5],flush=True)
        print('nfq_live_kernel_queue210_user_dropped='+hit[0][6],flush=True)

def main():
    if len(sys.argv)==2 and sys.argv[1]=='self-test':
        flags=parse_flags('--qnum=210\n--filter-tcp=443\n--payload=empty\n--lua-desync=synack_split\n')
        assert flags['queue210'] and flags['tcp443'] and flags['payload_empty'] and flags['synack_split']
        assert not flags['fake_reply']
        assert not parse_flags('--lua-desync=multidisorder:pos=2\n')['synack_split']
        print('nfq_live_offline_self_test=PASS')
        return
    if os.geteuid()!=0:
        raise RuntimeError('read-only inspection requires root')
    a=call(['ip','-4','-o','addr','show'])
    if a.returncode or DE not in a.stdout:
        raise RuntimeError('wrong machine')
    for unit in UNITS:
        short=unit.replace('.service','').replace('-','_')
        p=call(['systemctl','show',unit,'--property=LoadState,ActiveState,MainPID,ExecStart'])
        fields=dict(x.split('=',1) for x in p.stdout.splitlines() if '=' in x)
        print('nfq_live_'+short+'_loaded='+str(fields.get('LoadState')=='loaded').lower(),flush=True)
        print('nfq_live_'+short+'_active='+str(fields.get('ActiveState')=='active').lower(),flush=True)
        pid=fields.get('MainPID','0')
        print('nfq_live_'+short+'_pid_valid='+str(pid.isdigit() and int(pid)>0).lower(),flush=True)
        cmdline=''
        if pid.isdigit() and int(pid)>0:
            proc=pathlib.Path('/proc') / pid / 'cmdline'
            try:cmdline=proc.read_bytes().replace(b'\0',b' ').decode('utf-8','replace')
            except OSError:pass
        print('nfq_live_'+short+'_process_nfqws2='+str('nfqws2' in cmdline).lower(),flush=True)
        print('nfq_live_'+short+'_execstart_nfqws2='+str('nfqws2' in fields.get('ExecStart','')).lower(),flush=True)
        print('nfq_live_'+short+'_cmd_uses_config='+str(str(CONFIG) in cmdline).lower(),flush=True)
    print('nfq_live_config_present='+str(CONFIG.is_file()).lower(),flush=True)
    if CONFIG.is_file():
        cfg=CONFIG.read_text(encoding='utf-8',errors='replace')
        for name,enabled in parse_flags(cfg).items():
            print('nfq_live_config_'+name+'='+str(enabled).lower(),flush=True)
    inspect_nft()
    inspect_queue()
    print('nfq_live_readonly=true',flush=True)
    print('nfq_live_instagram_unblock=NOT_TESTED',flush=True)

if __name__=='__main__':
    main()
