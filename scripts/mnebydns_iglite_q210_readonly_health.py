#!/usr/bin/env python3
"""Bounded read-only correlation of DE TCP/443 and NFQUEUE 210 runtime health.

Reads kernel queue stats, nft counters, /proc/net/netstat, TCP states and
packet *headers*. Never changes network rules, logs raw IPs, or logs payloads.
"""
from __future__ import annotations
import ipaddress
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time

DE="89.125.90.101"
DURATION=19
TCP=re.compile(r"\bIP (\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s*>\s*(\d{1,3}(?:\.\d{1,3}){3})\.(\d+): .*?\bFlags \[([^\]]+)\]")

def cmd(argv, timeout=10):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=True).stdout

def queue():
    entries=[line.split() for line in pathlib.Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines()]
    match=[x for x in entries if len(x)>=7 and x[0]=='210']
    if len(match)!=1:
        raise RuntimeError('NFQUEUE210 handler absent or ambiguous')
    x=match[0]
    return dict(queued=int(x[2]), dropped=int(x[5]), user_dropped=int(x[6]), idseq=int(x[7]) if len(x)>7 else -1)

def nft_counter():
    data=json.loads(cmd(['nft','-j','list','ruleset']))['nftables']
    matched=[]
    for item in data:
        r=item.get('rule', {})
        if r.get('family')!='inet' or r.get('table')!='telegram_nfqws' or r.get('chain')!='post':
            continue
        ex=r.get('expr',[])
        if any(e.get('queue',{}).get('num')==210 for e in ex):
            txt=json.dumps(ex)
            for guard in ('eth0','sport','443','reply','mark'):
                if guard not in txt:
                    raise RuntimeError('queue210 guard changed: '+guard)
            hits=[int(e['counter']['packets']) for e in ex if 'counter' in e]
            if len(hits)!=1:raise RuntimeError('queue210 counter ambiguous')
            matched.append(hits[0])
    if len(matched)!=1:raise RuntimeError('queue210 rule ambiguous')
    return matched[0]

def tcp_globals():
    lines=pathlib.Path('/proc/net/netstat').read_text().splitlines()
    result={}
    for a,b in zip(lines[::2],lines[1::2]):
        if a.startswith('TcpExt:') and b.startswith('TcpExt:'):
            result=dict(zip(a.split()[1:],map(int,b.split()[1:])))
    keys=('TCPSynRetrans','TCPTimeouts','ListenDrops','ListenOverflows','TCPReqQFullDrop','TCPReqQFullDoCookies')
    return {k:result.get(k,0) for k in keys}

def parse_headers(output,peer):
    d=dict(peer_syn=0,peer_synack=0,peer_ack=0,peer_rst=0,
           other_syn=0,other_synack=0,other_source_count=0)
    others=set()
    for ln in output.splitlines():
        m=TCP.search(ln)
        if not m: continue
        src,sp,dst,dp,flags=m.groups()
        if dst==DE and dp=='443':
            if 'S' in flags and '.' not in flags:
                if src==peer:d['peer_syn']+=1
                else:d['other_syn']+=1;others.add(src)
            if src==peer and '.' in flags and 'S' not in flags:d['peer_ack']+=1
            if src==peer and 'R' in flags:d['peer_rst']+=1
        if src==DE and sp=='443' and 'S' in flags and '.' in flags:
            if dst==peer:d['peer_synack']+=1
            else:d['other_synack']+=1
    d['other_source_count']=len(others)
    return d

def self_test():
    sample=('eth0 In IP 198.51.100.2.12345 > 89.125.90.101.443: Flags [S], length 0\n'
            'eth0 Out IP 89.125.90.101.443 > 198.51.100.2.12345: Flags [S.], length 0\n'
            'eth0 In IP 198.51.100.2.12345 > 89.125.90.101.443: Flags [.], length 0\n'
            'eth0 In IP 198.51.100.3.555 > 89.125.90.101.443: Flags [S], length 0\n')
    d=parse_headers(sample,'198.51.100.2')
    assert (d['peer_syn'],d['peer_synack'],d['peer_ack'],d['other_syn'],d['other_source_count'])==(1,1,1,1,1)
    assert parse_headers('','198.51.100.2')['peer_syn']==0
    print('q210_readonly_selftest=PASS')

def main():
    if len(sys.argv)==2 and sys.argv[1]=='self-test':
        self_test();return
    if os.geteuid()!=0:raise RuntimeError('read-only kernel counters require root')
    ssh=os.environ.get('SSH_CONNECTION','').split()
    if len(ssh)!=4:raise RuntimeError('SSH peer unavailable')
    peer=str(ipaddress.IPv4Address(ssh[0]))
    if not ipaddress.ip_address(peer).is_global:raise RuntimeError('SSH peer not public')
    if DE not in cmd(['ip','-4','-o','addr','show']):raise RuntimeError('not the expected DE server')
    route=cmd(['ip','-4','route','get',peer,'from',DE])
    if not re.search(r'\bdev eth0\b',route):raise RuntimeError('peer egress route is not eth0')
    if not cmd(['ss','-ltnH','sport','=',' :443'.strip()]).strip():
        raise RuntimeError('DE TCP443 listener absent')
    before_q=queue(); before_nft=nft_counter();before_tcp=tcp_globals()
    capture=subprocess.Popen(['tcpdump','-i','eth0','-n','-nn','-l','-tt','-s','96',
                              'tcp and host '+DE+' and port 443'],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    time.sleep(.35)
    if capture.poll() is not None:raise RuntimeError('capture unavailable')
    highest_queued=before_q['queued'];highest_peer_synrecv=0;sample_count=0
    print('q210_readonly_observer=READY',flush=True)
    try:
        until=time.monotonic()+DURATION
        while time.monotonic()<until:
            q=queue()
            highest_queued=max(highest_queued,q['queued'])
            try:
                sessions=cmd(['ss','-H','-tn','state','syn-recv','sport','=',':443'],timeout=3)
                highest_peer_synrecv=max(highest_peer_synrecv,sum(peer in ln for ln in sessions.splitlines()))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
            sample_count+=1
            time.sleep(.25)
    finally:
        if capture.poll() is None:capture.send_signal(signal.SIGINT)
        try:
            output,errors=capture.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            capture.kill();output,errors=capture.communicate(timeout=3)
    after_q=queue();after_nft=nft_counter();after_tcp=tcp_globals()
    for key,value in parse_headers(output,peer).items():
        print('q210_tcp_'+key+'='+str(value),flush=True)
    print('q210_runtime_sample_count='+str(sample_count),flush=True)
    print('q210_runtime_queue_high_watermark='+str(highest_queued),flush=True)
    print('q210_runtime_queue_start='+str(before_q['queued']),flush=True)
    print('q210_runtime_queue_end='+str(after_q['queued']),flush=True)
    for key in ('dropped','user_dropped','idseq'):
        print('q210_runtime_'+key+'_delta='+str(after_q[key]-before_q[key]),flush=True)
    print('q210_nft_global_counter_delta='+str(after_nft-before_nft),flush=True)
    print('q210_synrecv_peer_peak='+str(highest_peer_synrecv),flush=True)
    for key in before_tcp:
        print('q210_tcpext_global_'+key+'_delta='+str(after_tcp[key]-before_tcp[key]),flush=True)
    print('q210_counter_attribution_to_test_peer=UNVERIFIED',flush=True)
    print('q210_packet_payload_logged=false',flush=True)
    print('q210_server_changes=NONE',flush=True)
if __name__=='__main__':
    main()
