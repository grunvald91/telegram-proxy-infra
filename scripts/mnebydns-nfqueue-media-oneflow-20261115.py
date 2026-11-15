#!/usr/bin/env python3
"""Extremely narrow DE89 NFQUEUE differential: only one RU188 test TCP flow.

The PUBLIC service port and all normal traffic are untouched.
The one rule is temporary and independently removed after 90 seconds.
"""
from __future__ import annotations
import os
import re
import subprocess
import sys
from pathlib import Path

TAG = 'MNEBYDNS_NFQUEUE_MEDIA_ONEFLOW_20261115'
CHAIN = ('inet','telegram_nfqws','post')
TARGET = '89.125.90.101'
PEER = '188.120.254.223'
PORT = 43161
TIMEOUT_UNIT = 'mnebydns-nfqueue-oneflow-revert-20261115'
HERE = '/tmp/mnebydns-nfqueue-oneflow-canary-20261115.py'

def command(args, *, check=True):
    return subprocess.run(args,capture_output=True,text=True,timeout=12,check=check)

def rules():
    return command(['nft','-a','list','chain',*CHAIN]).stdout

def find_handle():
    present=[x for x in rules().splitlines() if 'comment "'+TAG+'"' in x]
    if len(present)>1:
        raise RuntimeError('Unexpected multiple scoped test rules')
    if not present:
        return None
    m=re.search(r'# handle (\d+)\s*$',present[0])
    if not m:
        raise RuntimeError('Missing scoped rule handle')
    return m.group(1)

def verify():
    if os.geteuid()!=0:
        raise RuntimeError('Root required')
    if not Path(HERE).is_file():
        raise RuntimeError('Missing installed transient cleanup script')
    if command(['systemctl','is-active','telegram-foreign-nfqws.service'],check=False).stdout.strip()!='active':
        raise RuntimeError('Expected active foreign NFQUEUE handler absent')
    q=Path('/proc/net/netfilter/nfnetlink_queue')
    if not q.is_file() or not any(x.split() and x.split()[0]=='210' for x in q.read_text().splitlines()):
        raise RuntimeError('Queue 210 has no actual user')
    chain=rules()
    queuers=[s for s in chain.splitlines() if 'tcp sport 443' in s and re.search(r'\bto\s+210\b',s)]
    if len(queuers)!=1 or 'bypass' not in queuers[0]:
        raise RuntimeError('Unexpected public HTTPS queue')
    if not Path('/sys/class/net/eth0').exists():
        raise RuntimeError('Unexpected public interface')
    print('NFQ_ONEFLOW_PRECHECK=PASS',flush=True)

def cleanup():
    handle=find_handle()
    if handle:
        command(['nft','delete','rule',*CHAIN,'handle',handle])
    if find_handle():
        raise RuntimeError('Scoped rule still present')
    print('NFQ_ONEFLOW_ONLY_TEMPORARY_RULE_REMOVED=PASS',flush=True)

def arm():
    verify()
    if find_handle():
        raise RuntimeError('Canary already active')
    timer=command(['systemctl','list-units','--all',TIMEOUT_UNIT+'.timer'],check=False).stdout
    if TIMEOUT_UNIT+'.timer' in timer:
        raise RuntimeError('Canary timer already exists')
    # Arm a systemd-managed cleanup timer before changing any netfilter rule.
    command(['systemd-run','--unit='+TIMEOUT_UNIT,'--on-active=90s','--collect',
             '/usr/bin/python3','-B',HERE,'cleanup'])
    try:
        command(['nft','insert','rule',*CHAIN,
                 'oifname','eth0','ip','saddr',TARGET,'ip','daddr',PEER,
                 'tcp','sport','443','tcp','dport',str(PORT),
                 'counter','return','comment',TAG])
        if not find_handle():
            raise RuntimeError('Scoped canary missing after insertion')
    except Exception:
        cleanup()
        raise
    print('NFQ_ONEFLOW_BYPASS_ARMED_ONLY_TEST_SOURCE_PORT='+str(PORT),flush=True)
    print('NFQ_ONEFLOW_INDEPENDENT_CLEANUP_SECONDS=90',flush=True)

if __name__=='__main__':
    if len(sys.argv)!=2 or sys.argv[1] not in ('preflight','arm','cleanup'):
        raise SystemExit(2)
    if sys.argv[1]=='preflight':
        verify()
    elif sys.argv[1]=='arm':
        arm()
    else:
        cleanup()
