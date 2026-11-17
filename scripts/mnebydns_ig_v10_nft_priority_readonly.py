#!/usr/bin/env python3
"""Read-only DE NFQUEUE/mark ordering audit. Never logs IPs or full ruleset."""
import json
import os
import subprocess
import sys

def cmd(a):
    p=subprocess.run(a,capture_output=True,text=True,check=True,timeout=12)
    return p.stdout

def analyze(data):
    chains={}
    for item in data['nftables']:
        chain=item.get('chain')
        if chain and chain.get('family')=='inet' and chain.get('table')=='telegram_nfqws':
            chains[chain['name']]=dict(hook=chain.get('hook'),priority=chain.get('prio'))
    queue=[]
    for item in data['nftables']:
        rule=item.get('rule')
        if not rule or rule.get('family')!='inet' or rule.get('table')!='telegram_nfqws':
            continue
        if any(v.get('queue',{}).get('num')==210 for v in rule.get('expr',[])):
            queue.append(rule.get('chain'))
    print('priority_audit_nfqueue210_rules='+str(len(queue)),flush=True)
    for chain in sorted(set(queue)):
        c=chains.get(chain,{})
        print('priority_audit_nfqueue210_hook='+str(c.get('hook','UNKNOWN')),flush=True)
        print('priority_audit_nfqueue210_priority='+str(c.get('priority','UNKNOWN')),flush=True)
    print('priority_audit_candidate_mark_hook=postrouting',flush=True)
    print('priority_audit_candidate_mark_priority=100',flush=True)
    if len(queue)!=1:raise RuntimeError('unexpected live queue210 rule count')
    c=chains.get(queue[0],{})
    if c.get('hook')!='postrouting':
        print('priority_audit_mark_ordering=UNKNOWN_NON_POSTROUTING',flush=True)
        raise RuntimeError('unexpected NFQUEUE hook')
    priority=c.get('priority')
    if not isinstance(priority,int):
        print('priority_audit_mark_ordering=UNKNOWN_NUMERIC',flush=True)
    elif priority<=100:
        print('priority_audit_mark_ordering=MARK_TOO_LATE_OR_EQUAL',flush=True)
    else:
        print('priority_audit_mark_ordering=MARK_BEFORE_QUEUE',flush=True)
    print('priority_audit_server_modifications=NONE',flush=True)

def main():
    if os.geteuid()!=0:raise RuntimeError('root required to read live netfilter')
    if '89.125.90.101' not in cmd(['ip','-4','-o','addr','show']):
        raise RuntimeError('not DE')
    analyze(json.loads(cmd(['nft','-j','list','ruleset'])))

if __name__=='__main__':main()
