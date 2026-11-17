#!/usr/bin/env python3
"""Temporary NFQUEUE differential. Never changes persistent rules or services."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

CHAIN = ['inet', 'telegram_nfqws', 'post']
TAG = 'mnebydns_youtube_nfq_ab_20261117'

def cmd(args, check=True):
    return subprocess.run(args, capture_output=True, text=True, check=check, timeout=12)

def rules():
    data = json.loads(cmd(['nft', '-j', '-a', 'list', 'chain', *CHAIN]).stdout)
    return [x['rule'] for x in data['nftables'] if 'rule' in x]

def ours():
    return [r for r in rules() if r.get('comment') == TAG]

def cleanup():
    for r in ours():
        for e in r.get('expr', []):
            if 'counter' in e:
                print('BYPASS_MATCHED_PACKETS='+str(e['counter']['packets']), flush=True)
        cmd(['nft', 'delete', 'rule', *CHAIN, 'handle', str(r['handle'])])
    if ours():
        raise RuntimeError('TEMPORARY_RULE_NOT_REMOVED')
    print('BYPASS_REMOVED=true', flush=True)

def inventory():
    for svc in ['nginx', 'mnebydns-googlepilot', 'mnebydns-dot', 'telegram-foreign-nfqws']:
        print('SERVICE_'+svc+'='+cmd(['systemctl','is-active',svc],False).stdout.strip())
    for r in rules():
        print('POST_RULE='+json.dumps(r, sort_keys=True))
    conf=Path('/etc/zapret2/telegram-nfqws.conf').read_text()
    for line in conf.splitlines():
        if line.startswith(('--qnum=', '--server', '--filter-', '--payload=', '--lua-desync=')):
            print('NFQ_OPTION='+line)
    for path in ['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf']:
        args=['nginx','-T'] if path=='/etc/nginx/nginx.conf' else ['nginx','-T','-c',path]
        result=cmd(args,False)
        print('NGINX_CONFIG_TEST='+str(result.returncode))
        for line in result.stdout.splitlines():
            # Allow-list only routing and transport directives; no customer DoT labels.
            if re.search(r'^\s*(?:preread_buffer_size|preread_timeout|proxy_buffer_size|proxy_timeout|proxy_connect_timeout|resolver|ssl_preread|proxy_pass|listen|tcp_nodelay|proxy_socket_keepalive|worker_connections)\s',line) or (re.search(r'googlevideo|youtubei|ytimg',line) and not re.search(r'dns\.mnebyvpn|token|secret',line,re.I)):
                print('NGINX_TRANSPORT='+line.strip())
    result=cmd(['nft','-j','list','ruleset'])
    data=json.loads(result.stdout)
    for entry in data['nftables']:
        r=entry.get('rule',{})
        if any(any(k in e for k in ['queue','mangle','drop','reject']) for e in r.get('expr',[])):
            # Output operators only, not IP sets, personal access records or packet content.
            print('OTHER_NETFILTER_OPERATOR='+json.dumps({'family':r.get('family'),'table':r.get('table'),'chain':r.get('chain'),'operators':[list(e)[0] for e in r.get('expr',[])]}))
    print('NFQUEUE_STATS='+Path('/proc/net/netfilter/nfnetlink_queue').read_text().strip())

def stage(runid):
    if not re.fullmatch(r'[0-9]{8,20}',runid):
        raise RuntimeError('INVALID_RUN_ID')
    if os.geteuid()!=0 or ours():
        raise RuntimeError('ROOT_OR_CLEAN_STATE_REQUIRED')
    if not any(any(e.get('queue',{}).get('num')==210 for e in r.get('expr',[])) for r in rules()):
        raise RuntimeError('EXPECTED_NFQUEUE210_ABSENT')
    for svc in ['nginx','mnebydns-googlepilot','mnebydns-dot','telegram-foreign-nfqws']:
        cmd(['systemctl','is-active','--quiet',svc])
    argv=['nft','insert','rule',*CHAIN,'oifname','eth0','ip','saddr','89.125.90.101','tcp','sport','443','counter','accept','comment',TAG]
    cmd([argv[0],'-c',*argv[1:]])
    # /run and this nft rule disappear at reboot; systemd removes the rule even if SSH dies.
    cmd(['systemd-run','--quiet','--unit=mnebydns-nfq-ab-'+runid,'--on-active=150s','--collect','/usr/bin/python3','-B',str(Path(__file__).resolve()),'cleanup'])
    try:
        cmd(argv)
        if len(ours())!=1 or rules()[0].get('comment')!=TAG:
            raise RuntimeError('BYPASS_NOT_FIRST')
    except BaseException:
        cleanup()
        raise
    print('TEMPORARY_NFQUEUE_BYPASS_ARMED_150S=true',flush=True)

if __name__=='__main__':
    mode=sys.argv[1]
    if mode=='inventory': inventory()
    elif mode=='stage': stage(sys.argv[2])
    elif mode=='cleanup': cleanup()
    else: raise SystemExit(2)
