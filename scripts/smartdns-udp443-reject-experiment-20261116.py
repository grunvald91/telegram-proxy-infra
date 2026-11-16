"""Temporary public UDP443 reject, independent rollback, no listener restarts."""
import datetime,json,pathlib,subprocess,sys
TABLE='mnebydns_udp443_owner_exp_20261116';BASE=pathlib.Path('/run/'+TABLE);UNIT='mnebydns-udp443-owner-exp-revert-20261116'
def run(a,check=True,data=None):
 p=subprocess.run(a,input=data,capture_output=True,text=True,timeout=15)
 if check and p.returncode:raise RuntimeError(a[0]+' failed: '+p.stderr[-200:])
 return p

def state():
 j=json.loads(run(['nft','-j','-a','list','table','inet',TABLE]).stdout);rules=[x['rule'] for x in j['nftables'] if 'rule'in x];chain=next(x['chain'] for x in j['nftables'] if 'chain'in x)
 return {'chain':chain,'rules':rules}
mode=sys.argv[1]
if mode=='apply':
 allrules=json.loads(run(['nft','-j','list','ruleset']).stdout)['nftables'];assert not any(x.get('table',{}).get('name')==TABLE for x in allrules),'experiment table already exists'
 # Select an INPUT priority earlier than every current INPUT chain.
 priorities=[x['chain']['prio'] for x in allrules if x.get('chain',{}).get('hook')=='input' and isinstance(x['chain'].get('prio'),int)]
 priority=min([-100]+[p-10 for p in priorities]);route=json.loads(run(['ip','-j','route','get','1.1.1.1']).stdout)[0];dev=route['dev'];assert dev.replace('-','').replace('_','').isalnum()
 baseline={u:run(['systemctl','show',u,'-p','ActiveState','-p','MainPID']).stdout.strip() for u in ['nginx.service','mnebydns-googlepilot.service','mnebydns-dot.service','mnebyvpn-vpn-provisioner.service']}
 BASE.mkdir(mode=0o700,exist_ok=True);backup=BASE/'baseline.json';backup.write_text(json.dumps(baseline));backup.chmod(0o600)
 rollback=BASE/'rollback.sh';rollback.write_text('#!/bin/sh\n/usr/sbin/nft delete table inet '+TABLE+'\n');rollback.chmod(0o700)
 rules=f'table inet {TABLE} {{\n chain public_input {{\n type filter hook input priority {priority}; policy accept;\n iifname "{dev}" ip daddr 89.125.90.101 udp dport 443 counter reject with icmp type port-unreachable comment "owner temporary UDP443 TCP fallback test"\n }}\n}}\n'
 run(['nft','-c','-f','-'],data=rules)
 run(['systemd-run','--quiet','--unit='+UNIT,'--on-active=20m','/bin/sh',str(rollback)])
 try:run(['nft','-f','-'],data=rules)
 except Exception:
  run(['systemctl','stop',UNIT+'.timer'],check=False);raise
 out=state();out.update(applied=True,rollback_utc=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=20)).isoformat(),rollback_unit=UNIT+'.timer',interface=dev,prior_input_priorities=priorities,production_listeners_restarted=False)
 print(json.dumps(out))
elif mode=='verify':
 out=state();chain=out['chain'];assert chain['hook']=='input' and chain['prio']<=-100
 rules=out['rules'];assert len(rules)==1
 expressions=rules[0]['expr'];assert any('reject'in x for x in expressions)
 counters=[x['counter'] for x in expressions if 'counter'in x];assert counters and counters[0]['packets']>=1,'external test did not reach REJECT'
 baseline=json.loads((BASE/'baseline.json').read_text());now={u:run(['systemctl','show',u,'-p','ActiveState','-p','MainPID']).stdout.strip() for u in baseline};assert now==baseline,'listener processes changed during experiment'
 assert run(['systemctl','is-active',UNIT+'.timer']).stdout.strip()=='active'
 out.update(verified=True,listener_processes_unchanged=True,rollback_timer_active=True);print(json.dumps(out))
else:raise SystemExit('mode must be apply or verify')
