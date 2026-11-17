#!/usr/bin/env python3
"""Source/port-scoped original SYNACK handling; no persistent configuration edit."""
import json,os,pathlib,re,subprocess,sys
CHAIN=['inet','telegram_nfqws','post']
TAG='mnebydns_youtube_original_synack_oneflow'
def cmd(a):return subprocess.run(a,check=True,text=True,capture_output=True,timeout=12).stdout
def rules():return [x['rule'] for x in json.loads(cmd(['nft','-j','-a','list','chain',*CHAIN]))['nftables'] if 'rule' in x]
def clean():
 for r in rules():
  if r.get('comment')==TAG:
   print('ONEFLOW_COUNTER='+json.dumps([e['counter'] for e in r['expr'] if 'counter' in e]),flush=True)
   cmd(['nft','delete','rule',*CHAIN,'handle',str(r['handle'])])
 if any(r.get('comment')==TAG for r in rules()):raise RuntimeError('CLEANUP_FAILED')
 print('ONEFLOW_REMOVED=true',flush=True)
def arm(runid):
 if os.geteuid()!=0 or not re.fullmatch('[0-9]{8,20}',runid):raise RuntimeError('BAD_CONTEXT')
 rr=rules()
 if any(r.get('comment')==TAG for r in rr):raise RuntimeError('EXISTING_TEST')
 if not any(r.get('comment')=='mnebyvpn_de_standard_synack' for r in rr):raise RuntimeError('EXPECTED_STANDARD_GUARD_MISSING')
 if not any(e.get('queue',{}).get('num')==210 for r in rr for e in r['expr']):raise RuntimeError('EXPECTED_QUEUE_MISSING')
 conf=pathlib.Path('/etc/zapret2/telegram-nfqws.conf').read_text()
 if '--server' not in conf or '--lua-desync=synack_split' not in conf:raise RuntimeError('EXPECTED_ORIGINAL_MODE_MISSING')
 cmd(['systemctl','is-active','--quiet','telegram-foreign-nfqws'])
 argv=['nft','insert','rule',*CHAIN,'oifname','eth0','ip','saddr','89.125.90.101','ip','daddr','188.120.254.223','tcp','sport','443','tcp','dport','49188','tcp','flags','&','(','syn','|','ack',')','==','(','syn','|','ack',')','meta','mark','&','0x40000000','==','0','counter','queue','num','210','bypass','comment',TAG]
 cmd(['nft','-c',*argv[1:]])
 cmd(['systemd-run','--quiet','--collect','--unit=youtube-oneflow-clean-'+runid,'--on-active=90s','/usr/bin/python3','-B',str(pathlib.Path(__file__).resolve()),'clean'])
 try:
  cmd(argv)
  if rules()[0].get('comment')!=TAG:raise RuntimeError('RULE_NOT_FIRST')
 except BaseException:
  clean();raise
 print('ORIGINAL_SYNACK_MODE_SCOPED_TO_RU188_PORT49188=true',flush=True)
if __name__=='__main__':
 if sys.argv[1]=='arm':arm(sys.argv[2])
 elif sys.argv[1]=='clean':clean()
 else:raise SystemExit(2)
