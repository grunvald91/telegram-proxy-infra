#!/usr/bin/env python3
"""Verify committed AWG and optionally adapt the legacy peer monitor. Never expose keys."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROLE=sys.argv[1]
assert ROLE in ('RU','DE')
REPAIR=len(sys.argv)>2 and sys.argv[2]=='repair-monitor'
DIR='/opt/mnebydns-awg-prod-20261116'
BIN=DIR+'/bin'
env={**os.environ,'PATH':BIN+':'+os.environ.get('PATH','')}
def run(*args,timeout=15):
 return subprocess.run(args,capture_output=True,text=True,timeout=timeout,env=env)
def emit(k,v):print('AWG_VERIFY_'+ROLE+'_'+k+'='+json.dumps(v),flush=True)
for action in ('status','check'):
 p=run(DIR+'/manage.sh',action,ROLE)
 emit(action,{'rc':p.returncode,'result':p.stdout.strip()})
 assert p.returncode==0 and (action!='status' or '_ACTIVE=AWG' in p.stdout)
assert run('systemctl','is-enabled','mneby-awg-tg-relay.service').returncode==0
assert run('systemctl','is-enabled','wg-quick@tg-relay.service').stdout.strip()=='disabled'
emit('boot_configuration','AWG enabled; legacy WG disabled')
if ROLE=='DE' and REPAIR:
 p=Path('/usr/local/sbin/proxy-monitor.sh')
 old=p.read_text()
 needle='wg show tg-relay latest-handshakes'
 helper='/usr/local/sbin/proxy-monitor-tunnel-handshakes'
 body='''#!/usr/bin/env bash
set -euo pipefail
if systemctl is-active --quiet mneby-awg-tg-relay.service; then
  exec /opt/mnebydns-awg-prod-20261116/bin/awg show tg-relay latest-handshakes
fi
exec wg show tg-relay latest-handshakes
'''
 if helper not in old:
  assert old.count(needle)==1,'Unexpected monitor source; refusing edit'
  backup=Path('/var/backups/proxy-monitor-awg-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
  backup.mkdir(mode=0o700)
  target=backup/'proxy-monitor.sh';target.write_bytes(p.read_bytes());target.chmod(0o600)
  h=Path(helper);h.write_text(body);h.chmod(0o700)
  new=old.replace(needle,helper)
  tmp=p.with_name(p.name+'.awg-new');tmp.write_text(new);tmp.chmod(p.stat().st_mode & 0o777)
  assert run('bash','-n',str(tmp)).returncode==0
  tmp.replace(p)
  emit('monitor_backup',str(backup))
 assert run('bash','-n',str(p)).returncode==0
 q=run(helper)
 stamps=[int(l.split()[1]) for l in q.stdout.splitlines() if len(l.split())==2 and l.split()[1].isdigit()]
 assert q.returncode==0 and len(stamps)==1 and 0<=time.time()-stamps[0]<180
 emit('monitor_recognizes_awg',True)
 # Do not run the notification script: verification sends no Telegram messages.
for size in (32,1200):
 peer='10.66.77.1' if ROLE=='RU' else '10.66.77.2'
 p=run('ping','-n','-q','-M','do','-c','100','-i','0.2','-s',str(size),'-W','1',peer,timeout=30)
 m=re.search(r'(\d+) packets transmitted, (\d+) received, ([\d.]+)% packet loss',p.stdout)
 assert m,'No ping summary'
 emit('ping_'+str(size),{'sent':int(m[1]),'received':int(m[2]),'loss_pct':float(m[3])})
p=run('systemctl','show','mneby-awg-auto-rollback-20261116-r2.timer','-p','ActiveState,LastTriggerUSec,NextElapseUSecMonotonic')
emit('rescue_timer',p.stdout.strip())
