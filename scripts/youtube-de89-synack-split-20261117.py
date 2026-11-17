#!/usr/bin/env python3
"""Temporary source-scoped TCP split handshake test. Independent cleanup armed first."""
import hashlib, importlib.util, ipaddress, json, os, pathlib, re, subprocess, sys, time
ROOT=pathlib.Path(sys.argv[2]).resolve()
if not re.fullmatch(r'/run/mnebydns-synsplit-[0-9]+-[0-9]+',str(ROOT)):raise RuntimeError('BAD_ROOT')
CHAIN=['inet','telegram_nfqws','post'];TAG='mnebydns_youtube_synsplit_test'
FILES=['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf','/etc/zapret2/telegram-nfqws.conf','/usr/local/sbin/telegram-foreign-nfqws-rules']
def cmd(a,timeout=12):
    p=subprocess.run(a,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError('COMMAND_FAILED_'+pathlib.Path(a[0]).name+'_'+str(p.returncode))
    return p.stdout
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
def rules():return [x['rule'] for x in json.loads(cmd(['nft','-j','-a','list','chain',*CHAIN]))['nftables'] if 'rule' in x]
def hashes():return {p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in FILES}
def clear_rules():
    for r in rules():
        if r.get('comment')==TAG:
            emit('SYNSPLIT_RULE_COUNTER',[x['counter'] for x in r['expr'] if 'counter' in x])
            cmd(['nft','delete','rule',*CHAIN,'handle',str(r['handle'])])
    if any(r.get('comment')==TAG for r in rules()):raise RuntimeError('CLEANUP_FAILED')
def cleanup():
    clear_rules()
    subprocess.run(['systemctl','stop','mnebydns-synsplit-nfq-'+ROOT.name.removeprefix('mnebydns-synsplit-')],capture_output=True,timeout=10)
    old=ROOT/'HASHES.json'
    if old.exists() and json.loads(old.read_text())!=hashes():raise RuntimeError('PROTECTED_CONFIG_CHANGED')
    emit('SYNSPLIT_REMOVED_CONFIG_UNCHANGED',True)
def add_rule(addr):
    ip=ipaddress.ip_address(addr)
    if ip.version!=4 or not ip.is_global:raise RuntimeError('NONPUBLIC_SOURCE')
    args=['nft','insert','rule',*CHAIN,'oifname','eth0','ip','saddr','89.125.90.101','ip','daddr',str(ip),'tcp','sport','443','tcp','flags','&','(','syn','|','ack',')','==','(','syn','|','ack',')','meta','mark','&','0x40000000','==','0','counter','queue','num','211','bypass','comment',TAG]
    cmd(['nft','-c',*args[1:]]);cmd(args)
    if rules()[0].get('comment')!=TAG:raise RuntimeError('RULE_NOT_FIRST')
def prepare():
    if os.geteuid()!=0:raise RuntimeError('ROOT_REQUIRED')
    if any(r.get('comment')==TAG for r in rules()):raise RuntimeError('EXISTING_TEST')
    if not any(r.get('comment')=='mnebyvpn_de_standard_synack' for r in rules()):raise RuntimeError('STANDARD_GUARD_MISSING')
    lua=pathlib.Path('/opt/zapret2/lua/zapret-antidpi.lua')
    if 'function synack_split(' not in lua.read_text():raise RuntimeError('SYNSPLIT_NOT_INSTALLED')
    if any(line.split()[0]=='211' for line in pathlib.Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines()):raise RuntimeError('QUEUE_211_BUSY')
    (ROOT/'HASHES.json').write_text(json.dumps(hashes()))
    suffix=ROOT.name.removeprefix('mnebydns-synsplit-')
    # Cleanup is independent of this SSH session and is armed before rule insertion.
    cmd(['systemd-run','--quiet','--collect','--unit=mnebydns-synsplit-clean-'+suffix,'--on-active=260s','/usr/bin/python3','-B',str(pathlib.Path(__file__).resolve()),'cleanup',str(ROOT)])
    cmd(['systemd-run','--quiet','--unit=mnebydns-synsplit-nfq-'+suffix,'--property=RuntimeMaxSec=270','--property=StandardOutput=null','--property=StandardError=null','/opt/zapret2/nfqws2','--qnum=211','--debug=0','--server','--lua-init=@/opt/zapret2/lua/zapret-lib.lua','--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua','--filter-tcp=443','--payload=empty','--lua-desync=synack_split:mode=syn'])
    time.sleep(1)
    cmd(['systemctl','is-active','--quiet','mnebydns-synsplit-nfq-'+suffix])
    runner=os.environ.get('SSH_CONNECTION','').split()[0]
    add_rule(runner);emit('SYNSPLIT_RUNNER_CONTROL_ARMED',True);emit('SYNSPLIT_MODE','syn')
def kernel_stats(addr):
    raw=cmd(['ss','-Htin','state','established','(','sport','=',':443','and','dst',addr,')'])
    rows=[]
    for line in raw.splitlines():
        got=re.search(r'bytes_received:(\d+)',line)
        if got:
            sent=re.search(r'bytes_sent:(\d+)',line)
            rows.append({'received':int(got[1]),'sent':int(sent[1]) if sent else 0})
    emit('PHONE_KERNEL_TCP_BYTES',rows[:64])
def phone():
    clear_rules()
    source=pathlib.Path('/run/mnebydns-w4-44047955995-1/PHONE_SOURCE.json')
    entry=json.loads(source.read_text())
    if not 0 <= time.time()-entry['observed_at'] < 1200:raise RuntimeError('STALE_CLIENT_SOURCE')
    kernel_stats(entry['address'])
    add_rule(entry['address']);emit('PHONE_SYNSPLIT_APPLIED',True)
    time.sleep(45)
    emit('PHONE_SYNSPLIT_OBSERVATION_SECONDS',45)
    kernel_stats(entry['address'])
    clear_rules()
if __name__=='__main__':
    mode=sys.argv[1]
    if mode=='prepare':
        try:prepare()
        except BaseException:cleanup();raise
    elif mode=='phone':
        try:phone()
        finally:cleanup()
    elif mode=='cleanup':cleanup()
    else:raise SystemExit(2)
