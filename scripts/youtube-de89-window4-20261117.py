#!/usr/bin/env python3
"""Temporary source-scoped SYNACK window test. Independent cleanup armed first."""
import hashlib, importlib.util, ipaddress, json, os, pathlib, re, subprocess, sys, time
ROOT=pathlib.Path(sys.argv[2]).resolve()
if not re.fullmatch(r'/run/mnebydns-w4-[0-9]+-[0-9]+',str(ROOT)):raise RuntimeError('BAD_ROOT')
CHAIN=['inet','telegram_nfqws','post'];TAG='mnebydns_youtube_window4_test'
FILES=['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf','/etc/zapret2/telegram-nfqws.conf','/usr/local/sbin/telegram-foreign-nfqws-rules']
def cmd(a,timeout=12):return subprocess.run(a,check=True,capture_output=True,text=True,timeout=timeout).stdout
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
def rules():return [x['rule'] for x in json.loads(cmd(['nft','-j','-a','list','chain',*CHAIN]))['nftables'] if 'rule' in x]
def hashes():return {p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in FILES}
def clear_rules():
    for r in rules():
        if r.get('comment')==TAG:
            emit('WINDOW4_RULE_COUNTER',[x['counter'] for x in r['expr'] if 'counter' in x])
            cmd(['nft','delete','rule',*CHAIN,'handle',str(r['handle'])])
    if any(r.get('comment')==TAG for r in rules()):raise RuntimeError('CLEANUP_FAILED')
def cleanup():
    clear_rules()
    subprocess.run(['systemctl','stop','mnebydns-w4-nfq-'+ROOT.name.removeprefix('mnebydns-w4-')],capture_output=True,timeout=10)
    old=ROOT/'HASHES.json'
    if old.exists() and json.loads(old.read_text())!=hashes():raise RuntimeError('PROTECTED_CONFIG_CHANGED')
    emit('WINDOW4_REMOVED_CONFIG_UNCHANGED',True)
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
    if 'function wsize(' not in lua.read_text():raise RuntimeError('WSIZE_NOT_INSTALLED')
    if any(line.split()[0]=='211' for line in pathlib.Path('/proc/net/netfilter/nfnetlink_queue').read_text().splitlines()):raise RuntimeError('QUEUE_211_BUSY')
    (ROOT/'HASHES.json').write_text(json.dumps(hashes()))
    suffix=ROOT.name.removeprefix('mnebydns-w4-')
    # Cleanup is independent of this SSH session and is armed before rule insertion.
    cmd(['systemd-run','--quiet','--collect','--unit=mnebydns-w4-clean-'+suffix,'--on-active=240s','/usr/bin/python3','-B',str(pathlib.Path(__file__).resolve()),'cleanup',str(ROOT)])
    cmd(['systemd-run','--quiet','--unit=mnebydns-w4-nfq-'+suffix,'--property=RuntimeMaxSec=250','--property=StandardOutput=null','--property=StandardError=null','/opt/zapret2/nfqws2','--qnum=211','--debug=0','--server','--lua-init=@/opt/zapret2/lua/zapret-lib.lua','--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua','--filter-tcp=443','--payload=empty','--lua-desync=wsize:wsize=4:scale=0'])
    time.sleep(1)
    cmd(['systemctl','is-active','--quiet','mnebydns-w4-nfq-'+suffix])
    runner=os.environ.get('SSH_CONNECTION','').split()[0]
    add_rule(runner);emit('WINDOW4_RUNNER_CONTROL_ARMED',True)
def phone():
    clear_rules()
    spec=importlib.util.spec_from_file_location('observer',ROOT/'observer.py');obs=importlib.util.module_from_spec(spec);spec.loader.exec_module(obs)
    candidates=set()
    p=subprocess.Popen(['timeout','45','tcpdump','-i','eth0','-n','-U','-B','32768','-s','8192','-w','-','ip and tcp and dst host 89.125.90.101 and dst port 443'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0)
    try:
        endian,link=obs.read_header(p.stdout)
        emit('PHONE_MEDIA_SELECTOR_ARMED_SECONDS',45)
        while True:
            head=obs.read_exact(p.stdout,16)
            if head is None:break
            import struct
            sec,usec,cap,orig=struct.unpack(endian+'IIII',head)
            if cap>8192:raise RuntimeError('BAD_PREFIX_SIZE')
            body=obs.read_exact(p.stdout,cap)
            if body is None:raise RuntimeError('SHORT_PCAP')
            pkt=obs.decode(body,link)
            if pkt:
                name=obs.tls_sni(pkt[-1])
                if name and name.endswith('.googlevideo.com'):candidates.add(pkt[0])
    finally:
        p.wait(timeout=10)
    stats=p.stderr.read().decode('utf-8','replace');drops=re.search(r'(\d+) packets dropped by kernel',stats)
    emit('PHONE_MEDIA_CANDIDATE_COUNT',len(candidates))
    emit('PHONE_SELECTOR_KERNEL_DROPS',int(drops[1]) if drops else None)
    if len(candidates)!=1 or not drops or int(drops[1]):
        emit('PHONE_WINDOW4_APPLIED',False);return
    add_rule(next(iter(candidates)));emit('PHONE_WINDOW4_APPLIED',True)
    time.sleep(60);emit('PHONE_WINDOW4_OBSERVATION_SECONDS',60)
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
