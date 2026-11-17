#!/usr/bin/env python3
"""Five-minute peer-scoped NFQUEUE exclusion, authenticated by exact probe IDs."""
import hashlib,ipaddress,json,os,pathlib,re,subprocess,sys,time
ROOT=pathlib.Path(sys.argv[2]).resolve()
if not re.fullmatch(r'/run/mnebydns-owner-return-[0-9]+-[0-9]+',str(ROOT)):raise RuntimeError('BAD_ROOT')
CHAIN=['inet','telegram_nfqws','post'];TAG='mnebydns_owner_return_bypass_20261117'
FILES=['/etc/nginx/nginx.conf','/etc/mnebydns-googlepilot/nginx.conf','/etc/zapret2/telegram-nfqws.conf','/usr/local/sbin/telegram-foreign-nfqws-rules']
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
def cmd(a):
    p=subprocess.run(a,capture_output=True,text=True,timeout=12)
    if p.returncode:raise RuntimeError('COMMAND_FAILED_'+pathlib.Path(a[0]).name+'_'+str(p.returncode))
    return p.stdout
def rules():return [x['rule'] for x in json.loads(cmd(['nft','-j','-a','list','chain',*CHAIN]))['nftables'] if 'rule' in x]
def hashes():return {p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in FILES}
def clean():
    for r in rules():
        if r.get('comment')==TAG:
            emit('OWNER_RETURN_BYPASS_COUNTER',[e['counter'] for e in r['expr'] if 'counter' in e])
            cmd(['nft','delete','rule',*CHAIN,'handle',str(r['handle'])])
    if any(r.get('comment')==TAG for r in rules()):raise RuntimeError('CLEANUP_FAILED')
    snapshot=ROOT/'protected-hashes.json'
    if snapshot.exists() and json.loads(snapshot.read_text())!=hashes():raise RuntimeError('PROTECTED_CONFIGURATION_CHANGED')
    emit('OWNER_RETURN_BYPASS_REMOVED',True)
def apply():
    if os.geteuid()!=0:raise RuntimeError('ROOT_REQUIRED')
    expected={'70fd267cea0b7d0d':1578,'6d06aec16581692d':234,'22d1a1e6fded94a8':1592}
    path=pathlib.Path('/run/mnebydns-normalcurl-44083307553-1/bindings.private.jsonl')
    rows=[json.loads(x) for x in path.read_text().splitlines()]
    matches={x['probe']:x for x in rows if x['probe'] in expected}
    if set(matches)!=set(expected):raise RuntimeError('PHONE_PROBES_NOT_ALL_BOUND')
    if any(x['expected']!=expected[k] or not 0<=time.time()-x['observed_at']<=1800 for k,x in matches.items()):raise RuntimeError('STALE_OR_MISMATCHED_PHONE_PROBE')
    addresses={x['address'] for x in matches.values()}
    if len(addresses)!=1:raise RuntimeError('AMBIGUOUS_PHONE_SOURCE')
    address=next(iter(addresses));ip=ipaddress.ip_address(address)
    if ip.version!=4 or not ip.is_global:raise RuntimeError('BAD_PEER')
    rr=rules()
    if any(r.get('comment')==TAG for r in rr):raise RuntimeError('EXISTING_BYPASS_TEST')
    if not any(r.get('comment')=='mnebyvpn_de_standard_synack' for r in rr):raise RuntimeError('STANDARD_GUARD_MISSING')
    if not any(e.get('queue',{}).get('num')==210 for r in rr for e in r['expr']):raise RuntimeError('QUEUE_210_MISSING')
    (ROOT/'protected-hashes.json').write_text(json.dumps(hashes()))
    suffix=ROOT.name.removeprefix('mnebydns-owner-return-')
    timer='mnebydns-owner-return-clean-'+suffix
    cmd(['systemd-run','--quiet','--collect','--unit='+timer,'--on-active=300s','/usr/bin/python3','-B',str(pathlib.Path(__file__).resolve()),'clean',str(ROOT)])
    cmd(['systemctl','is-active','--quiet',timer+'.timer'])
    args=['nft','insert','rule',*CHAIN,'oifname','eth0','ip','saddr','89.125.90.101','ip','daddr',address,'tcp','sport','443','counter','accept','comment',TAG]
    try:
        cmd(['nft','-c',*args[1:]]);cmd(args)
        if rules()[0].get('comment')!=TAG:raise RuntimeError('BYPASS_NOT_FIRST')
    except BaseException:clean();raise
    emit('PHONE_SOURCE_BOUND_BY_NORMAL_TLS_PROBES',len(matches))
    emit('OWNER_RETURN_BYPASS_ACTIVE',True)
    emit('OWNER_RETURN_BYPASS_EXPIRES_UTC',time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(time.time()+300)))
    emit('PRODUCTION_CONFIG_FILES_UNCHANGED',hashes()==json.loads((ROOT/'protected-hashes.json').read_text()))
if __name__=='__main__':
    if sys.argv[1]=='apply':apply()
    elif sys.argv[1]=='clean':clean()
    elif sys.argv[1]=='status':
        selected=[r for r in rules() if r.get('comment')==TAG]
        emit('OWNER_RETURN_BYPASS_ACTIVE',bool(selected))
        for r in selected:emit('OWNER_RETURN_BYPASS_COUNTER',[e['counter'] for e in r['expr'] if 'counter' in e])
    else:raise SystemExit(2)
