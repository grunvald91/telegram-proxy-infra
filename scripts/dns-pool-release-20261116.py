#!/usr/bin/env python3
"""Canary a pinned upstream DoT pool, preserve auth/video policy and rollback."""
import fcntl,hashlib,importlib.util,json,os,pathlib,re,sys
BASE=pathlib.Path('/opt/mnebyvpn/owner-dns-release-20261116')
ROOT=pathlib.Path('/opt/mnebyvpn/dot-pool-release-20261116')
spec=importlib.util.spec_from_file_location('owner_release',BASE/'release.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.ROOT=ROOT;m.CANARY='mnebydns-dot-pool-canary';m.OLD_PRIVATE='mnebydns-dot-pool-previous';m.OLD_BOT='mnebyvpn-dot-pool-unused';m.TIMER='mnebydns-dot-pool-recovery-20261116'
TARGET='/srv/mnebyvpn/packages/dns-policy/src/pooled-dot-upstream.ts'
def patch_once(text,before,after):
    if text.count(before)!=1:raise RuntimeError('Installed production patch context differs')
    return text.replace(before,after)
def benchmark(ip,port):
    args=['docker','exec','--env-file','/opt/mnebyvpn/bot/web.env','-i','-e','DNS_BENCH_PRIVATE_ONLY=yes','-e','DNS_BENCH_PRIVATE_IP='+ip,'-e','DNS_BENCH_PRIVATE_PORT='+str(port),m.PRIVATE,'node','--experimental-strip-types','--input-type=module']
    return json.loads(m.run(args,60,data=(ROOT/'dns-bench.mjs').read_text()))
def valid(result):
    row=result['results'][0]
    if row['errors'] or row['ordinary']['n']!=10 or row['premium']['n']!=10:raise RuntimeError('DNS performance probe incomplete')
    return row
def apply(sha,pin):
    if not re.fullmatch('[a-f0-9]{40}',sha) or not re.fullmatch('[a-f0-9]{64}',pin):raise RuntimeError('Bad source pin')
    if (ROOT/'COMMITTED').exists():raise RuntimeError('Pool release already committed')
    if hashlib.sha256((ROOT/'pool.ts').read_bytes()).hexdigest()!=pin:raise RuntimeError('Pool source hash mismatch')
    for name in [m.CANARY,m.OLD_PRIVATE]:
        if m.exists(name):raise RuntimeError('Reserved pool container exists')
    if any(re.search(r':'+str(p)+r'\s',m.run(['ss','-Hlnt'])) for p in [19056,19057]):raise RuntimeError('Pool canary ports occupied')
    d=m.inspect(m.PRIVATE)
    if d['State']['Status']!='running':raise RuntimeError('Original private gateway inactive')
    m.private(ROOT/'original-private.json',json.dumps(d))
    mounts=json.loads(json.dumps(d['Mounts']));prod=next(x for x in mounts if x['Destination']=='/srv/mnebyvpn/apps/service/src/personal-dot-production.ts')
    source=pathlib.Path(prod['Source']).read_text()
    source=patch_once(source,"  from '../../../packages/dns-policy/src/verified-dot-upstream.ts';", "  from '../../../packages/dns-policy/src/verified-dot-upstream.ts';\nimport {createVerifiedDotPool} from '../../../packages/dns-policy/src/pooled-dot-upstream.ts';")
    source,n=re.subn(r"(?m)^  await db.query\('SELECT 1'\);$","  await db.query('SELECT 1');\n  const mappedPool=createVerifiedDotPool(mapped),directPool=createVerifiedDotPool(direct);",source)
    if n!=1:raise RuntimeError('Pool constructor context differs')
    for label in ['mapped','direct']:
        source,n=re.subn(r'queryVerifiedDotTls\('+label+r',query,([0-9]+),signal\)',lambda x:label+'Pool.query(query,'+x.group(1)+',signal)',source)
        if n!=1:raise RuntimeError('Pool callback context differs')
    source=patch_once(source,'  const shutdown=()=>{\n','  const shutdown=()=>{\n    mappedPool.close();directPool.close();\n')
    source=patch_once(source,'  }catch(err){\n    listening=false;','  }catch(err){\n    mappedPool.close();directPool.close();\n    listening=false;')
    m.private(ROOT/'production.ts',source);os.chmod(ROOT/'production.ts',0o644)
    prod['Source']=str(ROOT/'production.ts')
    if any(x['Destination']==TARGET for x in mounts):raise RuntimeError('Unexpected preexisting pool mount')
    mounts.append({'Type':'bind','Source':str(ROOT/'pool.ts'),'Destination':TARGET,'RW':False})
    (ROOT/'response.pub').write_bytes((BASE/'response.pub').read_bytes());m.private(ROOT/'probe.mjs',"process.env.OWNER_VIDEO_ORIGIN_REQUIRED='yes';\n"+(ROOT/'probe-source.mjs').read_text())
    before=benchmark('10.66.77.2',8856);baseline=before['results'][0];m.private(ROOT/'before.json',json.dumps(before))
    m.create(d,m.CANARY,d['Image'],{'MNEBYDNS_PERSONAL_DOT_BIND_IP':'127.0.0.1','MNEBYDNS_PERSONAL_DOT_PORT':'19056','MNEBYDNS_PERSONAL_DOT_HEALTH_PORT':'19057','MNEBYDNS_DOT_POOL_ENABLED':'yes'},mounts)
    m.ready(19057);m.test_links(d['Image'],19056)
    proposed=benchmark('127.0.0.1',19056);candidate=valid(proposed);m.private(ROOT/'canary.json',json.dumps(proposed))
    if not baseline['errors'] and baseline['premium']['n']==10 and candidate['premium']['p50_ms']>baseline['premium']['p50_ms']*.90:raise RuntimeError('Pool did not improve median premium DNS latency')
    if m.inspect(m.PRIVATE)['Id']!=d['Id']:raise RuntimeError('Private gateway changed concurrently')
    m.arm();m.run(['docker','stop','-t','10',m.PRIVATE]);m.run(['docker','rename',m.PRIVATE,m.OLD_PRIVATE])
    m.create(d,m.PRIVATE,d['Image'],{'MNEBYDNS_DOT_POOL_ENABLED':'yes'},mounts);m.ready(8857);m.test_links(d['Image'],8856,True)
    after=benchmark('10.66.77.2',8856);valid(after);m.private(ROOT/'after.json',json.dumps(after))
    m.private(ROOT/'COMMITTED',json.dumps({'source_sha':sha,'pool_sha256':pin})+'\n');m.run(['systemctl','disable','--now',m.TIMER+'.timer']);m.run(['docker','rm','-f',m.CANARY])
    print('DOT_POOL_COMMITTED='+sha,flush=True)
if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('Root required')
    with open('/run/lock/mnebyvpn-owner-dns-release.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if sys.argv[1]=='rollback':m.rollback()
        else:
            try:apply(sys.argv[1],sys.argv[2])
            except Exception as e:
                print('DOT_POOL_RELEASE_FAILED='+type(e).__name__+': '+str(e),flush=True);m.rollback();raise SystemExit(1)
