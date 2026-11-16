#!/usr/bin/env python3
"""Canary one CI-tested owner DNS module; preserve all live transport settings."""
import fcntl, hashlib, importlib.util, json, os, pathlib, re, sys

BASE=pathlib.Path('/opt/mnebyvpn/owner-dns-release-20261116')
ROOT=pathlib.Path('/opt/mnebyvpn/owner-dns-video-20261116')
spec=importlib.util.spec_from_file_location('owner_release',BASE/'release.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.ROOT=ROOT
m.CANARY='mnebydns-owner-video-canary'
m.OLD_PRIVATE='mnebydns-owner-video-previous'
m.OLD_BOT='mnebyvpn-owner-video-unused'
m.TIMER='mnebydns-owner-video-recovery-20261116'
TARGET='/srv/mnebyvpn/packages/dns-policy/src/owner-dns-access.ts'

def apply(sha,expected_hash):
    if not re.fullmatch('[a-f0-9]{40}',sha) or not re.fullmatch('[a-f0-9]{64}',expected_hash):raise RuntimeError('Invalid source pin')
    if (ROOT/'COMMITTED').exists():raise RuntimeError('Video release already committed')
    if hashlib.sha256((ROOT/'helper.ts').read_bytes()).hexdigest()!=expected_hash:raise RuntimeError('Source hash mismatch')
    for name in [m.CANARY,m.OLD_PRIVATE]:
        if m.exists(name):raise RuntimeError('Reserved video container exists')
    if any(re.search(r':'+str(p)+r'\s',m.run(['ss','-Hlnt'])) for p in [18956,18957]):raise RuntimeError('Video canary port occupied')
    d=m.inspect(m.PRIVATE)
    if d['State']['Status']!='running':raise RuntimeError('Original private gateway inactive')
    m.private(ROOT/'original-private.json',json.dumps(d))
    mounts=json.loads(json.dumps(d['Mounts']))
    if any(x['Destination']==TARGET for x in mounts):raise RuntimeError('Unexpected preexisting helper override')
    mounts.append({'Type':'bind','Source':str(ROOT/'helper.ts'),'Destination':TARGET,'RW':False})
    (ROOT/'response.pub').write_bytes((BASE/'response.pub').read_bytes())
    original=(ROOT/'probe-source.mjs').read_text()
    m.private(ROOT/'probe.mjs',"process.env.OWNER_VIDEO_ORIGIN_REQUIRED='yes';\n"+original)
    m.create(d,m.CANARY,d['Image'],{'MNEBYDNS_PERSONAL_DOT_BIND_IP':'127.0.0.1','MNEBYDNS_PERSONAL_DOT_PORT':'18956','MNEBYDNS_PERSONAL_DOT_HEALTH_PORT':'18957'},mounts)
    m.ready(18957);m.test_links(d['Image'],18956)
    if m.inspect(m.PRIVATE)['Id']!=d['Id']:raise RuntimeError('Private gateway changed concurrently')
    m.arm()
    m.run(['docker','stop','-t','10',m.PRIVATE]);m.run(['docker','rename',m.PRIVATE,m.OLD_PRIVATE])
    m.create(d,m.PRIVATE,d['Image'],{},mounts);m.ready(8857)
    m.test_links(d['Image'],8856,True)
    m.private(ROOT/'COMMITTED',json.dumps({'source_sha':sha,'helper_sha256':expected_hash})+'\n')
    m.run(['systemctl','disable','--now',m.TIMER+'.timer']);m.run(['docker','rm','-f',m.CANARY])
    print('OWNER_VIDEO_ORIGIN_COMMITTED='+sha,flush=True)

if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('Root required')
    with open('/run/lock/mnebyvpn-owner-dns-release.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if sys.argv[1]=='rollback':m.rollback()
        else:
            try:apply(sys.argv[1],sys.argv[2])
            except Exception as e:
                print('OWNER_VIDEO_RELEASE_FAILED='+type(e).__name__+': '+str(e),flush=True)
                m.rollback();raise SystemExit(1)
