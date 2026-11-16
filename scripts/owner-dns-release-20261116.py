#!/usr/bin/env python3
"""Scoped owner-link rollout. Private config never leaves the server.

Reuses existing mounts, certificates, upstreams and container limits. A failed
canary changes no listener. Both old containers survive until final commit.
"""
import datetime, fcntl, json, os, pathlib, re, shutil, subprocess, sys, tempfile, time, urllib.parse

ROOT=pathlib.Path('/opt/mnebyvpn/owner-dns-release-20261116')
PRIVATE='mnebydns-personal-dot-private'
BOT='mnebyvpn-bot-info'
CANARY='mnebydns-owner-link-canary'
OLD_PRIVATE='mnebydns-owner-link-previous'
OLD_BOT='mnebyvpn-owner-link-previous'
TIMER='mnebydns-owner-link-recovery-20261116'
def run(args,timeout=30,data=None):
    p=subprocess.run(args,input=data,capture_output=True,text=True,timeout=timeout)
    if p.returncode:
        # Only explicit non-sensitive probe errors may reach Actions logs.
        safe=re.findall(r'^Error: (Temporary link not issued|Permanent link not issued|DNS probe timeout|TLS or DNS failure|Bad DNS reply|Expired/unknown link accepted|Owner configuration unavailable)$',p.stderr,re.M)
        raise RuntimeError('Command failed: '+args[0]+' code '+str(p.returncode)+(' : '+safe[0] if safe else ''))
    return p.stdout
def private(path,content):
    path=pathlib.Path(path)
    fd,temp=tempfile.mkstemp(prefix='.'+path.name+'-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            f.write(content);f.flush()
            if path.exists():
                old=path.stat();os.fchown(f.fileno(),old.st_uid,old.st_gid)
                os.fchmod(f.fileno(),old.st_mode&0o777)
                for name in os.listxattr(path):os.setxattr(f.fileno(),name,os.getxattr(path,name))
            os.fsync(f.fileno())
        os.replace(temp,path)
        directory=os.open(path.parent,os.O_DIRECTORY|os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(temp):os.unlink(temp)
def inspect(name):return json.loads(run(['docker','inspect',name]))[0]
def exists(name):return name in run(['docker','ps','-a','--format','{{.Names}}']).splitlines()
def envmap(d):return dict(x.split('=',1) for x in d['Config']['Env'] if '=' in x)
def psql(sql):return run(['docker','exec','-i','mnebyvpn-stage-postgres','psql','-v','ON_ERROR_STOP=1','-U','mnebyvpn_stage','-d','mnebyvpn_stage','-At'],data=sql)
def create(d,name,image=None,overrides=None,mounts=None,start=True):
    env=envmap(d);env.update(overrides or {})
    envfile=ROOT/(name+'.env');private(envfile,''.join(k+'='+v+'\n' for k,v in env.items()))
    h=d['HostConfig'];c=d['Config']
    args=['docker','run' if start else 'create','--name',name,'--network','host',
          '--env-file',str(envfile),'--user',c['User'],'--read-only','--cap-drop','ALL',
          '--workdir',c.get('WorkingDir') or '/',
          '--security-opt','no-new-privileges','--pids-limit',str(h.get('PidsLimit') or 96),
          '--memory',str(h['Memory'] or 268435456),'--cpus',str((h.get('NanoCpus') or 500000000)/1e9),
          '--tmpfs','/tmp:rw,nosuid,nodev,size=16m','--restart','unless-stopped']
    for m in (mounts if mounts is not None else d.get('Mounts',[])):
        if m['Type']!='bind':raise RuntimeError('Unexpected mount type')
        args+=['--mount','type=bind,source='+m['Source']+',target='+m['Destination']+(',readonly' if not m['RW'] else '')]
    entry=c.get('Entrypoint') or []
    if len(entry)!=1:raise RuntimeError('Unexpected container entrypoint')
    args+=['--entrypoint',entry[0],image or d['Image']]+(c.get('Cmd') or [])
    if start:args.insert(2,'-d')
    run(args,60)
def ready(port):
    for _ in range(25):
        try:
            if run(['curl','--noproxy','*','-fsS','--max-time','2','http://127.0.0.1:'+str(port)+'/readyz'],4):return
        except Exception:pass
        time.sleep(1)
    raise RuntimeError('Candidate readiness failed')
def rollback():
    # COMMITTED makes old emergency timers harmless on a later reboot.
    if (ROOT/'COMMITTED').exists():return
    for name,backup in [(PRIVATE,OLD_PRIVATE),(BOT,OLD_BOT)]:
        if exists(backup):
            saved=ROOT/('original-private.json' if name==PRIVATE else 'original-bot.json')
            if exists(name) and saved.exists() and inspect(name)['Id']==json.loads(saved.read_text())['Id']:
                run(['docker','rm','-f',backup]);continue
            if exists(name):run(['docker','rm','-f',name])
            run(['docker','rename',backup,name]);run(['docker','start',name])
    if exists(CANARY):run(['docker','rm','-f',CANARY])
def arm():
    deadline=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=12)).strftime('%Y-%m-%d %H:%M:%S UTC')
    service='[Unit]\nDescription=Recover uncommitted owner DNS rollout\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 '+str(ROOT/'release.py')+' rollback\n'
    timer='[Unit]\nDescription=Persistent owner DNS recovery\n[Timer]\nOnCalendar='+deadline+'\nPersistent=true\nAccuracySec=1s\nUnit='+TIMER+'.service\n[Install]\nWantedBy=timers.target\n'
    pathlib.Path('/etc/systemd/system/'+TIMER+'.service').write_text(service)
    pathlib.Path('/etc/systemd/system/'+TIMER+'.timer').write_text(timer)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now',TIMER+'.timer'])
def bot_backup_image(bot):
    try:
        run(['docker','image','inspect',bot['Image']])
        return bot['Image']
    except RuntimeError:
        # The live container can survive removal of its image metadata. This
        # state was confirmed by the read-only diagnostic, not assumed.
        # Export its immutable rootfs; preserve env/command/user/working dir
        # separately through the saved inspect record and create(). No volumes
        # may be lost from this recovery snapshot.
        if bot.get('Mounts') or not bot['HostConfig'].get('ReadonlyRootfs'):
            raise RuntimeError('Missing-image backup requires an immutable bot without mounts')
        if shutil.disk_usage(ROOT).free<512*1024*1024:
            raise RuntimeError('Insufficient free space for a verified bot backup')
        archive=ROOT/'bot-rootfs.tar'
        archive.touch(mode=0o600,exist_ok=False)
        try:
            run(['docker','export','--output',str(archive),BOT],90)
            image='mnebyvpn-owner-recovery-bot:20261116'
            run(['docker','import',str(archive),image],90)
        finally:archive.unlink(missing_ok=True)
        # Verify an actual recovery container before any live service stops.
        name='mnebyvpn-owner-recovery-check'
        if exists(name):raise RuntimeError('Recovery canary name is occupied')
        if re.search(r':18798\s',run(['ss','-Hlnt'])):raise RuntimeError('Recovery canary port occupied')
        create(bot,name,image,{'BOT_PORT':'18798'})
        try:ready(18798)
        finally:run(['docker','rm','-f',name])
        print('ORIGINAL_BOT_MISSING_IMAGE_RECOVERY_VERIFIED=true',flush=True)
        return image
def test_links(image,port,public=False):
    args=['docker','run','--rm','--network','host','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
        '--env-file','/opt/mnebyvpn/bot/web.env','--mount','type=bind,source='+str(ROOT/'response.pub')+',target=/response.pub,readonly',
        '-e','OWNER_TEST_PORT='+str(port),'-e','OWNER_TEST_PUBLIC='+('yes' if public else 'no'),'--entrypoint','node',image,
        '--experimental-strip-types','--input-type=module','-e',(ROOT/'probe.mjs').read_text()]
    # Probe emits generic test results and an RSA-encrypted hostname only.
    result=json.loads(run(args,110));assert result['ok'] is True
    private(ROOT/'result.json',json.dumps(result))
    print('OWNER_LINK_CANARY_PUBLIC='+str(public)+' PASS',flush=True)
def apply(sha):
    if not re.fullmatch('[a-f0-9]{40}',sha):raise RuntimeError('Invalid release SHA')
    if (ROOT/'COMMITTED').exists():raise RuntimeError('Release already committed')
    for name in [CANARY,OLD_PRIVATE,OLD_BOT]:
        if exists(name):raise RuntimeError('Reserved container already exists')
    listeners=run(['ss','-Hlnt'])
    if any(re.search(r':'+str(port)+r'\s',listeners) for port in [18856,18857]):
        raise RuntimeError('Candidate port already occupied')
    d=inspect(PRIVATE);bot=inspect(BOT)
    if d['State']['Status']!='running' or bot['State']['Status']!='running':raise RuntimeError('Original service not running')
    if d['HostConfig']['NetworkMode']!='host':raise RuntimeError('Unexpected private network mode')
    private(ROOT/'original-private.json',json.dumps(d));private(ROOT/'original-bot.json',json.dumps(bot))
    release=pathlib.Path('/opt/mnebyvpn/releases')/sha
    image='mnebyvpn-stage-web:'+sha
    run(['docker','image','inspect',image])
    # Patch the *installed* server so its verified upstream and TLS fixes remain.
    mounted={m['Destination']:m for m in d['Mounts']}
    prod=mounted['/srv/mnebyvpn/apps/service/src/personal-dot-production.ts']
    original=pathlib.Path(prod['Source']).read_text()
    marker='    key,cert,db,classify,\n'
    addition="    ownerLinkStatus:async(label:string)=>{\n      const r=await db.query('SELECT owner_dns_link_status($1) AS status',[label]);\n      return String(r.rows[0]?.status??'DENY_UNKNOWN');\n    },\n"
    if original.count(marker)!=1 or 'ownerLinkStatus' in original:raise RuntimeError('Installed server needs a reviewed patch')
    candidate=original.replace(marker,marker+addition)
    private(ROOT/'production.ts',candidate);os.chmod(ROOT/'production.ts',0o644)
    # Refuse to discard unreviewed runtime listener modifications.
    listener_path='/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts'
    source=mounted.get(listener_path)
    if not source:raise RuntimeError('Expected explicit private listener mount')
    installed=pathlib.Path(source['Source']).read_text()
    changes=[
      ("import {parsePersonalDoTHostname} from './personal-dot-identity.ts';", "import {parsePersonalDoTHostname} from './personal-dot-identity.ts';\nimport {resolveOwnerDnsMessage,type OwnerDnsStatus} from './owner-dns-access.ts';"),
      ('export interface PersonalDotListenerOptions {','export interface PersonalDotListenerOptions {\n  ownerLinkStatus?:OwnerDnsStatus;'),
      ('    let buffer=Buffer.alloc(0),busy=false,closed=false;','    let buffer=Buffer.alloc(0),busy=false,closed=false;\n    let ownerLink:boolean|undefined;'),
      ('          let offlineDirectOnly=false;',"          let offlineDirectOnly=false;\n          if(ownerLink===undefined&&o.ownerLinkStatus){\n            const status=await o.ownerLinkStatus(label!);\n            if(status!=='UNKNOWN'&&status!=='ALLOWED'){stop();return;}\n            ownerLink=status==='ALLOWED';\n          }"),
      ('          if(verifiedAt!==undefined&&current>=verifiedAt&&','          if(ownerLink){\n          }else if(verifiedAt!==undefined&&current>=verifiedAt&&'),
      ('            const work=offlineDirectOnly','            const work=ownerLink&&o.ownerLinkStatus\n              ?resolveOwnerDnsMessage(label!,request,o.ownerLinkStatus,o.classify,o.mapped,o.direct,controller.signal)\n              :offlineDirectOnly'),
    ]
    for before,after in changes:
        if installed.count(before)!=1:raise RuntimeError('Runtime listener patch context differs')
        installed=installed.replace(before,after)
    private(ROOT/'listener.ts',installed);os.chmod(ROOT/'listener.ts',0o644)
    mounts=json.loads(json.dumps(d['Mounts']))
    for m in mounts:
        if m['Destination']==prod['Destination']:m['Source']=str(ROOT/'production.ts')
        if m['Destination']==listener_path:m['Source']=str(ROOT/'listener.ts')
    # Grant each existing role only the new capabilities it needs.
    bot_env=envmap(bot);dot_env=envmap(d)
    bot_role=urllib.parse.unquote(urllib.parse.urlsplit(bot_env['DATABASE_URL']).username)
    dot_role=urllib.parse.unquote(urllib.parse.urlsplit(dot_env['DATABASE_URL']).username)
    for role in [bot_role,dot_role]:
        if not re.fullmatch('[a-zA-Z0-9_]{1,63}',role):raise RuntimeError('Unexpected DB role')
    psql('GRANT SELECT,INSERT,UPDATE ON owner_dns_links TO "'+bot_role+'";\nGRANT SELECT,INSERT ON owner_dns_link_edits TO "'+bot_role+'";\nGRANT EXECUTE ON FUNCTION owner_dns_link_status(text) TO "'+dot_role+'";')
    env_path=pathlib.Path('/opt/mnebyvpn/bot/web.env');env_text=env_path.read_text()
    existing=dict(l.split('=',1) for l in env_text.splitlines() if '=' in l and not l.startswith('#'))
    if 'MNEBYDNS_OWNER_LINK_KEY' not in existing:
        key=os.urandom(32).hex()
        private(ROOT/'owner-key-backup.env','MNEBYDNS_OWNER_LINK_KEY='+key+'\n')
        private(env_path,env_text.rstrip()+'\nMNEBYDNS_OWNER_LINK_KEY='+key+'\n')
    elif not re.fullmatch('[a-f0-9]{64}',existing['MNEBYDNS_OWNER_LINK_KEY']):raise RuntimeError('Invalid existing encryption key')
    create(d,CANARY,image,{'MNEBYDNS_PERSONAL_DOT_BIND_IP':'127.0.0.1','MNEBYDNS_PERSONAL_DOT_PORT':'18856','MNEBYDNS_PERSONAL_DOT_HEALTH_PORT':'18857','MNEBYDNS_OWNER_LINKS_ENABLED':'yes'},mounts)
    ready(18857)
    if inspect(CANARY)['State']['Status']!='running':raise RuntimeError('Candidate exited')
    test_links(image,18856)
    # Retain an exact stopped bot clone for emergency recovery as well.
    create(bot,OLD_BOT,bot_backup_image(bot),start=False)
    arm()
    run(['docker','stop','-t','10',PRIVATE]);run(['docker','rename',PRIVATE,OLD_PRIVATE])
    create(d,PRIVATE,image,{'MNEBYDNS_OWNER_LINKS_ENABLED':'yes'},mounts);ready(int(dot_env['MNEBYDNS_PERSONAL_DOT_HEALTH_PORT']))
    test_links(image,int(dot_env['MNEBYDNS_PERSONAL_DOT_PORT']),True)
    run(['bash','/opt/mnebyvpn/owner-dns-release-20261116/promote.sh',sha],160)
    ready(8793)
    # Local signed test does not send a Telegram message; check JSON response.
    env=envmap(inspect(BOT))
    if not re.fullmatch('[a-f0-9]{64}',env.get('MNEBYDNS_OWNER_LINK_KEY','')):raise RuntimeError('Bot did not load link key')
    private(ROOT/'COMMITTED',sha+'\n')
    run(['systemctl','disable','--now',TIMER+'.timer'])
    run(['docker','rm','-f',CANARY])
    print('OWNER_DNS_RELEASE_COMMITTED='+sha,flush=True)

if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('Root required')
    ROOT.mkdir(mode=0o755,parents=True,exist_ok=True)
    # Candidate sources need to be readable by existing unprivileged service.
    # Runtime snapshots and keys themselves are mode 0600.
    with open('/run/lock/mnebyvpn-owner-dns-release.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if sys.argv[1]=='rollback':rollback()
        else:
            try:apply(sys.argv[1])
            except Exception as e:
                print('OWNER_DNS_RELEASE_FAILED='+type(e).__name__+': '+str(e),flush=True)
                rollback();raise SystemExit(1)
