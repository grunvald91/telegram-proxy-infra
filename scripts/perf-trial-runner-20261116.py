import concurrent.futures,json,os,pathlib,re,subprocess,time
ROOT='/opt/mnebyvpn/perf-trial-20261116'
roles={'DE':'89.125.90.101','RU':'188.120.254.223'}
opts=['-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','HostKeyAlgorithms=ssh-ed25519','-o','UserKnownHostsFile='+str(pathlib.Path('ops/mnebydns-owner-ssh-known_hosts').resolve()),'-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no','-o','LogLevel=ERROR']
OUT=pathlib.Path('output');OUT.mkdir(exist_ok=True)
def execute(role,args,timeout=140):
    env=dict(os.environ,SSHPASS=os.environ[role+'_PASS'])
    p=subprocess.run(['sshpass','-e']+args,capture_output=True,text=True,timeout=timeout,env=env)
    if p.returncode:
        lines=[x.strip() for x in p.stderr.splitlines() if re.match(r'^\w*(?:Error|Exception):',x.strip())]
        reason='; '.join(lines[-2:]);reason=re.sub(r'[a-z0-9]{12}\.dns\.mnebyvpn\.site','<personal>',reason)
        reason=re.sub(r'[A-Za-z0-9_+/=-]{32,}','<redacted>',reason)
        raise RuntimeError(role+' operation rc='+str(p.returncode)+' '+reason[:240])
    return p.stdout
def ssh(role,command,timeout=140):return execute(role,['ssh','-T']+opts+['root@'+roles[role],command],timeout)
def stage(role):
    ssh(role,"install -d -m 700 '"+ROOT+"'")
    for src,dst in [('scripts/perf-transport-trial-20261116.py','perf.py'),('scripts/perf-dns-bench-20261116.mjs','dns-bench.mjs')]:execute(role,['scp']+opts+[src,'root@'+roles[role]+':'+ROOT+'/'+dst])
    previous=json.loads(ssh(role,'python3 '+ROOT+'/perf.py collect '+role))
    (OUT/('previous-'+role+'.json')).write_text(json.dumps(previous,indent=2))
    return role,json.loads(ssh(role,'python3 '+ROOT+'/perf.py stage '+role))
def remote_measure(role):
    try:return role,json.loads(ssh(role,'python3 '+ROOT+'/perf.py measure '+role))
    except Exception as e:return role,{'error':str(e)}
def dns():
    # Existing live image only; credentials stay in the server's env file.
    cmd=('docker exec --env-file /opt/mnebyvpn/bot/web.env -i mnebydns-personal-dot-private '
         'node --experimental-strip-types --input-type=module < '+ROOT+'/dns-bench.mjs')
    return json.loads(ssh('RU',cmd,150))
try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as p:stages=dict(p.map(stage,roles))
    (OUT/'stage.json').write_text(json.dumps(stages,indent=2))
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as p:
        future_dns=p.submit(dns);measures=dict(p.map(remote_measure,roles))
        (OUT/'pings.json').write_text(json.dumps(measures,indent=2))
        bench=json.loads(ssh('RU','python3 '+ROOT+'/perf.py bench RU',90));(OUT/'tcp-client.json').write_text(json.dumps(bench,indent=2))
        try:dn=future_dns.result()
        except Exception as e:dn={'error':type(e).__name__}
    (OUT/'pings.json').write_text(json.dumps(measures,indent=2));(OUT/'dns-before.json').write_text(json.dumps(dn,indent=2))
    for role in roles:
        ssh(role,'python3 '+ROOT+'/perf.py finish '+role)
        report=json.loads(ssh(role,'python3 '+ROOT+'/perf.py collect '+role));(OUT/(role+'.json')).write_text(json.dumps(report,indent=2))
    print('PARALLEL_DIAGNOSTIC_FINISHED=true')
finally:
    for role in roles:
        try:print(ssh(role,'python3 '+ROOT+'/perf.py cleanup '+role,100).strip())
        except Exception as e:print('CLEANUP_PENDING_LOCAL_WATCHDOG='+role+' '+type(e).__name__)
