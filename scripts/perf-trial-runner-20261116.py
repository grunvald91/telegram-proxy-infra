import concurrent.futures,json,os,pathlib,subprocess,time
ROOT='/opt/mnebyvpn/perf-trial-20261116'
roles={'DE':'89.125.90.101','RU':'188.120.254.223'}
opts=['-o','ConnectTimeout=10','-o','StrictHostKeyChecking=yes','-o','HostKeyAlgorithms=ssh-ed25519','-o','UserKnownHostsFile='+str(pathlib.Path('ops/mnebydns-owner-ssh-known_hosts').resolve()),'-o','GlobalKnownHostsFile=/dev/null','-o','UpdateHostKeys=no','-o','LogLevel=ERROR']
OUT=pathlib.Path('output');OUT.mkdir(exist_ok=True)
def execute(role,args,timeout=140):
    env=dict(os.environ,SSHPASS=os.environ[role+'_PASS'])
    p=subprocess.run(['sshpass','-e']+args,capture_output=True,text=True,timeout=timeout,env=env)
    if p.returncode:raise RuntimeError(role+' operation rc='+str(p.returncode))
    return p.stdout
def ssh(role,command,timeout=140):return execute(role,['ssh','-T']+opts+['root@'+roles[role],command],timeout)
def stage(role):
    ssh(role,"install -d -m 700 '"+ROOT+"'")
    for src,dst in [('scripts/perf-transport-trial-20261116.py','perf.py'),('scripts/perf-dns-bench-20261116.mjs','dns-bench.mjs')]:execute(role,['scp']+opts+[src,'root@'+roles[role]+':'+ROOT+'/'+dst])
    return role,json.loads(ssh(role,'python3 '+ROOT+'/perf.py stage '+role))
def remote_measure(role):return role,json.loads(ssh(role,'python3 '+ROOT+'/perf.py measure '+role))
def dns():
    # Existing live image only; credentials stay in the server's env file.
    cmd="image=$(docker inspect -f '{{.Config.Image}}' mnebyvpn-public-web); docker run --rm --network host --read-only --cap-drop ALL --security-opt no-new-privileges --env-file /opt/mnebyvpn/bot/web.env --mount type=bind,source="+ROOT+"/dns-bench.mjs,target=/dns-bench.mjs,readonly --entrypoint node \"$image\" --experimental-strip-types --input-type=module -e \"\$(cat "+ROOT+"/dns-bench.mjs)\""
    return json.loads(ssh('RU',cmd,150))
try:
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as p:stages=dict(p.map(stage,roles))
    (OUT/'stage.json').write_text(json.dumps(stages,indent=2))
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as p:
        future_dns=p.submit(dns);measures=dict(p.map(remote_measure,roles));dn=future_dns.result()
    (OUT/'pings.json').write_text(json.dumps(measures,indent=2));(OUT/'dns-before.json').write_text(json.dumps(dn,indent=2))
    bench=json.loads(ssh('RU','python3 '+ROOT+'/perf.py bench RU',90));(OUT/'tcp-client.json').write_text(json.dumps(bench,indent=2))
    for role in roles:
        report=json.loads(ssh(role,'python3 '+ROOT+'/perf.py collect '+role));(OUT/(role+'.json')).write_text(json.dumps(report,indent=2))
    print('PARALLEL_DIAGNOSTIC_FINISHED=true')
finally:
    for role in roles:
        try:print(ssh(role,'python3 '+ROOT+'/perf.py cleanup '+role,100).strip())
        except Exception as e:print('CLEANUP_PENDING_LOCAL_WATCHDOG='+role+' '+type(e).__name__)
