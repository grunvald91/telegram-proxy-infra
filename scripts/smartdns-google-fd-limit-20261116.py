"""Raise the Google proxy FD limit live and persist it without restarting nginx."""
import datetime,json,os,pathlib,re,resource,subprocess
UNIT='mnebydns-googlepilot.service';ROOT=pathlib.Path('/opt/mnebydns-google-fd-limit-20261116');DROP=pathlib.Path('/etc/systemd/system')/(UNIT+'.d')/'90-smartdns-fd-limit-20261116.conf'
def checked(args):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=12).stdout.strip()
assert checked(['systemctl','is-active',UNIT])=='active'
pid=int(checked(['systemctl','show',UNIT,'-p','MainPID','--value']));assert pid>1
cfg=pathlib.Path('/etc/mnebydns-googlepilot/nginx.conf');assert str(cfg).encode() in pathlib.Path('/proc',str(pid),'cmdline').read_bytes()
m=re.search(r'worker_connections\s+(\d+)\s*;',cfg.read_text());assert m;connections=int(m[1]);desired=max(4096,2*connections);assert desired<=65535
pids=[pid]+[int(x) for x in pathlib.Path('/proc',str(pid),'task',str(pid),'children').read_text().split()]
limits={}
for child in pids:
 try:
  if pathlib.Path('/proc',str(child),'comm').read_text().strip()=='nginx':limits[child]=resource.prlimit(child,resource.RLIMIT_NOFILE)
 except FileNotFoundError:pass
assert pid in limits
# Preserve any higher existing limit rather than lowering it.
desired=max(desired,*[max(v) for v in limits.values()]);assert desired<=1048576
body=f'[Service]\nLimitNOFILE={desired}\n'
assert not DROP.exists() or DROP.read_text()==body,'Existing override differs; refuse overwrite'
ROOT.mkdir(mode=0o700,exist_ok=True);backup=ROOT/'original.json'
if not backup.exists():backup.write_text(json.dumps({'unit':UNIT,'pid_limits':limits,'override_preexisted':DROP.exists()}));os.chmod(backup,0o600)
DROP.parent.mkdir(mode=0o755,exist_ok=True);DROP.write_text(body);os.chmod(DROP,0o644)
checked(['systemctl','daemon-reload']);assert int(checked(['systemctl','show',UNIT,'-p','LimitNOFILE','--value']))>=desired
assert int(checked(['systemctl','show',UNIT,'-p','MainPID','--value']))==pid,'Concurrent service restart'
after={}
for child,old in limits.items():
 try:
  resource.prlimit(child,resource.RLIMIT_NOFILE,(max(old[0],desired),max(old[1],desired)));after[child]=resource.prlimit(child,resource.RLIMIT_NOFILE)
 except ProcessLookupError:pass
assert after.get(pid,(0,0))[0]>=desired
print(json.dumps({'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'done':True,'unit':UNIT,'worker_connections':connections,'before':limits,'after':after,'override':str(DROP),'process_restarted':False,'main_pid':pid}))
