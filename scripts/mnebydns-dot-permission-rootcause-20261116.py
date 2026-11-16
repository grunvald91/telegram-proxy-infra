#!/usr/bin/env python3
"""Read-only targeted DoT service permission diagnosis, no secrets emitted."""
import datetime,json,os,pathlib,subprocess,hashlib,re
def command(argv):
  try:
    p=subprocess.run(argv,capture_output=True,text=True,timeout=12)
    return {"rc":p.returncode,"out":p.stdout[:11000]}
  except Exception as e:return {"error":type(e).__name__}
paths={
 "core_live":"/opt/mnebydns-dot/Corefile",
 "core_backup":"/var/backups/mnebydns-nov8-google-restore-20261116-143947/dns.before",
 "pilot_live":"/etc/mnebydns-googlepilot/nginx.conf",
 "pilot_backup":"/var/backups/mnebydns-nov8-google-restore-20261116-143947/pilot.before",
 "core_parent":"/opt/mnebydns-dot",
}
data={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"read_only":True,"file_access":{}}
for name,path in paths.items():
  p=pathlib.Path(path)
  if not p.exists():
    data["file_access"][name]={"exists":False};continue
  stat=p.stat()
  names=os.listxattr(path)
  data["file_access"][name]={"exists":True,"mode":oct(stat.st_mode&0o7777),"uid":stat.st_uid,"gid":stat.st_gid,
    "xattrs":{key:hashlib.sha256(os.getxattr(path,key)).hexdigest() for key in names}}
service=command(["systemctl","show","mnebydns-dot.service","-p","User,Group,DynamicUser,SupplementaryGroups,WorkingDirectory,ExecStart,ProtectSystem,ReadOnlyPaths,ReadWritePaths"])
props={}
for line in service.get("out","").splitlines():
  if "=" in line:
    k,v=line.split("=",1)
    if k=="ExecStart":
      props[k]={"present":bool(v),"corefile_named":"Corefile" in v,"exec_start_binary":"coredns" if "coredns" in v.lower() else "other"}
    else:props[k]=v[:350]
data["service_permissions"]=props
j=command(["journalctl","-u","mnebydns-dot.service","--since","2026-11-16 14:39:00 UTC","-n","90","-o","cat","--no-pager"])
messages=[]
for line in j.get("out","").splitlines():
  if any(z in line.lower() for z in ("permission","denied","error","fail","corefile","open","certificate","credentials","process","exit")):
    line=re.sub(r'[a-z0-9]{12}\.dns\.mnebyvpn\.site','<personal-id>.dns.mnebyvpn.site',line,flags=re.I)
    line=re.sub(r'(?i)(password|token|secret|key)\s*[=:]\s*\S+',r'\1=<redacted>',line)
    messages.append(line[:260])
data["relevant_journal_messages"]=messages[-25:]
print(json.dumps(data,sort_keys=True))
