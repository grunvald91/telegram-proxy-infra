#!/usr/bin/env python3
"""On-node read-only CoreDNS service health observation; no queries or config writes."""
import datetime,json,subprocess,pathlib,re,hashlib
def cmd(*argv):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=9)
        return {"rc":p.returncode,"stdout":p.stdout[:3500],"stderr_present":bool(p.stderr)}
    except Exception as ex:return {"error":type(ex).__name__}
def properties(unit):
    r=cmd("systemctl","show",unit,
       "-p","LoadState,ActiveState,SubState,Result,ExecMainStatus,NRestarts,MainPID,FragmentPath,ExecMainStartTimestamp")
    return {"status":dict(line.split("=",1) for line in r.get("stdout","").splitlines() if "=" in line),
            "systemctl_rc":r.get("rc",999)}
def errors(unit):
    r=cmd("journalctl","-u",unit,"--since","40 minutes ago","-n","300","-o","cat","--no-pager")
    texts=r.get("stdout","").splitlines()
    categories={"no_such_file":0,"permission_denied":0,"bind_conflict":0,"configuration_parse":0,
        "connection_refused":0,"timeout":0,"exit_status":0,"error":0}
    for line in texts:
        l=line.lower()
        for name,expressions in (("no_such_file",("no such file","not found")),("permission_denied",("permission denied","operation not permitted")),
          ("bind_conflict",("address already in use","bind:","listen tcp")),("configuration_parse",("parse error","parse failed","invalid","syntax error","plugin/","unrecognized")),
          ("connection_refused",("connection refused",)),("timeout",("timed out","timeout")),("exit_status",("exit-code","status=1/","status=2/")),("error",("error","fatal","failed"))):
            if any(x in l for x in expressions):categories[name]+=1
    return {"records":len(texts),"categories":categories,"rc":r.get("rc",999)}
def sockets():
    r=cmd("ss","-H","-lnt","sport = :853")
    lines=r.get("stdout","").splitlines()
    return {"tcp853_listening":bool(lines),"tcp853_socket_count":len(lines)}
p=pathlib.Path("/opt/mnebydns-dot/Corefile")
files={"core_exists":p.is_file(),
       "core_sha256":hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None}
states={u:properties(u) for u in ("mnebydns-dot.service","nginx.service","mnebydns-googlepilot.service")}
states["mnebydns-dot-restore-recovery-20261116143947.timer"]=properties("mnebydns-nov8-google-recovery-20261116143947.timer")
out={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"read_only":True,
     "services":states,"dns_journal_categories":errors("mnebydns-dot.service"),
     "listeners":sockets(),"file":files}
print(json.dumps(out,sort_keys=True))
