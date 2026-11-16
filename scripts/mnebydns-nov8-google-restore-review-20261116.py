#!/usr/bin/env python3
"""Non-mutating post-restore code/config integrity review, no network probes."""
import datetime
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

ROOT=Path("/var/backups/mnebydns-nov8-google-restore-20261116-143947")
FILES={
 "dns":Path("/opt/mnebydns-dot/Corefile"),
 "pilot":Path("/etc/mnebydns-googlepilot/nginx.conf"),
 "shared":Path("/etc/nginx/nginx.conf")
}
def hashdata(b):return hashlib.sha256(b).hexdigest()
def report(p):
    if not p.is_file():return {"exists":False}
    s=p.stat()
    return {"exists":True,"sha256":hashdata(p.read_bytes()),
            "mode":oct(stat.S_IMODE(s.st_mode)),"uid":s.st_uid,"gid":s.st_gid,
            "bytes":s.st_size}
def service(name):
    try:
        p=subprocess.run(["systemctl","is-active",name],capture_output=True,text=True,timeout=6)
        return p.stdout.strip() if p.returncode==0 else "not_active_or_unknown"
    except Exception:return "not_available"
def main():
    result={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "read_only":True,"network_probes":False,"restore_backup_present":ROOT.is_dir(),
            "files":{},"services":{}}
    for k,path in FILES.items():
        before=ROOT/(k+".before")
        after=ROOT/(k+".after")
        current=report(path)
        old=report(before)
        staged=report(after)
        row={"current":current,"before":old,"staged":staged,
             "same_as_backup_stage":staged["exists"] and current["sha256"]==staged["sha256"],
             "same_as_before":old["exists"] and current["sha256"]==old["sha256"],
             "owner_same_as_before":old["exists"] and (current["uid"],current["gid"])==(old["uid"],old["gid"]),
             "mode_same_as_before":old["exists"] and current["mode"]==old["mode"]}
        if k=="dns" and old["exists"] and current["exists"]:
            s0=before.read_text()
            s1=path.read_text()
            marker="# Verified Google RU ingress 20261116"
            target='answer "{{ .Name }} 20 IN A 188.120.254.223"'
            replacement='answer "{{ .Name }} 20 IN A 89.125.90.101"'
            expected=(s0[:s0.index(marker)]+
                     s0[s0.index(marker):].replace(target,replacement,1)) if marker in s0 else None
            row.update(
                google_ru_override_marker=marker in s0,
                google_override_replaced_exactly_once=s0[s0.index(marker):].count(target)==1 if marker in s0 else False,
                only_google_ru_to_de_change=expected is not None and s1==expected,
                current_google_ru_literal_count=s1.count(target),
                current_google_de_literal_count=s1.count(replacement),
                old_google_de_literal_count=s0.count(replacement))
        if k=="pilot" and old["exists"] and current["exists"]:
            s0=before.read_text()
            s1=path.read_text()
            expected=re.sub(r'(?m)^([ \t]*proxy_timeout[ \t]+)15m;',r'\g<1>120s;',s0,count=1)
            row.update(
               only_proxy_timeout_change=(expected==s1),
               original_15m_count=len(re.findall(r'(?m)^\s*proxy_timeout\s+15m;',s0)),
               current_120s_count=len(re.findall(r'(?m)^\s*proxy_timeout\s+120s;',s1)),
               effective_pilot_15449="listen 127.0.0.1:15449" in s1)
        if k=="shared":
            row["shared_nginx_untouched_by_restore"]=row["same_as_before"]
        result["files"][k]=row
    for svc in ("nginx.service","mnebydns-dot.service","mnebydns-googlepilot.service"):
        result["services"][svc]=service(svc)
    # Explicitly check only own timer, without enumerating user config.
    result["recovery_timer"]=service("mnebydns-nov8-google-recovery-20261116143947.timer")
    result["review_pass_core_only_intended_changes"]=(result["files"]["dns"].get("only_google_ru_to_de_change",False) and
           result["files"]["pilot"].get("only_proxy_timeout_change",False) and
           result["files"]["shared"].get("shared_nginx_untouched_by_restore",False))
    print(json.dumps(result,separators=(",",":"),sort_keys=True),flush=True)
main()
