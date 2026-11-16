#!/usr/bin/env python3
"""Guarded on-node production Google routing restore from exact November 8 2026 checkpoint.

Changes only Google-specific DNS A ingress, legacy Google SNI entries,
and GooglePilot upstream timeouts; preserves all added domain catalog entries,
personal DNS access, subscription data, certificates and VPN.
No recurrent external probes or packet captures.
"""
from __future__ import annotations
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

SNAP=Path("/opt/mnebydns-googlepilot-backups/42519046699")
ACTIVE={
 "dns":Path("/opt/mnebydns-dot/Corefile"),
 "shared":Path("/etc/nginx/nginx.conf"),
 "pilot":Path("/etc/mnebydns-googlepilot/nginx.conf")
}
ORIG={"dns":SNAP/"dns.pilot","shared":SNAP/"nginx.pilot","pilot":SNAP/"proxy.pilot"}
# Compare byte-for-byte with what was read today; abort instead of overwriting
# later user changes.
EXPECTED_ACTIVE={
 "dns":"8a9256119353ed85a3839d127a5e767e6c8aa2271e817bf52c4e0e123adb43e7",
 "shared":"d4acc6190fc0ff20258412a6ca3b059e0f68f4601b2955bbf24ebd894d8decf8",
 "pilot":"d7f7458d71daaf8b651b909f66583433e2b38dc62df55571c5d83bd7e88bb0e6"
}
EXPECTED_ORIG={
 "dns":"32707b722c732217f9a29fcffeb0af6f3173e6ac98b197372527dce13824b358",
 "shared":"034e3e11bd5446e6d3dfa62c7605c1e482ef824dac6b7b93c9375881dc6a8a69",
 "pilot":"375c1837f9bc474edbb05fe786e6725616d2cd92cfb1109c0cc91b775e3ac523"
}
OUT={"operation":"restore_original_2026_11_08_all_existing_google_domains",
     "utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
     "non_google_routes_preserved":True,"customer_access_untouched":True,
     "source_run_id":"42519046699"}

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()
def run(argv,timeout=20):
    p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout)
    if p.returncode:
        raise RuntimeError(argv[0]+" exit="+str(p.returncode)+" "+p.stderr[-140:])
    return p.stdout
def block(src,variable):
    pattern=r"(?m)^[ \t]*map[ \t]+\$ssl_preread_server_name[ \t]+\$"+re.escape(variable)+r"[ \t]*\{"
    ms=list(re.finditer(pattern,src))
    if len(ms)!=1:raise ValueError("Cannot find unique Google SNI map "+variable)
    a=ms[0].end()
    m=re.search(r"(?m)^[ \t]*\}[ \t]*(?:#.*)?$",src[a:])
    if not m:raise ValueError("No SNI map end")
    return a,a+m.start()
def entries(body):
    result={}
    for match in re.finditer(r"(?m)^[ \t]*(\S+)[ \t]+([^;\n]+);[ \t]*(?:#.*)?$",body):
        key=match.group(1)
        if key in result:raise ValueError("Duplicate SNI map key "+key[:60])
        result[key]=match.group(2).strip()
    return result
def restore_google_map(current, original,variable):
    ca,cb=block(current,variable)
    oa,ob=block(original,variable)
    original_entries=entries(original[oa:ob])
    current_entries=entries(current[ca:cb])
    if not (len(original_entries)>=60 and len(current_entries)>=len(original_entries)):
        raise ValueError("November 8 SNI map unexpectedly incomplete")
    # Restore exact owned Google host entries; preserve all later entries and
    # other services, including later additional Google routes.
    original_exact={k:v for k,v in original_entries.items()
        if not k.startswith("~") and k not in ("default","hostnames","volatile","include")
        and (v=="127.0.0.1:15449" or variable=="experimental_origin" and v.endswith(":443")
             or k in ("www.google.com","gemini.google.com"))}
    updated=current[ca:cb]
    altered=[]
    for name,target in original_exact.items():
        pattern=r"(?m)^([ \t]*)"+re.escape(name)+r"([ \t]+)([^;\n]+);"
        found=list(re.finditer(pattern,updated))
        if len(found)!=1:raise ValueError("Original Google SNI key missing/duplicate "+name)
        if found[0].group(3).strip()!=target:
            updated=re.sub(pattern,lambda m:m.group(1)+name+m.group(2)+target+";",updated,count=1)
            altered.append(name)
    # The dynamic media suffixes from Nov8 must remain routed to the isolated
    # GooglePilot. Current config extends them (needed for all Google domains).
    older_regex=[(k,v) for k,v in original_entries.items() if k.startswith("~")]
    newer_regex=[(k,v) for k,v in current_entries.items() if k.startswith("~")
             and "googlevideo" in k and "ytimg" in k]
    if len(older_regex)!=1 or len(newer_regex)!=1:raise ValueError("Google media regex missing or ambiguous")
    original_roots=re.findall(r"([a-z-]+)\\[.]com",older_regex[0][0])
    # The broader current regex must contain every 8 Nov media family.
    for root in ("googlevideo","ytimg","ggpht","gstatic","googleusercontent","youtube","withgoogle"):
        if root not in newer_regex[0][0]:
            raise ValueError("Missing historical media family "+root)
    if newer_regex[0][1] != older_regex[0][1]:
        pattern=r"(?m)^([ \t]*)"+re.escape(newer_regex[0][0])+r"([ \t]+)([^;\n]+);"
        if len(re.findall(pattern,updated))!=1:raise ValueError("Unexpected Google media mapping")
        updated=re.sub(pattern,lambda m:m.group(1)+newer_regex[0][0]+m.group(2)+older_regex[0][1]+";",updated,count=1)
        altered.append("google_media_family")
    return current[:ca]+updated+current[cb:],altered,len(original_exact),len(current_entries)

def restore_dns(current,original):
    if "MNEBYDNS 4-service USER CANARY" not in current or "MNEBYDNS 4-service USER CANARY" not in original:
        raise ValueError("Original November 8 Google DNS rules were not retained")
    # Check that all original Google domain route templates are retained.
    original_hosts=re.findall(r"(?m)^[ \t]*template IN A (\S+) \{",original)
    present_hosts=re.findall(r"(?m)^[ \t]*template IN A (\S+) \{",current)
    for host in set(original_hosts)-{"."}:
        if host not in present_hosts:
            raise ValueError("Missing original Google DNS template "+host)
    for root in ("googlevideo","ytimg","ggpht","gstatic","googleusercontent","youtube","youtube-nocookie","withgoogle"):
        if root not in current:raise ValueError("Current Google DNS missing 8 Nov suffix "+root)
    marker="# Verified Google RU ingress 20261116"
    if current.count(marker)!=1:raise ValueError("Expected later RU Google override not found exactly once")
    start=current.index(marker)
    head,tail=current[:start],current[start:]
    # The appended 16 Nov block contains only 6 Google API web hosts; restore
    # foreign ingress A answers, while preserving the extended domain coverage.
    for name in ("www.google.com","generativelanguage.googleapis.com","daily-cloudcode-pa.googleapis.com",
                 "play.googleapis.com","aicode.googleapis.com","oauth2.googleapis.com"):
        if "tls://"+name+":853" not in tail:raise ValueError("Unexpected later Google zone list")
    old='answer "{{ .Name }} 20 IN A 188.120.254.223"'
    if tail.count(old)!=1:raise ValueError("Later Google-only A override changed unexpectedly")
    tail=tail.replace(old,'answer "{{ .Name }} 20 IN A 89.125.90.101"',1)
    assert head==current[:start]
    return head+tail, len(set(original_hosts)-{"."})

def restore_pilot(current,original):
    merged,altered,exact,total=restore_google_map(current,original,"experimental_origin")
    # Restore the exact 8 Nov Googlepilot stream proxy timeout while retaining
    # modern additional Google domain names and resource improvements.
    o=re.findall(r"(?m)^[ \t]*proxy_timeout[ \t]+([^;]+);",original)
    c=re.findall(r"(?m)^[ \t]*proxy_timeout[ \t]+([^;]+);",merged)
    if o!=["120s"] or len(c)!=1:raise ValueError("Googlepilot original/current timeout drift")
    if c!=o:
        merged=re.sub(r"(?m)^([ \t]*proxy_timeout[ \t]+)[^;]+;",r"\g<1>120s;",merged,count=1)
        altered.append("proxy_timeout")
    # Original specific resolver and upstream behaviour is maintained.
    for directive in ("ssl_preread on;","proxy_pass $experimental_origin;",
                      "resolver 9.9.9.9 ipv6=off valid=30s;"):
        if directive not in merged:raise ValueError("Legacy GooglePilot directive missing")
    return merged,altered,exact,total

def durable(path,data,mode):
    tmp=path.with_name(path.name+".restoring-nov8")
    with open(tmp,"wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp,mode)
    os.replace(tmp,path)

def main():
    if os.geteuid()!=0:raise PermissionError("Root required")
    for key in ACTIVE:
        if sha(ACTIVE[key])!=EXPECTED_ACTIVE[key]:
            raise ValueError("Production config drift; fail closed: "+key)
        if sha(ORIG[key])!=EXPECTED_ORIG[key]:
            raise ValueError("Historical snapshot signature mismatch: "+key)
        if ACTIVE[key].is_symlink():raise ValueError("Cannot replace linked file "+key)
    current={k:p.read_text() for k,p in ACTIVE.items()}
    orig={k:p.read_text() for k,p in ORIG.items()}
    newdns,old_hosts=restore_dns(current["dns"],orig["dns"])
    newshared,sh,old_entries,now_entries=restore_google_map(current["shared"],orig["shared"],"direct_mtproxy_backend")
    newpilot,pi,old_pilot,now_pilot=restore_pilot(current["pilot"],orig["pilot"])
    new={"dns":newdns,"shared":newshared,"pilot":newpilot}
    changed=[k for k in new if new[k]!=current[k]]
    OUT.update(
      nov8_google_a_hosts_retained=old_hosts,nov8_google_exact_sni_retained=old_entries,
      later_google_sni_retained=now_entries,nov8_pilot_origins_retained=old_pilot,
      later_google_pilot_origins_retained=now_pilot,
      restored_sni_differences=sh,restored_pilot_differences=pi,
      updated_files=changed,
      ru_google_override_restored_to_de89=True)
    if not changed:
        OUT.update(done=True,changed=False)
        print(json.dumps(OUT,sort_keys=True));return
    stamp=datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup=Path("/var/backups")/("mnebydns-nov8-google-restore-"+stamp)
    backup.mkdir(mode=0o700)
    for k in ACTIVE:
        shutil.copy2(ACTIVE[k],backup/(k+".before"))
    OUT["rollback_backup"]=str(backup)
    for k in changed:
        p=backup/(k+".after")
        p.write_text(new[k])
        p.chmod(0o600)
    if "shared" in changed:
        run(["/usr/sbin/nginx","-t","-c",str(backup/"shared.after")],timeout=15)
    if "pilot" in changed:
        run(["/usr/sbin/nginx","-t","-c",str(backup/"pilot.after")],timeout=15)
    # Recovery independent of this SSH/GitHub process.
    rollback=backup/"rollback.sh"
    rollback.write_text(
      "#!/bin/bash\nset -Eeuo pipefail\n"
      "for name in "+ " ".join(changed)+"; do\n"
      " case \"$name\" in dns) target=/opt/mnebydns-dot/Corefile;;"
      " shared) target=/etc/nginx/nginx.conf;;"
      " pilot) target=/etc/mnebydns-googlepilot/nginx.conf;; esac\n"
      " cp -p "+str(backup)+"/$name.before \"$target\"\n"
      "done\n"
      ("systemctl restart mnebydns-dot.service\n" if "dns" in changed else "")+
      ("nginx -s reload -c /etc/mnebydns-googlepilot/nginx.conf\n" if "pilot" in changed else "")+
      ("systemctl reload nginx\n" if "shared" in changed else "")
    )
    rollback.chmod(0o700)
    unit="mnebydns-nov8-google-recovery-"+stamp.replace("-","")
    timer_active=False
    any_applied=False
    try:
        run(["systemd-run","--quiet","--unit="+unit,"--on-active=6m",
             "/bin/bash",str(rollback)],timeout=12)
        timer_active=True
        for k in changed:
            p=ACTIVE[k]
            mode=p.stat().st_mode & 0o777
            durable(p,new[k].encode(),mode)
            any_applied=True
        if "shared" in changed:
            run(["/usr/sbin/nginx","-t"],timeout=12)
            run(["systemctl","reload","nginx"],timeout=14)
        if "pilot" in changed:
            run(["/usr/sbin/nginx","-t","-c",str(ACTIVE["pilot"])],timeout=12)
            run(["/usr/sbin/nginx","-s","reload","-c",str(ACTIVE["pilot"])],timeout=14)
        if "dns" in changed:
            run(["systemctl","restart","mnebydns-dot.service"],timeout=30)
        for svc in ("nginx.service","mnebydns-dot.service","mnebydns-googlepilot.service"):
            if run(["systemctl","is-active",svc],timeout=9).strip()!="active":
                raise RuntimeError("Expected service not active "+svc)
        for k in changed:
            if sha(ACTIVE[k])!=hashlib.sha256(new[k].encode()).hexdigest():
                raise RuntimeError("Final file changed unexpectedly "+k)
        # Commit: cancel pending watchdog before its deadline.
        run(["systemctl","stop",unit+".timer"],timeout=12)
        timer_active=False
        OUT.update(done=True,changed=True,rollback_armed=False,
                   googlepilot_nov8_timeout="120s",
                   current_google_extra_domains_preserved=True,
                   production_services_healthy=True)
        print(json.dumps(OUT,sort_keys=True),flush=True)
    except Exception:
        if any_applied:
            try:
                run(["/bin/bash",str(rollback)],timeout=50)
                OUT["rolled_back"]=True
                if timer_active:run(["systemctl","stop",unit+".timer"],timeout=12)
            except Exception:
                OUT["rollback_timer_left_armed"]=timer_active
        raise
if __name__=="__main__":
    try:main()
    except Exception as exc:
        OUT.update(done=False,error=type(exc).__name__,reason=str(exc)[:240])
        print(json.dumps(OUT,sort_keys=True),flush=True)
        raise SystemExit(1)
