#!/usr/bin/env python3
"""Find exact November 8, 2026 Googlepilot production snapshots, without config mutation."""
import datetime,hashlib,json,pathlib,re
root=pathlib.Path("/opt/mnebydns-googlepilot-backups")
wanted=root/"42519046699"
names=("nginx.before","nginx.pilot","dns.before","dns.pilot","proxy.pilot","pilot.service","rollback.sh")
def info(p):
    if not p.is_file():return {"exists":False}
    raw=p.read_bytes()
    result={"exists":True,"sha256":hashlib.sha256(raw).hexdigest(),"size":len(raw)}
    if p.name.endswith((".pilot",".conf")) or p.name in ("Corefile","nginx.conf"):
        s=raw.decode("utf-8","replace")
        result.update(
            googlevideo_marker="googlevideo" in s,
            youtube_marker="youtube.com" in s,
            googlepilot_15449="15449" in s,
            media_regex_count=len([x for x in s.splitlines() if "googlevideo" in x and "map" not in x]),
            proxy_timeout=sorted(set(re.findall(r"(?m)^\s*proxy_timeout\s+([^;]+)",s))),
            server_bind=sorted(set(re.findall(r"(?m)^\s*listen\s+([^;]+)",s)))[:20],
        )
    return result
out={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"changed":False,
     "backup_location":str(wanted),"backup_present":wanted.is_dir(),
     "backup_files":{name:info(wanted/name) for name in names},
     "other_snapshot_directories":sorted(p.name for p in root.iterdir() if p.is_dir() and p.name.isdigit())[-15:] if root.is_dir() else [],
     "active_files":{
         "nginx":info(pathlib.Path("/etc/nginx/nginx.conf")),
         "dns":info(pathlib.Path("/opt/mnebydns-dot/Corefile")),
         "googlepilot":info(pathlib.Path("/etc/mnebydns-googlepilot/nginx.conf")),
     }}
for key,p in (("nginx",pathlib.Path("/etc/nginx/nginx.conf")),("dns",pathlib.Path("/opt/mnebydns-dot/Corefile"))):
    if not p.is_file():continue
    lines=p.read_text(errors="replace").splitlines()
    matches=[]
    for line in lines:
        line=line.strip()
        if any(x in line for x in ("googlevideo", "youtube.com", "ytimg.com", "15449")):
            # Only match domain-bearing config lines; do not echo customer data, tokens or IPs.
            matches.append({"kind": "map" if "15449" in line else "match", "has_video":"googlevideo" in line,
                            "has_ytimg":"ytimg" in line,"has_youtube":"youtube.com" in line,
                            "is_regex":line.startswith("~") or "match " in line,
                            "synthetic_a_de":("89.125.90.101" in line),"synthetic_a_ru":("188.120.254.223" in line)})
    out[key+"_media_lines_summary"]={"total":len(matches),"sample":matches[:45]}
print(json.dumps(out,sort_keys=True))
