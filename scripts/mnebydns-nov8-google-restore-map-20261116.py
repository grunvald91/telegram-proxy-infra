#!/usr/bin/env python3
"""Structure-only view of confirmed 8 Nov Google routing and current Google routing.
Return public domain/service names only. Never returns customer, cert or secret data.
"""
import datetime,hashlib,json,pathlib,re

BASE=pathlib.Path('/opt/mnebydns-googlepilot-backups/42519046699')
old_paths={"nginx":BASE/"nginx.pilot","core":BASE/"dns.pilot","pilot":BASE/"proxy.pilot"}
now_paths={"nginx":pathlib.Path("/etc/nginx/nginx.conf"),"core":pathlib.Path("/opt/mnebydns-dot/Corefile"),"pilot":pathlib.Path("/etc/mnebydns-googlepilot/nginx.conf")}
roots=("google","youtube","youtu.be","ytimg","ggpht","gstatic","googlevideo","googleusercontent","withgoogle","doubleclick","googleapis","clients6","gvt","googletagmanager")
def google(s):
    return any(x in s.lower() for x in roots)
def ngmaps(src):
    maps=[]
    for x in re.finditer(r'(?m)^\s*map\s+\$ssl_preread_server_name\s+\$(\w+)\s*\{',src):
        block=src[x.end():]
        end=re.search(r"(?m)^\s*\}",block)
        if end is None:continue
        lines=block[:end.start()].splitlines()
        entries=[]
        for line in lines:
            if line.lstrip().startswith("#"):continue
            p=re.fullmatch(r'\s*(\S+)\s+([^;]+);\s*(?:#.*)?',line)
            if not p:continue
            key,target=p.groups()
            if google(key):
                entries.append({"key":key[:250],"backend":target.strip()[:150]})
        maps.append({"variable":x.group(1),"google_entry_count":len(entries),"entries":entries[:130],"all_entry_count":sum(bool(re.match(r'^\s*(\S+)\s+[^;]+;',l)) for l in lines)})
    return maps
def cores(src):
    headers=[(m.group(1),m.group(2)) for m in re.finditer(r'(?m)^\s*template\s+IN\s+(\S+)\s+(\S+)\s*\{',src)]
    counts={}
    for kind,name in headers:
        counts[kind]=counts.get(kind,0)+1
    return {"templates_total":len(headers),"templates_per_kind":counts,"google_named":sorted(set(n for k,n in headers if google(n)))[:160],"google_template_count":sum(google(n) for k,n in headers),
        "nov8_google_marker":"MNEBYDNS 4-service USER CANARY" in src,
        "google_ru_ingress_marker":"Verified Google RU ingress 20261116" in src,
        "external_core_imports":len(re.findall(r'(?m)^\s*import\s+\S+',src)),
        "cache_count":len(re.findall(r'(?m)^\s*cache\s+30(?:\s|\{)',src)),
        "google_video_regexp_count":src.count('googlevideo[.]com'),
        "has_split_google_dns_zone":"tls://www.google.com:853" in src,
        "tail_last_1200": ''.join(re.sub(r'[a-z0-9]{12}\.dns\.mnebyvpn\.site','<id>.dns.mnebyvpn.site',line) for line in src.splitlines(keepends=True)[-30:] if ("Verified Google" in line or "tls://" in line or "template IN" in line or "bind " in line or "cache " in line))[:900]}
def read(path):
    return path.read_text(errors="replace") if path.is_file() else None
data={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"read_only":True,"old":{},"current":{}}
for label,paths in (("old",old_paths),("current",now_paths)):
    for role,p in paths.items():
        s=read(p)
        data[label][role]={"exists":s is not None}
        if s is not None:
            data[label][role].update(sha256=hashlib.sha256(s.encode()).hexdigest(),size=len(s))
            if role=="core":data[label][role]["structure"]=cores(s)
            else:data[label][role]["maps"]=ngmaps(s)
print(json.dumps(data,ensure_ascii=False,sort_keys=True))
