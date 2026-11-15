#!/usr/bin/env python3
"""Read-only compare the active production personal DNS sidecar policy
with old sidecar, including public domain coverage, without leaking identifiers.
"""
import subprocess,json,datetime,sys
def out(k,v):print("POLICYAUDIT_"+k+"="+json.dumps(v,sort_keys=True,ensure_ascii=False),flush=True)
def cmd(argv,timeout=12):
    try:
        p=subprocess.run(argv,text=True,capture_output=True,timeout=timeout)
        return p.stdout,p.returncode
    except Exception:return "",999
out("UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
for container in ("mnebydns-personal-dot","mnebydns-personal-dot-private"):
    raw,rc=cmd(["docker","inspect",container],12)
    if rc!=0:
        out(container+"_PRESENT",False);continue
    j=json.loads(raw)[0]
    out(container+"_RUNTIME",{"status":j.get("State",{}).get("Status"),
                               "restart_count":j.get("RestartCount"),
                               "started_at":j.get("State",{}).get("StartedAt"),
                               "mount_destinations":[r.get("Destination") for r in j.get("Mounts",[]) if "policy" in r.get("Destination","").lower() or "mnebydns" in r.get("Destination","").lower()][:12]})
    # Executes a read-only Node inspection inside the existing container.
    # It reads only configured public policy patterns, not credentials/DB.
    js=r'''
const fs=require("fs"),crypto=require("crypto");
const file=process.env.MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_FILE;
const expected=process.env.MNEBYDNS_PERSONAL_DOT_ROUTE_POLICY_SHA256;
if(!file){console.log(JSON.stringify({policy_file_configured:false}));process.exit(0);}
const buf=fs.readFileSync(file);
const arr=JSON.parse(buf);
const keys=new Set(arr);
const check=(domain)=>keys.has(domain)||Array.from(keys).some(z=>z.startsWith("*.")&&domain.endsWith(z.slice(1)));
const names=["youtube.com","www.youtube.com","rr1---sn-gxuo03g-ig3s.googlevideo.com","chatgpt.com","generativelanguage.googleapis.com","groq.com","oracle.com","copilot.microsoft.com","antigravity.google","claude.ai"];
console.log(JSON.stringify({policy_file_configured:true,route_count:arr.length,
duplicates:arr.length-keys.size,sha256:crypto.createHash("sha256").update(buf).digest("hex"),
expected_hash_matches:expected===crypto.createHash("sha256").update(buf).digest("hex"),
domain_coverage:Object.fromEntries(names.map(n=>[n,check(n)]))}));
'''
    raw,rc=cmd(["docker","exec",container,"node","-e",js],15)
    if rc==0:
        try:out(container+"_POLICY",json.loads(raw.strip().splitlines()[-1]))
        except Exception:out(container+"_POLICY",{"parse_error":True})
    else:out(container+"_POLICY",{"inspect_failed":True})
out("DONE",True)
