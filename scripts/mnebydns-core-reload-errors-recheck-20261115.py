#!/usr/bin/env python3
"""Read only CoreDNS reload error classification and actual template match collision audit."""
import subprocess,re,collections,json,pathlib,datetime
def out(k,v):print("COREDIAG_"+k+"="+json.dumps(v,sort_keys=True,ensure_ascii=False),flush=True)
def run(argv):
    try:
        q=subprocess.run(argv,text=True,capture_output=True,timeout=15)
        return q.stdout,q.returncode
    except Exception:return "",999
j,_=run(["journalctl","-u","mnebydns-dot.service","--since","2026-11-15 11:00:00",
          "--no-pager","-o","short-iso"])
samples=[]
for ln in j.splitlines():
    if not any(x in ln.lower() for x in ("fail","reload","error","new config","plugin")):continue
    ts=ln.split(" ",1)[0] if ln.startswith("2026-") else ""
    # redact sensitive domains/IPs/paths from error lines, preserve meaningful error words
    text=ln[ln.find("]: ")+3:] if "]: " in ln else ln[30:]
    text=re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b","IP",text)
    text=re.sub(r"[a-z0-9-]{2,}(?:\.[a-z0-9-]{2,}){2,}","DOMAIN",text,flags=re.I)
    text=re.sub(r"/(?:[a-zA-Z0-9._-]+/){1,}[a-zA-Z0-9._-]+","FILE",text)
    text=text.replace("\n"," ")
    if len(text)>210:text=text[:210]
    samples.append({"ts":ts,"message":text})
out("RELOAD_RECENT",samples[-36:])
p=pathlib.Path("/opt/mnebydns-dot/Corefile")
if p.is_file():
    lines=p.read_text(errors="replace").splitlines()
    # Block parsing: capture per template first match selector and type, without emitting domain names
    defs=[]
    for i,ln in enumerate(lines):
        m=re.match(r"^\s*template\s+(IN|CH)\s+([A-Z0-9]+)\s+(.+?)\s*\{\s*$",ln)
        if not m:continue
        block=[]
        for ln2 in lines[i+1:i+16]:
            block.append(ln2)
            if ln2.strip()=="}":break
        mm=[x.strip().removeprefix("match").strip() for x in block if re.match(r"^\s*match\s+",x)]
        ans=[x.strip().removeprefix("answer").strip() for x in block if re.match(r"^\s*answer\s+",x)]
        defs.append({"type":m.group(2),"zone":m.group(3),"matches":tuple(mm),"ans":tuple(ans),
                     "rcode":tuple(x.strip() for x in block if re.match(r"^\s*rcode\s+",x))})
    freq=collections.Counter((d["type"],d["zone"],d["matches"]) for d in defs)
    duplicates=[(k,c) for k,c in freq.items() if c>1]
    conflicts=[]
    for key,c in duplicates:
        answers=set((x["ans"],x["rcode"]) for x in defs if (x["type"],x["zone"],x["matches"])==key)
        if len(answers)>1:conflicts.append((key,c))
    out("TEMPLATE_COLLISION",{"parsed":len(defs),"duplicate_type_zone_match":len(duplicates),
                              "distinct_answers_for_same_selector":len(conflicts),
                              "missing_match":sum(not z["matches"] for z in defs),
                              "type_counts":dict(collections.Counter(z["type"] for z in defs)),
                              "empty_answer_counts":sum(not z["ans"] for z in defs)})
out("DONE",True)
