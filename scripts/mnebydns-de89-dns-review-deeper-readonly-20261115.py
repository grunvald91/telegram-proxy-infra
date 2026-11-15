#!/usr/bin/env python3
"""Read-only deeper DNS review: Nginx config test, watchdog failure modes,
CoreDNS duplicate template selectors and backend health. No secret content."""
import pathlib,subprocess,datetime,re,json,collections,sys,time,os
def p(k,v):print("DEEPDNS_"+k+"="+json.dumps(v,sort_keys=True,ensure_ascii=False),flush=True)
def run(argv,secs=12):
    try:
        f=subprocess.run(argv,capture_output=True,text=True,timeout=secs)
        return (f.returncode,f.stdout,f.stderr)
    except Exception as ex:return (999,"",type(ex).__name__)
p("UTC",datetime.datetime.now(datetime.timezone.utc).isoformat())
unit="/etc/mnebydns/personal-sni/nginx.conf"
if pathlib.Path(unit).is_file():
    status,_,stderr=run(["nginx","-t","-c",unit],8)
    errors=[]
    for l in stderr.splitlines()[-10:]:
        if re.search(r"(?:error|invalid|failed|permission|module|bind|duplicate|syntax|cycle|pid|emerg)",l,re.I):
            # Only a static error category; avoid printing arbitrary config snippets
            kinds=[]
            for tag in ("permission denied","unknown directive","unknown variable","duplicate","module","invalid","configuration file",
                        "bind","already in use","no such file","emerg","syntax","pid","open()"):
                if tag in l.lower():kinds.append(tag)
            errors.append(kinds or ["other"])
    p("SNI_NGINX_TEST",{"exit_code":status,"error_categories":errors})
    q=pathlib.Path("/run/mnebydns-personal-sni.pid")
    p("SNI_PID_FILE",{"exists":q.exists(),"symlink":q.is_symlink()})
    p("SNI_CERT_MODE",None)
    st,_,_=run(["systemctl","is-active","mnebydns-personal-sni-stream.service"])
    p("SNI_UNIT_RUNNING",st==0)
for target in ("/usr/local/sbin/mnebydns-personal-sni-watch","/etc/mnebydns/personal-sni/nginx.conf"):
    q=pathlib.Path(target)
    if q.is_file():
        t=q.read_text(errors="replace")
        p("SOURCE_FEATURE_"+q.name,{
            "watch_disables_redirect":bool(re.search(r"systemctl\s+stop\s+mnebydns-personal-sni-redirect",t)),
            "watch_reenables_redirect":bool(re.search(r"systemctl\s+(?:start|enable|restart)\s+mnebydns-personal-sni-redirect",t)),
            "uses_3_consecutive_failures":"failures < 3" in t,
            "checks_personal_tls":("aaaaaaaaaaaa.dns.mnebyvpn.site" in t),
            "checks_real_personal_dns_query":("qname" in t and "aaaaaaaaaaaa.dns.mnebyvpn.site" in t),
            "proxy_origin_8856":"10.66.77.2:8856" in t,
            "personal_nginx_listens_all":"listen 0.0.0.0:8854;" in t
        })
# Current Corefile: identify duplicates and possibly mismatched DNS template selectors, no labels emitted.
core=pathlib.Path("/opt/mnebydns-dot/Corefile")
if core.is_file():
    t=core.read_text(errors="replace")
    templates=[]
    for m in re.finditer(r"(?m)^\s*template\s+(IN|CH)\s+([A-Z0-9\s]+?)\s*\{",t):
        part=t[m.end():]
        # Brace match to avoid treating nested template blocks as separate or confusing nested configs.
        depth=1;i=0
        while i<len(part) and depth:
            if part[i]=="{":depth+=1
            elif part[i]=="}":depth-=1
            i+=1
        block=part[:i]
        match=re.findall(r'(?m)^\s*match\s+([^\n]+)',block)
        templates.append({"type":m.group(2).strip(),"match":match[:3],
                          "answer_count":len(re.findall(r"(?m)^\s*answer\s+",block))})
    keys=collections.Counter((z["type"],tuple(z["match"])) for z in templates)
    dup=[(k,v) for k,v in keys.items() if v>1]
    p("CORE_TEMPLATE_SHAPE",{
        "parsed_templates":len(templates),"raw_template_count":len(re.findall(r"(?m)^\s*template\b",t)),
        "duplicate_selectors":len(dup),
        "max_repeats":max(keys.values()) if keys else 0,
        "duplicated_selector_examples":list(map(lambda kv:{"rtype":kv[0][0],"repeats":kv[1]},dup[:6])),
        "types":dict(collections.Counter(z["type"] for z in templates)),
        "empty_answer_templates":sum(z["answer_count"]==0 for z in templates),
        "zero_match_templates":sum(not z["match"] for z in templates),
    })
# Watchdog history summary only, no direct journal raw lines or customer info.
s,stdout,_=run(["journalctl","-u","mnebydns-personal-sni-watch.service",
                "--since","2026-11-13 00:00:00","-o","short-iso","--no-pager"],16)
events=[]
for l in stdout.splitlines():
    if any(k in l for k in ("PERSONAL_SNI_WATCH=","PERSONAL_SNI_WATCH_CONSECUTIVE_FAILURES")):
        t=re.search(r"^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)",l)
        msg=l.split("PERSONAL_SNI_",1)[1].strip()
        # Do not include hostnames, tokens or IPs: only stable known event enums.
        if any(tag in msg for tag in ("FELL_BACK","FAILURES=","COREDNS_ORIGIN_UNHEALTHY","HEALTHY_NO_CHANGES","NO_PERSONAL_REDIRECT")):
            events.append((t.group(1) if t else "unknown",msg[:85]))
p("WATCH_STATUS_HISTORY",{"selected_events":len(events),
  "fallback_events":[x for x in events if "FELL_BACK" in x[1]][-6:],
  "consecutive_failure_events":[x for x in events if "FAILURES=" in x[1]][-12:],
  "healthy_count":sum("HEALTHY_NO_CHANGES" in x[1] for x in events)})
p("DONE",True)
