#!/usr/bin/env python3
"""On-node read-only comparison of Nov8 Google policy with production.

No packet captures, DNS requests, client information, or private keys.
"""
from pathlib import Path
import datetime
import hashlib
import json
import re
from collections import Counter
def original_template_parity(original, current):
    pattern=re.compile(r"(?ms)^[ \t]*template IN (A|AAAA|HTTPS|SVCB|CNAME) (\S+) \{(.*?)^[ \t]*\}")
    def parse(src):
        result=[]
        for m in pattern.finditer(src):
            body=m.group(3)
            vals=[tuple(x.strip() for x in re.findall(r"(?m)^\s*"+w+r"\s+(.+)$",body))
                  for w in ("match","answer","rcode")]
            result.append((m.group(1),m.group(2),*vals))
        return result
    before,after=parse(original),parse(current)
    if len(before) < 300 or len(after) < len(before):
        raise ValueError('No genuine historical CoreDNS template coverage; refuse false PASS')
    diff=Counter(before)-Counter(after)
    # Five Nov8 wildcard templates were expanded to additional Google
    # domains. Their regex strings differ, but outputs may be equivalent.
    old_roots=("googlevideo.com","ytimg.com","ggpht.com","gstatic.com",
               "googleusercontent.com","youtube.com","youtube-nocookie.com",
               "withgoogle.com")
    samples=[n+"." for root in old_roots for n in (root,"r1---sn-test."+root)]
    candidates=list(after)
    expanded=[]
    unresolved=[]
    for item in diff.elements():
        kind,zone,oldmatch,oldanswer,oldrcode=item
        if zone!="." or len(oldmatch)!=1:
            unresolved.append((kind,zone))
            continue
        try:
            oldrx=re.compile(oldmatch[0])
            old_samples=[s for s in samples if oldrx.fullmatch(s)]
        except re.error:
            unresolved.append((kind,zone))
            continue
        if len(old_samples)!=len(samples):
            unresolved.append((kind,zone))
            continue
        compatible=False
        for candidate in candidates:
            t,z,match,answer,rcode=candidate
            if t!=kind or z!=zone or answer!=oldanswer or rcode!=oldrcode or len(match)!=1:
                continue
            try:rx=re.compile(match[0])
            except re.error:continue
            if all(rx.fullmatch(s) for s in old_samples):
                compatible=True
                break
        if compatible:expanded.append(kind)
        else:unresolved.append((kind,zone))
    return {"historical_templates":len(before),"current_templates":len(after),
            "missing_or_changed_historical":sum(diff.values()),
            "missing_templates":[{"kind":item[0],"zone":item[1],"match":str(item[2])[:180],
                                  "expected_de89": "89.125.90.101" in str(item[3]),
                                  "expected_ru188": "188.120.254.223" in str(item[3])}
                                 for item in diff.elements()][:12],
            "historical_rr_types":sorted(set(x[0] for x in before)),
            "all_historical_rules_retained":not diff,
            "equivalent_widened_historical_rr_types":sorted(expanded),
            "unresolved_historical_rr_types":sorted(set(k for k,_ in unresolved)),
            "historical_semantics_covered_by_exact_or_wider_rule":not unresolved}


BASE=Path("/opt/mnebydns-googlepilot-backups/42519046699")
core_old=(BASE/"dns.pilot").read_text()
core_now=Path("/opt/mnebydns-dot/Corefile").read_text()
nginx_old=(BASE/"nginx.pilot").read_text()
nginx_now=Path("/etc/nginx/nginx.conf").read_text()
pilot_old=(BASE/"proxy.pilot").read_text()
pilot_now=Path("/etc/mnebydns-googlepilot/nginx.conf").read_text()
def names(src,variable):
    pattern=r"(?m)^\s*map\s+\$ssl_preread_server_name\s+\$"+re.escape(variable)+r"\s*\{"
    m=re.search(pattern,src)
    if not m:raise ValueError("missing expected nginx SNI map "+variable)
    end=re.search(r"(?m)^\s*\}",src[m.end():])
    if not end:raise ValueError("unterminated SNI map")
    block=src[m.end():m.end()+end.start()]
    return dict((h,v.strip()) for h,v in re.findall(r"(?m)^\s*([A-Za-z0-9._-]+)\s+([^;\n]+);",block)
                if h not in ("default","hostnames"))
old_names=names(nginx_old,"direct_mtproxy_backend")
now_names=names(nginx_now,"direct_mtproxy_backend")
old_pilot_names=names(pilot_old,"experimental_origin")
now_pilot_names=names(pilot_now,"experimental_origin")
missing_nginx=sorted(n for n,v in old_names.items() if now_names.get(n)!=v)
missing_pilot=sorted(n for n,v in old_pilot_names.items() if now_pilot_names.get(n)!=v)
prefix="~*^(?:[a-z0-9-]+"
# Nginx SNI source may include several regex rules. Compare only Google regex.
def google_pattern(src):
    lines=[line.strip().split()[0] for line in src.splitlines()
           if line.lstrip().startswith("~*") and "googlevideo" in line and "ytimg" in line]
    if len(lines)!=1:raise ValueError("expected one Google media SNI regex")
    return lines[0]
old_reg=google_pattern(nginx_old)
new_reg=google_pattern(nginx_now)
pilot_old_reg=google_pattern(pilot_old)
pilot_now_reg=google_pattern(pilot_now)
samples=("rr2---sn-abc.googlevideo.com","www.ytimg.com","r1.ggpht.com",
         "cdn.gstatic.com","r.googleusercontent.com","www.youtube.com",
         "www.youtube-nocookie.com","www.withgoogle.com")
def matched(pattern,item):
    return bool(re.fullmatch(pattern[2:],item,re.I))
regex_all=all(not matched(old_reg,n) or matched(new_reg,n) for n in samples)
pilot_regex_all=all(not matched(pilot_old_reg,n) or matched(pilot_now_reg,n) for n in samples)
core_report=original_template_parity(core_old,core_now)
# 6-host late override was restored to foreign DE ingress.
zone="# Verified Google RU ingress 20261116"
later=core_now.split(zone,1)[1] if core_now.count(zone)==1 else ""
post={"utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
      "read_only":True,"no_server_changes":True,
      "historical_googles":len(old_names),
      "historical_pilot_origins":len(old_pilot_names),
      "missing_or_changed_8nov_exact_nginx":missing_nginx,
      "missing_or_changed_8nov_exact_pilot":missing_pilot,
      "original_google_media_regex_covered":regex_all,
      "original_pilot_media_regex_covered":pilot_regex_all,
      "google_dns_rr_template_parity":core_report,
      "later_six_host_zone_present":bool(later),
      "later_six_host_zone_targets_de":'answer "{{ .Name }} 20 IN A 89.125.90.101"' in later,
      "later_six_host_zone_targets_ru":'answer "{{ .Name }} 20 IN A 188.120.254.223"' in later,
      "original_googlepilot_idle_timeout_seconds":120 if "proxy_timeout 120s;" in pilot_old else None,
      "current_googlepilot_idle_timeout_seconds":120 if "proxy_timeout 120s;" in pilot_now else None,
      "historical_source_snapshot_hash":hashlib.sha256((BASE/"dns.pilot").read_bytes()).hexdigest()
      }
print(json.dumps(post,sort_keys=True))
