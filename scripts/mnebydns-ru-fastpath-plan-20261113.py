#!/usr/bin/env python3
"""Guarded plan to route explicit verified HTTPS hostnames to RU ingress.

NO production updates. Rewrites only one existing *exact-match* A template
per proven service. Keeps all AAAA/HTTPS/SVCB/CNAME, DoT, Nginx and VPN
unchanged. Enables independent deploy preparation only after a dry-run.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import sys

ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/"fastpath-ru-plan"
SRC=ROOT/"scripts/mnebydns-owner-domain-controller-20261110.py"
spec=importlib.util.spec_from_file_location("fastpath_controller",SRC)
assert spec and spec.loader
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)
PUBLIC_DE="89.125.90.101"
PUBLIC_RU="188.120.254.223"
# All listed hostnames have been observed with verified original-SNI TLS on
# RU ingress in GitHub Actions #43407406542, except the deliberately
# excluded community.teamviewer.com (HTTP timeout). Excludes IG/Threads.
CANDIDATES=(
    "claude.ai","api.anthropic.com","gemini.google.com",
    "www.youtube.com","grok.com","x.com","www.tiktok.com",
    "cloud.oracle.com","id.cisco.com","codebrowser.dev",
    "copilot.microsoft.com",
)
HEADER=re.compile(r"(?m)^[ \t]*template[ \t]+IN[ \t]+A[ \t]+([^ \t\r\n{}]+)[ \t]*\{")
ANSWER=re.compile(r'(?m)^(?P<indent>[ \t]*)answer[ \t]+"\{\{ \.Name \}\}[ \t]+(?P<ttl>[0-9]+)[ \t]+IN[ \t]+A[ \t]+89\.125\.90\.101"[ \t]*$')
MATCH=re.compile(r"(?m)^[ \t]*match[ \t]+([^ \t\r\n{}]+)[ \t]*$")

def blocks(core):
    items=[]
    for m in HEADER.finditer(core):
        depth=1
        i=m.end()
        while i<len(core) and depth:
            if core[i]=="{":depth+=1
            elif core[i]=="}":depth-=1
            i+=1
        if depth:raise RuntimeError("Malformed CoreDNS template braces")
        items.append((m.start(),i,m.group(1),core[m.end():i-1]))
    return items

def exact_regex(pattern,host):
    if not pattern.startswith("^") or not pattern.endswith("$"):return False
    try:
        if not re.search(pattern,host+"."):return False
        # Reject any wildcard family match, suffix capture, or arbitrary names.
        for sibling in ("x."+host+".",host+".evil.","unrelated.example."):
            if re.search(pattern,sibling):return False
        return True
    except re.error: return False

def render(core):
    matches={}
    block_list=blocks(core)
    for host in CANDIDATES:
        owner._render.validate_domain(host)
        hits=[]
        for start,end,zone,body in block_list:
            parsed=MATCH.findall(body)
            if len(parsed)!=1 or not exact_regex(parsed[0],host):continue
            z=zone.rstrip(".")
            if z not in (".","",host) and not host.endswith("."+z):
                continue
            hits.append((start,end,body))
        if len(hits)>1:raise RuntimeError("Ambiguous route template for "+host)
        if not hits:
            matches[host]={"state":"EXACT_A_TEMPLATE_NOT_FOUND"}
            continue
        start,end,body=hits[0]
        valid=ANSWER.findall(body)
        if len(valid)!=1:
            matches[host]={"state":"EXPECTED_DE_A_ANSWER_NOT_FOUND"}
            continue
        if int(valid[0][1]) not in range(1,3601):
            raise RuntimeError("Unexpected A TTL for "+host)
        matches[host]={"state":"ELIGIBLE","ttl":int(valid[0][1]),"span":(start,end)}
    selected=[host for host in CANDIDATES if matches[host]["state"]=="ELIGIBLE"]
    # Replace entire template blocks in reverse order. An owner-only
    # exact-host template may be included alongside legacy zones.
    spans=[]
    for host in selected:
        start,end=matches[host]["span"]
        raw=core[start:end]
        edited,n=ANSWER.subn(lambda m: m.group(0).replace(PUBLIC_DE,PUBLIC_RU),raw,count=1)
        if n!=1 or edited==raw:raise RuntimeError("A rule mutation not exact")
        spans.append((start,end,edited,host))
    if len({(start,end) for start,end,_,_ in spans})!=len(spans):
        raise RuntimeError("Two requested domains share one CoreDNS template")
    candidate=core
    for start,end,edited,_ in sorted(spans,reverse=True):
        candidate=candidate[:start]+edited+candidate[end:]
    if len(selected)<3 or candidate==core:
        raise RuntimeError("No sufficiently scoped explicit A rules can be safely rerouted")
    for host in selected:
        matches[host].pop("span")
    return candidate,matches,selected

def remote_file(role,filename):
    # SSH strips surrounding whitespace, so read exact bytes via lowercase
    # hex without any decoded text normalization or accidental log exposure.
    query=("python3 -c "+shlex.quote(
        "import sys;sys.stdout.write(open(sys.argv[1],'rb').read().hex())")+
        " "+shlex.quote(filename))
    raw=owner.ssh(role,query,55)
    return bytes.fromhex(raw).decode("utf-8")

def plan():
    if not owner.live_checkpoint_unchanged():raise RuntimeError("STABLE_CHECKPOINT_DRIFT")
    core=remote_file("de","/opt/mnebydns-dot/Corefile")
    next_core,states,selected=render(core)
    if not owner.live_checkpoint_unchanged():raise RuntimeError("STABLE_CHANGED_DURING_RENDER")
    OUT.mkdir(mode=0o700,exist_ok=True)
    for name,content in (("dns.before",core),("dns.pilot",next_core)):
        f=OUT/name
        if f.exists():raise RuntimeError("Refuse to overwrite a prepared route plan")
        f.write_text(content)
        f.chmod(0o600)
    evidence={
        "read_only":True,"scope":"exact A answers only; no other RR or Nginx changes",
        "proven_ru_tls_reference":"https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43407406542",
        "all_live_exact_tls_reference":"https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43408002870",
        "candidate_total":len(CANDIDATES),"selected_count":len(selected),
        "selected":selected,
        "excluded":[{"domain":x,"reason":states[x]["state"]} for x in CANDIDATES if x not in selected],
        "sha_before":hashlib.sha256(core.encode()).hexdigest(),
        "sha_pilot":hashlib.sha256(next_core.encode()).hexdigest(),
    }
    (OUT/"plan.json").write_text(json.dumps(evidence,indent=2,ensure_ascii=False)+"\n")
    (OUT/"report.md").write_text("# RU ingress fast path read-only preparation\n\n"+
      "Scope: exact A template answers only. No DNS route changed.\n\n"+
      "Selected: "+str(len(selected))+"/"+str(len(CANDIDATES))+
      "\n\n## Candidate domains\n"+
      "\n".join("- `"+x+"`: "+states[x]["state"] for x in CANDIDATES)+"\n")
    print("FASTPATH_PLAN_SELECTED="+json.dumps(selected),flush=True)
    print("FASTPATH_PLAN_EXCLUDED="+json.dumps(evidence["excluded"]),flush=True)
    print("FASTPATH_PREP_READONLY=PASS",flush=True)

def self_test():
    sample=('tls://.:853 {\n'
      '  template IN A claude.ai {\n'
      '    match ^claude[.]ai[.]$\n'
      '    answer "{{ .Name }} 20 IN A 89.125.90.101"\n'
      '    fallthrough\n'
      '  }\n'
      '  template IN A . {\n'
      '    match ^cloud[.]oracle[.]com[.]$\n'
      '    answer "{{ .Name }} 20 IN A 89.125.90.101"\n'
      '    fallthrough\n'
      '  }\n'
      '  template IN A . {\n'
      '    match ^id[.]cisco[.]com[.]$\n'
      '    answer "{{ .Name }} 20 IN A 89.125.90.101"\n'
      '    fallthrough\n'
      '  }\n'
      '  cache 30\n}\n')
    rendered,states,selected=render(sample)
    assert len(selected)==3
    assert rendered.count(" IN A 188.120.254.223")==3
    assert rendered.count(" IN A 89.125.90.101")==0
    assert "  cache 30" in rendered
    assert exact_regex("^claude[.]ai[.]$","claude.ai")
    assert not exact_regex("^.*claude[.]ai[.]$","claude.ai")
    print("FASTPATH_RENDER_OFFLINE=PASS",flush=True)

if __name__=="__main__":
    if sys.argv[1:]==["--self-test"]:self_test()
    elif sys.argv[1:]==["--plan"]:plan()
    else:raise SystemExit("Usage: --self-test|--plan")
