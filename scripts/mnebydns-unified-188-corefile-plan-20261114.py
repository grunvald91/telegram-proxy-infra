#!/usr/bin/env python3
"""Guarded shared CoreDNS A-only promotion, retaining exact SNI and personal auth.
All currently DE89-mapped premium host A replies become RU188.
Reuses proven 45-min rollback/checkpoint machinery.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import re
import shlex
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
OUT=ROOT/'unified-188-core-plan'
SRC=ROOT/'scripts/mnebydns-owner-domain-controller-20261110.py'
spec=importlib.util.spec_from_file_location('unified_188_owner',SRC)
assert spec and spec.loader
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)

EDGE='89.125.90.101'
RU='188.120.254.223'
# Selected DNS controls verify exact A templates, broad Google/Meta/OpenAI,
# and both service classes that previously resolved to RU or DE.
SELECTED=(
 'chatgpt.com','auth.openai.com','www.chatgpt.com','android.chat.openai.com',
 'api.openai.com','cdn.oaistatic.com','files.oaiusercontent.com',
 'claude.ai','api.anthropic.com','gemini.google.com',
 'www.youtube.com','youtubei.googleapis.com','www.googlevideo.com',
 'i.ytimg.com','s.ytimg.com','www.tiktok.com',
 'x.com','grok.com','cloud.oracle.com','id.cisco.com',
 'codebrowser.dev','microsoft.com','bing.com','copilot.microsoft.com',
)
HEADER=re.compile(r'(?m)^\s*template\s+IN\s+A\s+([^\s{]+)\s*\{')
ANSWER=re.compile(r'(?m)^(\s*answer\s+"\{\{ \.Name \}\}\s+\d+\s+IN\s+A\s+)(89\.125\.90\.101)(")\s*$')

def render(core:str)->tuple[str,int]:
    assert core.count('tls://.:853 {')==1
    assert core.count('    bind 89.125.90.101')==1
    headers=list(HEADER.finditer(core))
    if len(headers)!=264:
        raise RuntimeError('A_TEMPLATE_STRUCTURE_DRIFT '+str(len(headers)))
    if len({x.group(1) for x in headers if x.group(1)!='.'})!=151:
        raise RuntimeError('A_TEMPLATE_UNIQUE_HOST_DRIFT')
    next_core,count=ANSWER.subn(lambda m:m.group(1)+RU+m.group(3),core)
    if count!=253:raise RuntimeError('FOREIGN_A_253_COUNT_DRIFT '+str(count))
    if len(HEADER.findall(next_core))!=len(headers):
        raise RuntimeError('A_TEMPLATE_COUNT_CHANGED')
    if len(re.findall(r'(?m)^\s*answer\s+"\{\{ \.Name \}\}\s+\d+\s+IN\s+A\s+'+re.escape(RU)+r'"',next_core))!=264:
        raise RuntimeError('A_TEMPLATE_NOT_ALL_RU')
    assert 'tls://.:853 {' in next_core and '    bind 89.125.90.101' in next_core
    assert '    reload 5s 1s' in next_core
    assert '    cache 30 {' in next_core
    assert '    forward . tls://9.9.9.9 tls://149.112.112.112 {' in next_core
    assert not re.search(r'(?m)^\s*answer\s+".*\sIN\sA\s89[.]125[.]90[.]101"',next_core)
    if next_core==core:raise RuntimeError('NO_CHANGES')
    return next_core,count

def remote_core():
    # Preserve exact bytes; SSH client strip() would otherwise drop trailing LF.
    query=("python3 -c "+shlex.quote(
        "import sys;sys.stdout.write(open(sys.argv[1],'rb').read().hex())")+
        " /opt/mnebydns-dot/Corefile")
    return bytes.fromhex(owner.ssh('de',query,65)).decode('utf8')

def plan():
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError('STABLE_CHECKPOINT_DRIFT')
    old=remote_core()
    new,count=render(old)
    if not owner.live_checkpoint_unchanged():
        raise RuntimeError('STABLE_CHANGED_DURING_RENDER')
    if OUT.exists():raise RuntimeError('Existing unified plan cannot be overwritten')
    OUT.mkdir(mode=0o700)
    for filename,data in [('dns.before',old),('dns.pilot',new)]:
        dest=OUT/filename
        dest.write_text(data)
        dest.chmod(0o600)
    info={
        'read_only':True,
        'purpose':'all premium A mappings RU188, unchanged original and personal DoT',
        'selected':list(SELECTED),'selected_count':len(SELECTED),
        'foreign_a_changed':count,'a_total':264,
        'sha_before':hashlib.sha256(old.encode()).hexdigest(),
        'sha_pilot':hashlib.sha256(new.encode()).hexdigest()
    }
    (OUT/'plan.json').write_text(json.dumps(info,sort_keys=True,indent=2)+'\n')
    print('UNIFIED_SHARED_ALL_PREMIUM_A_REPOINT_TO_RU188='+str(count),flush=True)
    print('UNIFIED_SHARED_A_TEMPLATE_TOTAL=264',flush=True)
    print('UNIFIED_SHARED_PERSONAL_CORE_DNS_SHARED_WILL_CHANGE=true',flush=True)
    print('UNIFIED_SHARED_DNS_ROLLBACK_CHECKPOINT=READY',flush=True)

def selftest():
    sample='''tls://.:853 {
    bind 89.125.90.101
    template IN A host.example.com {
      match ^host[.]example[.]com[.]$
      answer "{{ .Name }} 20 IN A 89.125.90.101"
    }
    template IN A test.example.com {
      match ^test[.]example[.]com[.]$
      answer "{{ .Name }} 20 IN A 188.120.254.223"
    }
    template IN A . {
      match ^.*$
      answer "{{ .Name }} 20 IN A 89.125.90.101"
    }
    cache 30 {
      servfail 0
    }
    reload 5s 1s
    forward . tls://9.9.9.9 tls://149.112.112.112 {
    }
}
'''
    assert len(ANSWER.findall(sample))==2
    assert len(HEADER.findall(sample))==3
    print('UNIFIED_SHARED_CORE_RENDER_REGEX_SELFTEST=PASS')

if __name__=='__main__':
    if sys.argv[1:]==['--self-test']:selftest()
    elif sys.argv[1:]==['--plan']:plan()
    else:raise SystemExit('Usage --self-test|--plan')
