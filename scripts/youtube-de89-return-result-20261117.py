#!/usr/bin/env python3
"""Correlate the requested peer trial and restore it; never print peer addresses."""
import json,pathlib,subprocess,time
capture=pathlib.Path('/run/mnebydns-normalcurl-44087349813-1')
trial=pathlib.Path('/run/mnebydns-owner-return-44087349813-1')
original=pathlib.Path('/run/mnebydns-normalcurl-44083307553-1')
ids={'c03b85752da74621','4e2c3866eb62d91e','da67f0a412cd9bb8','7e062b1483a4efa3'}
def emit(k,v):print(k+'='+json.dumps(v,sort_keys=True),flush=True)
for line in (capture/'result.log').read_text().splitlines():
    if any(i in line for i in ids):print(line,flush=True)
rows=[json.loads(x) for x in (capture/'bindings.private.jsonl').read_text().splitlines()]
new=[x for x in rows if x['probe'] in ids]
old_ids={'70fd267cea0b7d0d','6d06aec16581692d','22d1a1e6fded94a8'}
old=[json.loads(x) for x in (original/'bindings.private.jsonl').read_text().splitlines()]
peer={x['address'] for x in old if x['probe'] in old_ids}
start=(trial/'protected-hashes.json').stat().st_mtime
emit('RETURN_TRIAL_CORRELATION',{'observed_probe_count':len(new),'peer_matches_original':len(peer)==1 and all(x['address'] in peer for x in new),'probes_within_five_minute_window':bool(new) and all(start<=x['observed_at']<=start+300 for x in new)})
def run(a):
    p=subprocess.run(a,capture_output=True,text=True,timeout=15)
    print(p.stdout,flush=True,end='')
    return p.returncode
run(['python3','-B',str(trial/'probe.py'),'status',str(trial)])
timer='mnebydns-owner-return-clean-44087349813-1'
run(['journalctl','-u',timer+'.service','--no-pager','-n','30','-o','cat'])
subprocess.run(['systemctl','stop',timer+'.timer'],capture_output=True,timeout=10)
if run(['python3','-B',str(trial/'probe.py'),'clean',str(trial)]):raise SystemExit(2)
emit('TRIAL_RESTORED',True)
