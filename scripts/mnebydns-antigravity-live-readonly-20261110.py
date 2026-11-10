#!/usr/bin/env python3
"""Read-only live DNS/TLS check for all owner-requested Google Antigravity hosts."""
from __future__ import annotations
import importlib.util
import time
from pathlib import Path

root=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("antigravity_batch",root/"mnebydns-antigravity-owner-live-activate-20261110.py")
batch=importlib.util.module_from_spec(spec)
spec.loader.exec_module(batch)
owner=batch.owner

def main():
    results={}
    for host in batch.DOMAINS:
        try:
            owner.oracle_canary_check(host,True)
            print("antigravity_live_dns="+host+":PASS",flush=True)
            # Only retry a transient TLS probe, never a DNS policy violation.
            # Keep strict certificate verification on all attempts.
            for attempt in range(3):
                try:
                    owner.tls_public_route(host)
                    break
                except RuntimeError:
                    if attempt == 2:
                        raise
                    time.sleep(1 + attempt)
            print("antigravity_live_tls="+host+":PASS",flush=True)
            results[host]="LIVE_DOT_TLS_VERIFIED"
        except Exception as exc:
            results[host]="FAIL_"+type(exc).__name__+"_"+str(exc).replace("\n"," ")[:100]
        print("antigravity_live_result="+host+":"+results[host],flush=True)
    passed=sum(v=="LIVE_DOT_TLS_VERIFIED" for v in results.values())
    print("antigravity_live_verified_count="+str(passed)+"/"+str(len(batch.DOMAINS)),flush=True)
    print("antigravity_readonly=true",flush=True)
    if passed != len(batch.DOMAINS):
        raise SystemExit(2)

if __name__=="__main__": main()
