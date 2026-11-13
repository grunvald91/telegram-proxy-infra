#!/usr/bin/env python3
"""Temporary SYNACK-only exception from Telegram NFQUEUE, never changes service/config.
Auto-rollback via independent systemd timer plus immediate scoped cleanup.
"""
import json
import pathlib
import re
import subprocess
import sys
import time

assert len(sys.argv)==2 and re.fullmatch(r"\d{8,20}",sys.argv[1])
run_id=sys.argv[1]
marker="mnebyvpn_synack_canary_"+run_id
unit="mnebyvpn-synack-canary-"+run_id
rollback_path=pathlib.Path("/run/"+unit+"-rollback.py")
def run(*args,raise_on_error=True,timeout=12):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if p.returncode and raise_on_error:
        raise RuntimeError("command failed: "+args[0]+" "+args[1])
    return p
def rules():
    p=run("nft","-j","-a","list","chain","inet","telegram_nfqws","post")
    return [i["rule"] for i in json.loads(p.stdout)["nftables"] if "rule" in i]
def matched():
    return [r for r in rules() if r.get("comment")==marker]
def queued():
    return [r for r in rules() if any("queue" in e and e["queue"].get("num")==210 for e in r.get("expr",[]))]
assert run("systemctl","is-active","--quiet","telegram-nfqws.service",raise_on_error=False).returncode==0
assert run("systemctl","is-active","--quiet","nginx.service",raise_on_error=False).returncode==0
conf=pathlib.Path("/etc/zapret2/telegram-nfqws.conf")
assert conf.exists() and "synack_split" in conf.read_text()
assert len(queued())==1
assert not matched()
# All SYN+ACK packets from source TCP443 on physical ethernet, not arbitrary data.
arguments=["nft","insert","rule","inet","telegram_nfqws","post",
           "oifname","ens3","tcp","sport","443","tcp","flags","&",
           "(","syn","|","ack",")","==","(","syn","|","ack",")",
           "counter","accept","comment",marker]
run("nft","-c",*arguments[1:])
print("SYNACK_NFT_SYNTAX_PASS=true",flush=True)

# Timer is installed BEFORE touching nft; survives a lost SSH session.
rollback_code="""
import json,pathlib,subprocess,sys
marker=sys.argv[1]
p=subprocess.run(["nft","-j","-a","list","chain","inet","telegram_nfqws","post"],
                 text=True,capture_output=True)
if p.returncode == 0:
    for item in json.loads(p.stdout).get("nftables", []):
        rule=item.get("rule", {})
        if rule.get("comment")==marker:
            subprocess.run(["nft","delete","rule","inet","telegram_nfqws","post",
                            "handle",str(rule["handle"])],check=True)
pathlib.Path(__file__).unlink(missing_ok=True)
"""
rollback_path.write_text(rollback_code)
rollback_path.chmod(0o700)
armed=False
try:
    run("systemd-run","--quiet","--unit="+unit,"--on-active=70s",
        "/usr/bin/python3",str(rollback_path),marker)
    armed=True
    assert run("systemctl","is-active","--quiet",unit+".timer",raise_on_error=False).returncode==0
    run(*arguments)
    assert len(matched())==1
    assert len(queued())==1
    print("SYNACK_ONLY_CANARY_ACTIVE=true",flush=True)
    print("SYNACK_ONLY_CANARY_TIMER_ARMED=true",flush=True)
    time.sleep(30)
finally:
    if rollback_path.exists():
        run("/usr/bin/python3",str(rollback_path),marker,raise_on_error=False)
    if not matched():
        if armed:run("systemctl","stop",unit+".timer",raise_on_error=False)
        rollback_path.unlink(missing_ok=True)
        print("SYNACK_ONLY_CANARY_REMOVED=true",flush=True)
    else:
        print("SYNACK_ONLY_CANARY_WATCHDOG_PENDING=true",flush=True)
        raise RuntimeError("canary cleanup not confirmed")
