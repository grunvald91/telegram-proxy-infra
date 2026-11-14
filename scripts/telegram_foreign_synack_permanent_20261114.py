#!/usr/bin/env python3
"""Guarded foreign Telegram public443 SYNACK, preserve WEB/DNS/VPN traffic.
Modes: self-test (offline), stage (RU root), commit (RU root), rollback (RU root).
No restarts, no nginx/DNS/WireGuard changes, independent auto-rollback after stage.
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

SOURCE=pathlib.Path("/usr/local/sbin/telegram-foreign-nfqws-rules")
BACKUP=pathlib.Path("/root/proxy-backups")
MARKER="mnebyvpn_de_standard_synack"
ANCHOR='        nft add rule inet telegram_nfqws post oifname "$WAN_IF" tcp sport 443 ct reply packets 1-20 meta mark and 0x40000000 == 0 counter queue num "$QUEUE" bypass comment telegram-nfqws'
EXCEPTION='        nft add rule inet telegram_nfqws post oifname "$WAN_IF" tcp sport 443 tcp flags ' + "'&' '(' syn '|' ack ')' '==' '(' syn '|' ack ')'" + ' counter accept comment '+MARKER

def cmd(*args,ok=True,timeout=16):
    p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if ok and p.returncode:
        raise RuntimeError("command failed: "+str(args[:2]))
    return p

def sha(data):
    return hashlib.sha256(data).hexdigest()

def render(source):
    if MARKER in source:raise RuntimeError("Persistent SYNACK fix already present")
    if source.count(ANCHOR)!=1:raise RuntimeError("Unexpected active NFQUEUE script; refusing mutation")
    if "nft add table inet telegram_nfqws" not in source:
        raise RuntimeError("Expected nfqueue table creation absent")
    return source.replace(ANCHOR,EXCEPTION+"\n"+ANCHOR,1)

def chain():
    p=cmd("nft","-j","-a","list","chain","inet","telegram_nfqws","post")
    return [item["rule"] for item in json.loads(p.stdout)["nftables"] if "rule" in item]

def listed():
    return [r for r in chain() if r.get("comment")==MARKER]

def queue():
    return [r for r in chain() if any("queue" in e and e["queue"].get("num")==210 for e in r.get("expr",[]))]

def replace_bytes(path,payload):
    stat=path.stat()
    fd,name=tempfile.mkstemp(prefix=".mnebyvpn-synack-",dir=str(path.parent))
    try:
        os.fchmod(fd,stat.st_mode&0o7777)
        os.fchown(fd,stat.st_uid,stat.st_gid)
        with os.fdopen(fd,"wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        if os.path.exists(name):os.unlink(name)

def directory(runid):
    if not re.fullmatch(r"[0-9]{8,20}",runid):
        raise RuntimeError("Invalid run ID")
    return BACKUP/("foreign443-synack-"+runid)

ROLLBACK_CODE="""
import hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile
folder=pathlib.Path(sys.argv[1])
if (folder/'confirmed').exists():
    print('SYNACK_ROLLBACK_SKIPPED_CONFIRMED=true',flush=True)
    raise SystemExit(0)
meta=json.loads((folder/'state.json').read_text())
target=pathlib.Path('/usr/local/sbin/telegram-foreign-nfqws-rules')
def digest(x):return hashlib.sha256(x).hexdigest()
try:
    current=target.read_bytes()
    if digest(current)==meta['new_sha']:
        st=target.stat()
        fd,name=tempfile.mkstemp(prefix='.mnebyvpn-synack-restore-',dir=str(target.parent))
        try:
            os.fchmod(fd,st.st_mode&0o7777);os.fchown(fd,st.st_uid,st.st_gid)
            with os.fdopen(fd,'wb') as f:
                f.write((folder/'original-rules').read_bytes());f.flush();os.fsync(f.fileno())
            os.replace(name,target)
        finally:
            if os.path.exists(name):os.unlink(name)
    elif digest(current)!=meta['old_sha']:
        print('ROLLBACK_FILE_DRIFT_NOT_OVERWRITTEN=true',flush=True)
except Exception as e:
    print('ROLLBACK_SCRIPT_FAILURE='+type(e).__name__,flush=True)
p=subprocess.run(['nft','-j','-a','list','chain','inet','telegram_nfqws','post'],
                 text=True,capture_output=True)
if p.returncode==0:
    for row in json.loads(p.stdout).get('nftables',[]):
        r=row.get('rule',{})
        if r.get('comment')=='mnebyvpn_de_standard_synack':
            subprocess.run(['nft','delete','rule','inet','telegram_nfqws','post',
                            'handle',str(r['handle'])],check=True)
print('SYNACK_ROLLBACK_INVOKED=true',flush=True)
"""

def preflight():
    for svc in ("telegram-foreign-nfqws.service","nginx.service"):
        assert cmd("systemctl","is-active","--quiet",svc,ok=False).returncode==0,svc
    conf=pathlib.Path("/etc/zapret2/telegram-nfqws.conf")
    assert conf.is_file() and "synack_split" in conf.read_text()
    assert len(queue())==1
    assert not listed()
    assert SOURCE.is_file() and not SOURCE.is_symlink()

def stage(runid):
    assert os.geteuid()==0
    preflight()
    original=SOURCE.read_bytes()
    updated=render(original.decode("utf-8")).encode("utf-8")
    # Validate shell and nft syntax before changing any live file or rule.
    test=subprocess.run(["sh","-n"],input=updated,capture_output=True,timeout=8)
    if test.returncode:raise RuntimeError("Candidate shell syntax invalid")
    nftargs=["nft","insert","rule","inet","telegram_nfqws","post",
             "oifname","eth0","tcp","sport","443","tcp","flags","&",
             "(","syn","|","ack",")","==","(","syn","|","ack",")",
             "counter","accept","comment",MARKER]
    cmd("nft","-c",*nftargs[1:])
    folder=directory(runid)
    folder.mkdir(mode=0o700,parents=False,exist_ok=False)
    (folder/"original-rules").write_bytes(original)
    (folder/"original-rules").chmod(0o600)
    meta={"old_sha":sha(original),"new_sha":sha(updated),"run_id":runid}
    (folder/"state.json").write_text(json.dumps(meta))
    (folder/"state.json").chmod(0o600)
    (folder/"rollback.py").write_text(ROLLBACK_CODE)
    (folder/"rollback.py").chmod(0o700)
    unit="telegram-de443-rollback-"+runid
    armed=False
    try:
        # Independent timer first. A lost SSH connection cannot leave the patch indefinitely.
        cmd("systemd-run","--quiet","--unit="+unit,"--on-active=6min",
            "/usr/bin/python3",str(folder/"rollback.py"),str(folder))
        armed=True
        assert cmd("systemctl","is-active","--quiet",unit+".timer",ok=False).returncode==0
        assert SOURCE.read_bytes()==original
        replace_bytes(SOURCE,updated)
        assert SOURCE.read_bytes()==updated
        cmd(*nftargs)
        arr=chain()
        i=next((idx for idx,r in enumerate(arr) if r.get("comment")==MARKER),-1)
        q=next((idx for idx,r in enumerate(arr) if any("queue" in e and e["queue"].get("num")==210 for e in r.get("expr",[]))),-1)
        assert i>=0 and q>i and len(listed())==1,"SYNACK rule must precede queue"
        print("SYNACK_PERMANENT_STAGE_APPLIED=true",flush=True)
        print("SYNACK_ROLLBACK_TIMER_ARMED=true",flush=True)
    except BaseException:
        if armed:
            cmd("/usr/bin/python3",str(folder/"rollback.py"),str(folder),ok=False)
            if not listed() and SOURCE.read_bytes()==original:
                cmd("systemctl","stop",unit+".timer",ok=False)
        raise

def commit(runid):
    assert os.geteuid()==0
    folder=directory(runid)
    meta=json.loads((folder/"state.json").read_text())
    assert meta["run_id"]==runid
    assert sha(SOURCE.read_bytes())==meta["new_sha"],"Active persistent script was modified"
    arr=chain()
    i=next((idx for idx,r in enumerate(arr) if r.get("comment")==MARKER),-1)
    q=next((idx for idx,r in enumerate(arr) if any("queue" in e and e["queue"].get("num")==210 for e in r.get("expr",[]))),-1)
    assert i>=0 and q>i and len(listed())==1
    for svc in ("nginx.service","telegram-foreign-nfqws.service"):
        assert cmd("systemctl","is-active","--quiet",svc,ok=False).returncode==0
    unit="telegram-de443-rollback-"+runid
    assert cmd("systemctl","is-active","--quiet",unit+".timer",ok=False).returncode==0
    (folder/"confirmed").touch()
    cmd("systemctl","stop",unit+".timer")
    assert cmd("systemctl","is-active","--quiet",unit+".timer",ok=False).returncode!=0
    print("SYNACK_PERMANENT_FIX_COMMITTED=true",flush=True)
    print("SYNACK_PERSISTENCE_SCRIPT_CHECKED=true",flush=True)
    print("SYNACK_ROLLBACK_BACKUP_PRESERVED=true",flush=True)

def rollback(runid):
    folder=directory(runid)
    # Explicit manual rollback remains available after commit. Timed watchdog
    # respects the confirmed marker, but an operator can request a restore.
    (folder/"confirmed").unlink(missing_ok=True)
    cmd("/usr/bin/python3",str(folder/"rollback.py"),str(folder))
    assert not listed()
    print("SYNACK_MANUAL_ROLLBACK_VERIFIED=true",flush=True)

def selftest():
    example=pathlib.Path("legacy-mtproxy/live-snapshot/relay89/usr/local/sbin/telegram-foreign-nfqws-rules").read_text()
    target=render(example)
    compile(ROLLBACK_CODE, '<server-rollback>', 'exec')
    assert target.count(MARKER)==1
    assert target.index(MARKER)<target.index(ANCHOR)
    assert subprocess.run(["sh","-n"],input=target,text=True,capture_output=True).returncode==0
    try:render(target)
    except RuntimeError:pass
    else:raise AssertionError("render not idempotence-safe")
    print("SYNACK_PERSISTENCE_SELFTEST=PASS")

if __name__=="__main__":
    if sys.argv[1:]==["self-test"]:selftest()
    elif len(sys.argv)==3 and sys.argv[1]=="stage":stage(sys.argv[2])
    elif len(sys.argv)==3 and sys.argv[1]=="commit":commit(sys.argv[2])
    elif len(sys.argv)==3 and sys.argv[1]=="rollback":rollback(sys.argv[2])
    else:raise SystemExit("invalid mode")
