#!/usr/bin/env python3
"""Guarded MNEBYVPN VPN+SmartDNS Xray inbound SNI sniffing patch, no subscriber mutations."""
from __future__ import annotations
import hashlib, json, os, pathlib, shutil, subprocess, sys, time, fcntl
ROOT=pathlib.Path("/opt/mnebyvpn-vpn-dns-sniff-fix-20261115")
STATE=ROOT/"state"
CONF=pathlib.Path("/etc/mnebyvpn/xray-canary.json")
SOURCE=pathlib.Path("/opt/mnebyvpn/vpn-provisioner.py")
XRAY="/opt/xray/xray"
PROV="mnebyvpn-vpn-provisioner.service"
SHARED="xray.service"
TIMER="mnebyvpn-vpn-dns-sniff-autorevert-20261115.timer"
EXPECTED_CONFIG_SHA="2d82ec33a36d2349a801499c39f3c846b2f1a4df21b02720a3a4a805edb480f9"
EXPECTED_SOURCE_SHA="450f1ee7d0e77412dcd72c4cc97c7cb08390ee3c4ebc8aef2e02d264f6199105"
OPTIONS={"enabled": True, "destOverride": ["http","tls","quic"], "routeOnly": False}
def sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def out(key,val):print("VPN_SNI_PATCH_"+key+"="+str(val),flush=True)
def run(args,timeout=20,check=True):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=timeout)
    if p.returncode and check:raise RuntimeError("COMMAND_FAILED "+str(args[:2])+" rc="+str(p.returncode)+" "+p.stderr[-180:])
    return p
def verify_json(cfg):
    b=cfg.get("inbounds")
    assert type(b)==list and len(b)==2
    assert {x.get("port") for x in b}=={18943,2053}
    for x in b:
        assert x.get("protocol")=="vless"
        assert x.get("sniffing")==OPTIONS, "sniffing mismatch "+str(x.get("port"))
    assert cfg.get("routing",{}).get("domainStrategy")=="IPIfNonMatch"
def candidate():
    orig=CONF.read_bytes()
    assert sha(orig)==EXPECTED_CONFIG_SHA,"production config drift; no changes"
    assert sha(SOURCE.read_bytes())==EXPECTED_SOURCE_SHA,"provisioner drift; no changes"
    cfg=json.loads(orig)
    assert len(cfg.get("inbounds",[]))==2
    assert {x.get("port") for x in cfg["inbounds"]}=={18943,2053}
    assert all(x.get("sniffing") is None for x in cfg["inbounds"])
    modified=json.loads(orig)
    for x in modified["inbounds"]:x["sniffing"]=OPTIONS.copy()
    verify_json(modified)
    data=(json.dumps(modified,separators=(",",":"),ensure_ascii=True)+"\n").encode()
    return orig,data
def lock():
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    f=open(ROOT/"lock","a+")
    fcntl.flock(f,fcntl.LOCK_EX)
    return f
def write_atomic(data:bytes):
    temp=CONF.with_name(CONF.name+".sniff-20261115-temp")
    assert not temp.exists()
    st=CONF.stat()
    try:
        with open(temp,"xb") as f:f.write(data);f.flush();os.fsync(f.fileno())
        os.chmod(temp,st.st_mode & 0o7777)
        os.chown(temp,st.st_uid,st.st_gid)
        os.replace(temp,CONF)
    finally:temp.unlink(missing_ok=True)
def test(candidate_file):
    p=run([XRAY,"run","-test","-c",str(candidate_file)],timeout=20,check=False)
    if p.returncode:raise RuntimeError("XRAY_CONFIG_TEST_FAILED rc="+str(p.returncode)+" "+p.stderr[-140:])
    out("XRAY_CONFIG_TEST","PASS")
def listeners():
    p=run(["ss","-H","-lntp"],timeout=9)
    lines=p.stdout.splitlines()
    for port in (18943,2053):
        assert any(len(x.split())>=5 and x.split()[3].endswith(":"+str(port)) and "xray" in x.lower() for x in lines),"missing Xray port "+str(port)
    out("XRAY_PORTS","18943,2053")
def services():
    for service in (PROV,SHARED):
        assert run(["systemctl","is-active",service]).stdout.strip()=="active",service+" inactive"
    listeners()
def apply():
    fd=lock()
    assert not STATE.exists(),"existing operation requires review"
    orig,changed=candidate()
    services()
    # xray test file lives alongside original to maintain path semantics.
    temp=CONF.with_name("xray-canary.sniff-candidate-20261115.json")
    assert not temp.exists()
    try:
        with open(temp,"xb") as f:f.write(changed)
        os.chmod(temp,0o600);test(temp)
    finally:temp.unlink(missing_ok=True)
    STATE.mkdir(mode=0o700)
    with open(STATE/"before.json","xb") as f:f.write(orig)
    os.chmod(STATE/"before.json",0o600)
    with open(STATE/"candidate.json","xb") as f:f.write(changed)
    os.chmod(STATE/"candidate.json",0o600)
    run(["systemd-run","--unit=mnebyvpn-vpn-dns-sniff-autorevert-20261115","--on-active=5m","--collect","/usr/bin/python3",str(ROOT/"fix.py"),"rollback"],timeout=16)
    out("AUTO_ROLLBACK","ARMED_5M")
    write_atomic(changed)
    out("LIVE_CONFIG_UPDATED","YES")
    # This restarts only the provisioner and its isolated Xray child. Shared xray.service is untouched.
    run(["systemctl","restart",PROV],timeout=35)
    time.sleep(5)
    services()
    assert CONF.read_bytes()==changed,"provisioner rewrote the patched config"
    out("PATCH_APPLIED","YES")
    fd.close()
def verify():
    fd=lock()
    assert STATE.exists()
    changed=(STATE/"candidate.json").read_bytes()
    assert CONF.read_bytes()==changed,"live config changed unexpectedly"
    verify_json(json.loads(CONF.read_bytes()))
    test(CONF);services()
    # Verify running daemon adopted the patch: child must be present and started after checkpoint.
    chk=run(["systemctl","show",PROV,"-p","MainPID","-p","ActiveState"]).stdout
    out("PROVISIONER_STATUS",repr(chk.replace("\n",";")[:120]))
    out("VERIFY","SUCCESS")
    fd.close()
def confirm():
    fd=lock()
    assert STATE.exists()
    assert CONF.read_bytes()==(STATE/"candidate.json").read_bytes()
    verify_json(json.loads(CONF.read_bytes()))
    services()
    (STATE/"confirmed").write_text("verified\n")
    p=run(["systemctl","stop",TIMER],check=False,timeout=9)
    out("ROLLBACK_TIMER_STOP_RC",p.returncode)
    out("COMMITTED","YES")
    fd.close()
def rollback():
    fd=lock()
    if not STATE.exists() or (STATE/"confirmed").exists():
        out("ROLLBACK","SKIPPED_CONFIRMED_OR_ABSENT");return
    orig=(STATE/"before.json").read_bytes()
    changed=(STATE/"candidate.json").read_bytes()
    assert CONF.read_bytes() in (orig,changed),"unrelated live changes; refusing unsafe rollback"
    if CONF.read_bytes()!=orig:
        write_atomic(orig)
        run(["systemctl","restart",PROV],timeout=35)
        time.sleep(3)
    assert CONF.read_bytes()==orig
    services()
    out("ROLLBACK","RESTORED_EXACT_PREVIOUS_CONFIG")
    fd.close()
if __name__=="__main__":
    try:
        if len(sys.argv)!=2:raise RuntimeError("Expected mode")
        {
            "apply":apply,
            "verify":verify,
            "confirm":confirm,
            "rollback":rollback,
        }[sys.argv[1]]()
    except Exception as exc:
        out("ERROR",type(exc).__name__+": "+str(exc)[:300])
        raise
