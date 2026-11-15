#!/usr/bin/env python3
"""Guarded DNS-only restoration of YouTube A routes to verified 2026-11-13 00:51 MSK."""
from __future__ import annotations
import datetime, fcntl, hashlib, json, os, pathlib, re, shutil, socket, ssl, stat, struct, subprocess, sys, time
BASE=pathlib.Path("/opt/mnebydns-youtube-pre13-restore-20261115")
STATE=BASE/"state"
CPROOT=pathlib.Path("/opt/mnebydns-stable-checkpoints")
PTR=CPROOT/"current"
OLDCP=CPROOT/"1794520280"
DNS=pathlib.Path("/opt/mnebydns-dot/Corefile")
NGINX=pathlib.Path("/etc/nginx/nginx.conf")
PROXY=pathlib.Path("/etc/mnebydns-googlepilot/nginx.conf")
UNIT="mnebydns-youtube-pre13-revert-20261115"
RU="188.120.254.223"
DE="89.125.90.101"
EXPECTED_SHA="578d8c0777a494dd91351aa75e839e35b1c9028355cdc9e8d5592a13fea98fb1"
TMPL=re.compile(r"(?ms)^[ \t]*template IN A (\S+) \{\n.*?^[ \t]*\}")
def emit(key,val): print("YT_PRE13_"+key+"="+str(val),flush=True)
def sha(data): return hashlib.sha256(data).hexdigest()
def cmd(*args,timeout=25):
    p=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if p.returncode:raise RuntimeError("COMMAND_FAILED "+repr(args[:2])+" "+p.stderr[:160])
    return p.stdout.strip()
def lock():
    f=open("/run/lock/mnebyvpn-public-route.lock","a+")
    fcntl.flock(f,fcntl.LOCK_EX)
    return f
def cp_check(p):
    assert re.fullmatch(r"/opt/mnebydns-stable-checkpoints/[0-9]+",str(p))
    assert (p/"stable-manifest.sha256").is_file()
    assert subprocess.run(["sha256sum","-c","stable-manifest.sha256"],cwd=p,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0
def current():
    p=pathlib.Path(PTR.read_text().strip())
    cp_check(p)
    return p
def intact(p):
    assert (p/"dns.stable").read_bytes()==DNS.read_bytes(),"live dns drift"
    assert (p/"nginx.stable").read_bytes()==NGINX.read_bytes(),"nginx drift"
    assert (p/"proxy.stable").read_bytes()==PROXY.read_bytes(),"proxy drift"
def active():
    for name in ["nginx.service","mnebydns-dot.service","mnebydns-googlepilot.service","mnebydns-de89-public-quic-20261115.service"]:
        assert cmd("systemctl","is-active",name)=="active",name
    assert DE+":853" in cmd("ss","-H","-lnt","sport",":853")
    assert DE+":443" in cmd("ss","-H","-lun","sport",":443")
def media_blocks(data):
    matches=list(TMPL.finditer(data))
    www=[m for m in matches if m.group(1)=="www.youtube.com" and "^www[.]youtube[.]com[.]$" in m.group(0)]
    gv=[m for m in matches if m.group(1)=="." and "googlevideo[.]com[.]$" in m.group(0)]
    assert len(www)==1 and len(gv)==1, "nonunique youtube media blocks"
    assert "answer" in www[0].group(0) and "answer" in gv[0].group(0)
    return www[0],gv[0]
def generate():
    cp=current(); intact(cp); active(); cp_check(OLDCP)
    old=OLDCP.joinpath("dns.stable").read_text()
    assert re.search(r"template IN A www[.]youtube[.]com \{.*?89[.]125[.]90[.]101",old,re.S)
    assert "googlevideo\\." in old and DE in old
    before=DNS.read_bytes()
    assert sha(before)==EXPECTED_SHA,"baseline moved since last read-only audit"
    src=before.decode()
    www,gv=media_blocks(src)
    for m in (www,gv):
        t=m.group(0)
        assert t.count("IN A "+RU)==1,"unexpected current IP"
        assert "IN A "+DE not in t,"mixed current block"
    # Restore only the two pre-13 effective destinations. Keep all later domain additions.
    pilot=src
    for m in sorted((www,gv),key=lambda m:m.start(),reverse=True):
        t=m.group(0)
        fixed=t.replace("IN A "+RU,"IN A "+DE,1)
        pilot=pilot[:m.start()]+fixed+pilot[m.end():]
    www2,gv2=media_blocks(pilot)
    assert all("IN A "+DE in m.group(0) and "IN A "+RU not in m.group(0) for m in (www2,gv2))
    assert pilot!=src and pilot.count("template IN A")==src.count("template IN A")
    return cp,before,pilot.encode()
def atomic(data):
    tmp=DNS.with_name("Corefile.yt-pre13-new-"+str(os.getpid()))
    assert not tmp.exists()
    try:
        with open(tmp,"xb") as f:f.write(data);f.flush();os.fsync(f.fileno())
        shutil.copymode(DNS,tmp);os.chown(tmp,DNS.stat().st_uid,DNS.stat().st_gid)
        os.replace(tmp,DNS)
    finally:
        tmp.unlink(missing_ok=True)
def query_a(host):
    q=b"".join(bytes([len(x)])+x.encode() for x in host.split("."))+b"\x00"
    msg=struct.pack("!HHHHHH",0x3814,0x0100,1,0,0,0)+q+struct.pack("!HH",1,1)
    ctx=ssl.create_default_context()
    with socket.create_connection((DE,853),timeout=6) as raw:
        with ctx.wrap_socket(raw,server_hostname="dns.mnebyvpn.site") as sock:
            sock.settimeout(8)
            sock.sendall(struct.pack("!H",len(msg))+msg)
            def recv_exact(n):
                b=b""
                while len(b)<n:
                    x=sock.recv(n-len(b))
                    if not x:raise RuntimeError("short DoT")
                    b+=x
                return b
            data=recv_exact(struct.unpack("!H",recv_exact(2))[0])
    if data[:2]!=msg[:2]:raise RuntimeError("DoT ID")
    _id,flags,questions,answers,_,_=struct.unpack("!HHHHHH",data[:12])
    assert flags&15==0 and questions==1 and answers>0
    def name_end(i):
        for _ in range(64):
            z=data[i]
            if z==0:return i+1
            if z&192==192:return i+2
            i+=z+1
        raise RuntimeError("invalid dns")
    i=name_end(12)+4
    ips=[]
    for _ in range(answers):
        i=name_end(i)
        kind,klass,ttl,length=struct.unpack("!HHIH",data[i:i+10]);i+=10
        if kind==1 and klass==1 and length==4:ips.append(socket.inet_ntoa(data[i:i+4]))
        i+=length
    return sorted(set(ips))
def check(expected):
    for host in ["www.youtube.com","rr1---sn-gxuo03g-ig3s.googlevideo.com"]:
        ips=query_a(host)
        emit("DOT_"+host,repr(ips))
        if ips!=[expected]:raise RuntimeError("DoT route unexpected for "+host)
def apply():
    guard=lock()
    assert not STATE.exists(),"existing attempt must be reviewed"
    cp,before,pilot=generate()
    check(RU) # Must match live route before making a change.
    STATE.mkdir(mode=0o700,parents=True)
    (STATE/"dns.before").write_bytes(before)
    (STATE/"dns.pilot").write_bytes(pilot)
    (STATE/"checkpoint.before").write_text(str(cp)+"\n")
    (STATE/"sha.json").write_text(json.dumps({"before":sha(before),"pilot":sha(pilot)}))
    cmd("systemd-run","--unit="+UNIT,"--on-active=15m","--collect","/usr/bin/python3",str(BASE/"manager.py"),"rollback")
    emit("AUTO_ROLLBACK_ARMED",True)
    atomic(pilot)
    emit("PILOT_APPLIED",True)
    guard.close()
def verify():
    guard=lock()
    assert STATE.is_dir() and not (STATE/"confirmed").exists()
    assert DNS.read_bytes()==(STATE/"dns.pilot").read_bytes()
    assert str(current())==(STATE/"checkpoint.before").read_text().strip()
    time.sleep(7)
    active()
    check(DE)
    emit("VERIFY_SUCCESS",True)
    guard.close()
def confirm():
    guard=lock()
    assert not (STATE/"confirmed").exists()
    cp=current()
    assert str(cp)==(STATE/"checkpoint.before").read_text().strip()
    assert DNS.read_bytes()==(STATE/"dns.pilot").read_bytes()
    assert (cp/"nginx.stable").read_bytes()==NGINX.read_bytes()
    assert (cp/"proxy.stable").read_bytes()==PROXY.read_bytes()
    check(DE)
    dest=CPROOT/str(int(time.time()))
    assert not dest.exists()
    dest.mkdir(mode=0o700)
    for x in cp.iterdir():
        if x.is_file():shutil.copy2(x,dest/x.name)
    shutil.copy2(DNS,dest/"dns.stable")
    with (dest/"stable-manifest.sha256").open("w") as f:
        for name in ("nginx.stable","dns.stable","proxy.stable"):
            f.write(sha((dest/name).read_bytes())+"  "+name+"\n")
        f.flush();os.fsync(f.fileno())
    cp_check(dest)
    assert DNS.read_bytes()==(dest/"dns.stable").read_bytes()
    t=CPROOT/("current.yt-pre13-"+str(os.getpid()))
    with open(t,"x") as f:f.write(str(dest)+"\n");f.flush();os.fsync(f.fileno())
    shutil.copymode(PTR,t)
    os.replace(t,PTR)
    (STATE/"confirmed").write_text(str(dest)+"\n")
    subprocess.run(["systemctl","stop",UNIT+".timer"],capture_output=True,timeout=15)
    emit("NEW_STABLE_CHECKPOINT",dest)
    emit("COMMITTED",True)
    guard.close()
def rollback():
    guard=lock()
    if not STATE.exists() or (STATE/"confirmed").exists():
        emit("ROLLBACK_SKIPPED",True);return
    old=(STATE/"dns.before").read_bytes(); pilot=(STATE/"dns.pilot").read_bytes()
    cp=current()
    assert str(cp)==(STATE/"checkpoint.before").read_text().strip(),"new checkpoint; refuse revert"
    assert cp.joinpath("dns.stable").read_bytes()==old
    assert DNS.read_bytes() in (old,pilot),"unexpected live DNS; refuse revert"
    if DNS.read_bytes()==pilot: atomic(old);time.sleep(7)
    check(RU)
    active()
    emit("ROLLED_BACK",True)
    guard.close()
def main():
    assert len(sys.argv)==2
    if sys.argv[1]=="audit":
        cp,before,pilot=generate()
        emit("OLD_CP",OLDCP)
        emit("LIVE_CP",cp)
        emit("RESTORED_BLOCKS",2)
        emit("CURRENT_SHA",sha(before))
        emit("PILOT_SHA",sha(pilot))
    elif sys.argv[1]=="apply": apply()
    elif sys.argv[1]=="verify": verify()
    elif sys.argv[1]=="confirm": confirm()
    elif sys.argv[1]=="rollback": rollback()
    else:raise SystemExit("Unknown mode")
if __name__=="__main__":main()
