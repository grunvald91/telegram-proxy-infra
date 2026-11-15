#!/usr/bin/env python3
"""Guarded restoration of exact 2026-11-14 morning YouTube DNS A routing.

Only the exact www.youtube.com A template is changed to the value from
the verified 2026-11-13 stable snapshot. Other DNS records and Nginx are untouched.
"""
import datetime,fcntl,hashlib,ipaddress,json,os,pathlib,re,shutil,socket,ssl,struct,subprocess,sys,time
ROOT=pathlib.Path("/opt/mnebydns-youtube-morning-20261115")
STATE=ROOT/"state"; LIVE=pathlib.Path("/opt/mnebydns-dot/Corefile")
HISTORY=pathlib.Path("/opt/mnebydns-stable-checkpoints/1794566430/dns.stable")
CPROOT=pathlib.Path("/opt/mnebydns-stable-checkpoints")
CHECKPOINT=CPROOT/"current"
NGINX=pathlib.Path("/etc/nginx/nginx.conf")
PROXY=pathlib.Path("/etc/mnebydns-googlepilot/nginx.conf")
UNIT="mnebydns-youtube-morning-revert-20261115"
PATT=re.compile(r"(?ms)^template IN A www\.youtube\.com \{\n.*?^\}")
OLDIP="188.120.254.223"; NEWIP="89.125.90.101"
def emit(k,v):print("YT_MORNING_"+k+"="+str(v),flush=True)
def sha(data):return hashlib.sha256(data).hexdigest()
def run(*args):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30)
    if p.returncode:raise RuntimeError("command failed: "+repr(args[:3])+" "+p.stderr[:180])
    return p.stdout.strip()
def exact_block(data):
    s=data.decode()
    matches=list(PATT.finditer(s))
    if len(matches)!=1:raise RuntimeError("expected exactly one www.youtube.com A template")
    return matches[0],s
def current_checkpoint():
    ref=CHECKPOINT.read_text().strip()
    if not re.fullmatch(r"/opt/mnebydns-stable-checkpoints/[0-9]+",ref):raise RuntimeError("unstable checkpoint pointer")
    p=pathlib.Path(ref)
    run("sha256sum","-c",str(p/"stable-manifest.sha256")) if False else None
    proc=subprocess.run(["sha256sum","-c","stable-manifest.sha256"],cwd=p,capture_output=True,text=True,timeout=15)
    if proc.returncode:raise RuntimeError("checkpoint manifest mismatch")
    return p
def assert_base(cp):
    if (cp/"dns.stable").read_bytes()!=LIVE.read_bytes():raise RuntimeError("live DNS differs from stable checkpoint")
    if (cp/"nginx.stable").read_bytes()!=NGINX.read_bytes():raise RuntimeError("live nginx differs from checkpoint")
    if (cp/"proxy.stable").read_bytes()!=PROXY.read_bytes():raise RuntimeError("live proxy differs from checkpoint")
def active():
    for svc in ("mnebydns-dot.service","nginx.service","mnebydns-googlepilot.service"):
        if run("systemctl","is-active",svc)!="active":raise RuntimeError("inactive "+svc)
def restore_file(data):
    tmp=LIVE.with_name("Corefile.youtube-restore-20261115.tmp")
    if tmp.exists():raise RuntimeError("unowned Corefile tmp")
    try:
        with open(tmp,"xb") as fp:fp.write(data);fp.flush();os.fsync(fp.fileno())
        shutil.copymode(LIVE,tmp)
        os.chown(tmp,LIVE.stat().st_uid,LIVE.stat().st_gid)
        os.replace(tmp,LIVE)
    finally:tmp.unlink(missing_ok=True)
def wait_reload():
    before=run("systemctl","show","--value","-p","MainPID","mnebydns-dot.service")
    if not before.isdecimal() or int(before)<=1:raise RuntimeError("missing original resolver pid")
    if "    reload 5s 1s" not in LIVE.read_text():raise RuntimeError("reload directive missing")
    if "reload" not in run("/opt/mnebydns-dot/coredns","-plugins"):raise RuntimeError("CoreDNS reload plugin missing")
    time.sleep(7)
    if run("systemctl","show","--value","-p","MainPID","mnebydns-dot.service")!=before:raise RuntimeError("unexpected DNS restart")
    active()
    if not any("89.125.90.101:853" in x for x in run("ss","-H","-lnt","sport",":853").splitlines()):
        raise RuntimeError("public DoT listener missing")
def receive(sock,n):
    out=b""
    while len(out)<n:
        d=sock.recv(n-len(out))
        if not d:raise RuntimeError("short DNS response")
        out+=d
    return out
def query_dot():
    hostname="www.youtube.com"
    name=b"".join(bytes([len(p)])+p.encode() for p in hostname.split("."))+b"\x00"
    msg=struct.pack("!HHHHHH",0x4692,0x0100,1,0,0,0)+name+struct.pack("!HH",1,1)
    ctx=ssl.create_default_context()
    with socket.create_connection(("89.125.90.101",853),timeout=6) as tcp:
      with ctx.wrap_socket(tcp,server_hostname="dns.mnebyvpn.site") as tls:
        tls.settimeout(8);tls.sendall(struct.pack("!H",len(msg))+msg)
        length=struct.unpack("!H",receive(tls,2))[0]
        raw=receive(tls,length)
    if raw[:2]!=msg[:2] or len(raw)<12:raise RuntimeError("bad DNS correlation")
    _,flags,qd,an,ns,ar=struct.unpack("!HHHHHH",raw[:12])
    if flags&15 or qd!=1 or not an:raise RuntimeError("bad DNS reply")
    def skip_name(p):
      for _ in range(80):
        if p>=len(raw):raise RuntimeError("malformed DNS name")
        length=raw[p]
        if length&0xC0==0xC0:return p+2
        if length==0:return p+1
        p+=length+1
      raise RuntimeError("excessive name")
    p=skip_name(12)+4
    ips=[]
    for _ in range(an):
      p=skip_name(p)
      if p+10>len(raw):raise RuntimeError("short RR")
      kind,klass,ttl,size=struct.unpack("!HHIH",raw[p:p+10]);p+=10
      if kind==1 and klass==1 and size==4:
        ips.append(str(ipaddress.IPv4Address(raw[p:p+4])))
      p+=size
    return sorted(set(ips))
def canary_ready():
    cp=current_checkpoint();assert_base(cp);active()
    if not HISTORY.is_file():raise RuntimeError("historical snapshot missing")
    old=HISTORY.read_bytes();now=LIVE.read_bytes()
    old_m,old_text=exact_block(old);now_m,now_text=exact_block(now)
    old_block=old_m.group();now_block=now_m.group()
    if old_block.count(OLDIP)!=1 or NEWIP in old_block:raise RuntimeError("historical YouTube rule unexpected")
    if now_block.count(NEWIP)!=1 or OLDIP in now_block:raise RuntimeError("current YouTube rule unexpected")
    if now_block.replace(NEWIP,OLDIP)!=old_block:raise RuntimeError("morning YouTube rule differs beyond its IP; manual review needed")
    pilot=now_text[:now_m.start()]+old_block+now_text[now_m.end():]
    if pilot.count(OLDIP)!=1:raise RuntimeError("unexpected extra RU mappings")
    return cp,now,pilot.encode()
def stage():
    if STATE.exists():raise RuntimeError("state already exists")
    cp,before,pilot=canary_ready()
    # Verify baseline DoT on the same service that will be changed.
    baseline=query_dot()
    if baseline!=[NEWIP]:raise RuntimeError("baseline public DoT does not match current Corefile: "+repr(baseline))
    STATE.mkdir(mode=0o700)
    (STATE/"dns.before").write_bytes(before);(STATE/"dns.pilot").write_bytes(pilot)
    (STATE/"checkpoint.before").write_text(str(cp)+"\n")
    (STATE/"stage.json").write_text(json.dumps({"old":sha(before),"pilot":sha(pilot),"historical":sha(HISTORY.read_bytes())})+"\n")
    emit("HISTORICAL_CHECKPOINT_USED",str(HISTORY.parent))
    emit("BEFORE_SHA",sha(before));emit("PILOT_SHA",sha(pilot))
    emit("MORNING_ROUTE_WWW_YOUTUBE",OLDIP);emit("OTHER_DOMAINS_PRESERVED",True)
    emit("BASELINE_DOT",repr(baseline))
    emit("STAGED",True)
def do_apply():
    if not (STATE/"stage.json").is_file():raise RuntimeError("not staged")
    meta=json.loads((STATE/"stage.json").read_text())
    cp=current_checkpoint()
    if str(cp)!=(STATE/"checkpoint.before").read_text().strip():raise RuntimeError("checkpoint changed after staging")
    assert_base(cp);active()
    if sha(LIVE.read_bytes())!=meta["old"]:raise RuntimeError("concurrent DNS change")
    if (STATE/"dns.pilot").read_bytes()!=(lambda x: x)((STATE/"dns.pilot").read_bytes()):raise RuntimeError("invalid pilot")
    if sha((STATE/"dns.pilot").read_bytes())!=meta["pilot"]:raise RuntimeError("pilot modified")
    if "    reload 5s 1s" not in LIVE.read_text():raise RuntimeError("reload plugin absent in Corefile")
    if "reload" not in run("/opt/mnebydns-dot/coredns","-plugins"):raise RuntimeError("reload plugin absent")
    # Independent systemd timer is installed before changing production.
    run("systemd-run","--unit="+UNIT,"--on-active=12m","--collect",
        "/usr/bin/python3",str(ROOT/"manager.py"),"rollback")
    emit("INDEPENDENT_REVERT_ARMED",True)
    restore_file((STATE/"dns.pilot").read_bytes())
    emit("PILOT_ACTIVE",True)
def verify():
    if not (STATE/"dns.pilot").is_file():raise RuntimeError("not staged")
    if LIVE.read_bytes()!=(STATE/"dns.pilot").read_bytes():raise RuntimeError("pilot replaced by concurrent edit")
    wait_reload()
    result=query_dot()
    emit("CURRENT_PUBLIC_DOT_WWW_YOUTUBE",repr(result))
    if result!=[OLDIP]:raise RuntimeError("morning DNS answer not observed")
    if not (STATE/"verified").exists(): (STATE/"verified").write_text(datetime.datetime.now(datetime.timezone.utc).isoformat())
    emit("ROUTE_VERIFIED",True)
def confirm():
    if not (STATE/"verified").is_file():raise RuntimeError("not verified")
    cp=current_checkpoint()
    if str(cp)!=(STATE/"checkpoint.before").read_text().strip():raise RuntimeError("checkpoint advanced")
    if (cp/"dns.stable").read_bytes()!=(STATE/"dns.before").read_bytes():raise RuntimeError("checkpoint DNS changed")
    if LIVE.read_bytes()!=(STATE/"dns.pilot").read_bytes():raise RuntimeError("pilot no longer active")
    if (cp/"nginx.stable").read_bytes()!=NGINX.read_bytes() or (cp/"proxy.stable").read_bytes()!=PROXY.read_bytes():raise RuntimeError("proxy/nginx drift")
    if query_dot()!=[OLDIP]:raise RuntimeError("verified DoT changed")
    name=str(int(time.time()))
    dest=CPROOT/name
    dest.mkdir(mode=0o700)
    for p in cp.iterdir():
        if p.is_file():shutil.copy2(p,dest/p.name)
    shutil.copy2(STATE/"dns.pilot",dest/"dns.stable")
    with (dest/"stable-manifest.sha256").open("w") as f:
      for name in ("nginx.stable","dns.stable","proxy.stable"):
        f.write(sha((dest/name).read_bytes())+"  "+name+"\n")
      f.flush();os.fsync(f.fileno())
    proc=subprocess.run(["sha256sum","-c","stable-manifest.sha256"],cwd=dest,capture_output=True)
    if proc.returncode:raise RuntimeError("new stable manifest failed")
    if LIVE.read_bytes()!=(dest/"dns.stable").read_bytes():raise RuntimeError("race before checkpoint promotion")
    temp=CPROOT/("current.yt-restore."+str(os.getpid()))
    with temp.open("x") as f:f.write(str(dest)+"\n");f.flush();os.fsync(f.fileno())
    shutil.copymode(CHECKPOINT,temp)
    os.replace(temp,CHECKPOINT)
    if current_checkpoint()!=dest:raise RuntimeError("checkpoint promotion mismatch")
    (STATE/"confirmed").write_text(str(dest))
    emit("NEW_STABLE_CHECKPOINT",str(dest))
    emit("CONFIRMED",True)
def rollback():
    if not STATE.exists():return emit("ROLLBACK_NO_STATE",True)
    if (STATE/"confirmed").exists():return emit("ROLLBACK_SKIPPED_CONFIRMED",True)
    before=(STATE/"dns.before").read_bytes()
    pilot=(STATE/"dns.pilot").read_bytes()
    current=LIVE.read_bytes()
    if current==before:return emit("ROLLBACK_ALREADY_BASELINE",True)
    if current!=pilot:raise RuntimeError("rollback refuses unexpected concurrent DNS change")
    cp=current_checkpoint()
    if str(cp)!=(STATE/"checkpoint.before").read_text().strip():raise RuntimeError("checkpoint advanced; manual review")
    if (cp/"dns.stable").read_bytes()!=before:raise RuntimeError("checkpoint mismatch during rollback")
    restore_file(before)
    wait_reload()
    if query_dot()!=[NEWIP]:raise RuntimeError("rollback DNS mismatch")
    emit("ROLLBACK_VERIFIED",True)
def locked():
    lock=open("/run/lock/mnebyvpn-public-route.lock","a+")
    fcntl.flock(lock,fcntl.LOCK_EX)
    return lock
if __name__=="__main__":
    if len(sys.argv)!=2 or sys.argv[1] not in ("stage","apply","verify","confirm","rollback"):raise SystemExit(2)
    ROOT.mkdir(mode=0o700,exist_ok=True)
    with locked():
      action=sys.argv[1]
      globals()[{"stage":"stage","apply":"do_apply","verify":"verify","confirm":"confirm","rollback":"rollback"}[action]]()
