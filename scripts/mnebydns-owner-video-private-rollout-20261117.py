#!/usr/bin/env python3
"""Bounded blue/green update of *only* RU188 owner private DoT.
No broad service restart, public bind, secret logging or unrelated cleanup.
New source is pinned to a green Mnebyvpn commit. Old :8856 stays running.
"""
from __future__ import annotations
import fcntl, hashlib, json, os, pathlib, secrets, socket, ssl, struct
import subprocess, sys, tempfile, time, uuid

SOURCE_SHA="f811efe2a429f1f113719489cbb588fea371c7a3"
IMAGE="mnebyvpn-stage-web:"+SOURCE_SHA
ORIGINAL="mnebydns-personal-dot-private"
CANARY="mnebydns-personal-dot-private-video-canary-20261117"
PREVIOUS="mnebydns-personal-dot-private-previous-20261117"
NAME_OLD_BACKUP="mnebydns-personal-dot-private-video-rollback-20261117"
STATE=pathlib.Path("/etc/mnebydns/personal-dot/owner-video-release-20261117.json")
LOCK="/run/lock/mnebydns-owner-video-20261117.lock"
TEST_OWNER_ID=9000000000000000000
DOMAIN="rr1---sn-gxuo03g-ig3s.googlevideo.com"
OLD_PORT=8856
NEW_PORT=8858
NEW_HEALTH=8859

def call(args:list[str],input_text:str|None=None,check=True)->str:
    p=subprocess.run(args,input=input_text,text=True,capture_output=True,timeout=45)
    if check and p.returncode:
        # Never echo stdout/stderr; SQL and Docker may contain credential data.
        raise RuntimeError("Command failed: "+args[0]+" (code "+str(p.returncode)+")")
    return p.stdout.strip()

def inspect(name:str)->dict|None:
    r=subprocess.run(["docker","inspect",name],capture_output=True,text=True,timeout=15)
    if r.returncode:return None
    return json.loads(r.stdout)[0]

def ensure(cond:bool,msg:str)->None:
    if not cond:raise RuntimeError(msg)

def running(name:str)->dict:
    obj=inspect(name)
    ensure(bool(obj and obj["State"]["Running"]),name+" is not running")
    return obj

def port_occupied(p:int)->bool:
    data=call(["ss","-H","-lnt"])
    return any(line.split()[3].rsplit(":",1)[-1]==str(p)
               for line in data.splitlines() if len(line.split())>=4)

def owner_database(sql:str)->str:
    return call(["docker","exec","-i","mnebyvpn-stage-postgres",
                 "psql","-X","-qAt","-v","ON_ERROR_STOP=1",
                 "-U","mnebyvpn_stage","-d","mnebyvpn_stage"],sql)

def verify_migration()->None:
    sql=("SELECT CASE WHEN EXISTS(SELECT 1 FROM deployment_schema_migrations "
         "WHERE file_name='0130_owner_dns_video_routes.sql') "
         "THEN 'READY' ELSE 'MISSING' END;")
    ensure(owner_database(sql)=="READY","Migration 0130 missing")

def read_state()->dict:
    ensure(STATE.is_file(),"Release state not found")
    return json.loads(STATE.read_text())

def save_state(value:dict)->None:
    STATE.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
    # State is created once per release, not a shared config.
    with os.fdopen(os.open(STATE,flags,0o600),"w") as f:
        json.dump(value,f)
        f.flush()
        os.fsync(f.fileno())

def update_state(value:dict)->None:
    tmp=STATE.with_suffix(".tmp")
    fd=os.open(tmp,os.O_CREAT|os.O_TRUNC|os.O_WRONLY,0o600)
    with os.fdopen(fd,"w") as f:
        json.dump(value,f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp,STATE)

def ufw_check()->bool:
    return "MNEBYDNS owner video canary 20261117" in call(["ufw","status"])

def ufw_add()->None:
    call(["ufw","allow","in","on","tg-relay","from","10.66.77.1",
          "to","10.66.77.2","port",str(NEW_PORT),"proto","tcp",
          "comment","MNEBYDNS owner video canary 20261117"])

def ufw_remove()->None:
    call(["ufw","delete","allow","in","on","tg-relay","from","10.66.77.1",
          "to","10.66.77.2","port",str(NEW_PORT),"proto","tcp"])

def one_record(label:str,route:str)->tuple[str,str]:
    row_id=str(uuid.uuid4())
    tokenhash=hashlib.sha256(label.encode()).hexdigest()
    request_key="video-canary-"+row_id
    # Test credentials are short-lived, never returned to the caller,
    # and never decryptable by the bot (test-only ciphertext).
    sql=(f"INSERT INTO owner_dns_links "
         f"(id,owner_telegram_id,token_sha256,token_ciphertext,request_key,"
         f"permanent,expires_at,video_route) VALUES ('{row_id}',"
         f"{TEST_OWNER_ID},'{tokenhash}',repeat('x',54),"
         f"'{request_key}',false,clock_timestamp()+interval '10 minutes','{route}');")
    owner_database(sql)
    try:
        status=owner_database("SELECT owner_dns_link_status('"+label+"');")
        expected="ALLOWED_SMART_DNS" if route=="smart_dns" else "ALLOWED"
        ensure(status==expected,"Owner DNS credential policy mismatch")
    except Exception:
        owner_database("DELETE FROM owner_dns_links WHERE id='"+row_id+
                       "' AND owner_telegram_id="+str(TEST_OWNER_ID)+";")
        raise
    return row_id,request_key

def dns_query(ip:str,port:int,label:str,domain:str,typ:int=1)->tuple[int,list[str]]:
    host=label+".dns.mnebyvpn.site"
    qid=secrets.randbelow(65535)
    qname=b"".join(bytes([len(x)])+x.encode("ascii") for x in domain.split("."))+b"\0"
    q=struct.pack("!HHHHHH",qid,256,1,0,0,0)+qname+struct.pack("!HH",typ,1)
    with socket.create_connection((ip,port),timeout=9) as raw:
        raw.settimeout(9)
        with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as tls:
            tls.sendall(struct.pack("!H",len(q))+q)
            first=tls.recv(2)
            while len(first)<2:
                more=tls.recv(2-len(first))
                ensure(bool(more),"Short DNS TCP length")
                first+=more
            n=struct.unpack("!H",first)[0]
            ensure(12<=n<=16384,"Invalid DNS answer size")
            reply=b""
            while len(reply)<n:
                chunk=tls.recv(n-len(reply))
                ensure(bool(chunk),"Truncated DoT answer")
                reply+=chunk
    ensure(struct.unpack_from("!H",reply)[0]==qid,"DNS reply ID mismatch")
    flags,qd,an=struct.unpack_from("!HHH",reply,2)
    ensure(flags&0x8000!=0 and qd==1,"Invalid DNS response")
    rcode=flags&15
    offset=12
    def skip_name(pos:int)->int:
        for _ in range(128):
            ensure(pos<len(reply),"DNS name truncated")
            size=reply[pos]
            if size&0xC0==0xC0:
                ensure(pos+2<=len(reply),"DNS compression truncated")
                return pos+2
            ensure(size<=63 and pos+1+size<=len(reply),"Bad DNS label")
            pos+=1+size
            if size==0:return pos
        raise RuntimeError("DNS compression/name loop")
    offset=skip_name(offset)+4
    addresses=[]
    for _ in range(an):
        offset=skip_name(offset)
        ensure(offset+10<=len(reply),"DNS record truncated")
        rrtype,rrclass,ttl,rdlen=struct.unpack_from("!HHIH",reply,offset)
        offset+=10
        ensure(offset+rdlen<=len(reply),"DNS RDATA truncated")
        if rrtype==1 and rrclass==1 and rdlen==4:
            addresses.append(socket.inet_ntoa(reply[offset:offset+4]))
        offset+=rdlen
    if typ in (28,64,65):
        ensure(an==0,"Unexpected video AAAA/HTTPS/SVCB answer")
    return rcode,addresses

def policy_probe(endpoint_ip:str,endpoint_port:int)->None:
    temp_ids=[]
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789"
    try:
        labels=[]
        for route in ("smart_dns","vpn_origin"):
            label="".join(secrets.choice(alphabet) for _ in range(12))
            row_id,_=one_record(label,route)
            temp_ids.append(row_id)
            labels.append(label)
        smart,legacy=labels
        rcode,mapped=dns_query(endpoint_ip,endpoint_port,smart,DOMAIN)
        ensure(rcode==0 and "89.125.90.101" in mapped,
               "Smart DNS video A did not map to DE89")
        rcode,origins=dns_query(endpoint_ip,endpoint_port,legacy,DOMAIN)
        ensure(rcode==0 and bool(origins) and
               "89.125.90.101" not in origins,
               "Legacy VPN-origin video A changed or failed")
        for t in (28,64,65):
            for label in labels:
                code,ans=dns_query(endpoint_ip,endpoint_port,label,DOMAIN,t)
                ensure(code==0 and not ans,"Video hint/IPv6 policy failed")
        code,ans=dns_query(endpoint_ip,endpoint_port,smart,"example.org")
        ensure(code==0 and bool(ans),"Ordinary domain failed")
        print("SMART_VIDEO_MAPPED_DE89=PASS",flush=True)
        print("LEGACY_VPN_VIDEO_ORIGIN=PASS",flush=True)
        print("VIDEO_IPV6_AND_HINTS_POLICY=PASS",flush=True)
        print("ORDINARY_DOMAIN=PASS",flush=True)
    finally:
        if temp_ids:
            sql="DELETE FROM owner_dns_links WHERE owner_telegram_id="+str(TEST_OWNER_ID)+" AND id IN ("+(",".join("'"+x+"'" for x in temp_ids))+");"
            owner_database(sql)

def stage()->None:
    ensure(not STATE.exists(),"Release already staged")
    ensure(not inspect(CANARY) and not inspect(PREVIOUS) and not inspect(NAME_OLD_BACKUP),
           "Reserved container name already used")
    old=running(ORIGINAL)
    ensure(not port_occupied(NEW_PORT) and not port_occupied(NEW_HEALTH),
           "Canary port already occupied")
    ensure(pathlib.Path("/opt/mnebyvpn/staging/active_sha").read_text().strip()==SOURCE_SHA,
           "Active staging release SHA does not match pinned green source")
    call(["docker","image","inspect",IMAGE])
    verify_migration()
    ensure("Status: active" in call(["ufw","status"]),"UFW inactive")
    ensure("10.66.77.2/24" in call(["ip","-o","-4","addr","show","dev","tg-relay"]),
           "WireGuard private address changed")
    av=int(next((line.split()[1] for line in pathlib.Path("/proc/meminfo").read_text().splitlines()
                 if line.startswith("MemAvailable:")),"0"))
    ensure(av>=320000,"Insufficient available memory for safe blue-green canary")
    env=dict(x.split("=",1) for x in old["Config"]["Env"] if "=" in x)
    ensure(env.get("MNEBYDNS_OWNER_LINKS_ENABLED")=="yes","Owner authorization not enabled")
    ensure(env.get("MNEBYDNS_PERSONAL_DOT_PORT")=="8856","Old endpoint has changed")
    ensure(env.get("MNEBYDNS_PERSONAL_MAPPED_DOT_IP")=="10.66.77.1" and
           env.get("MNEBYDNS_PERSONAL_MAPPED_DOT_PORT")=="1853","Mapped origin changed")
    ensure(env.get("MNEBYDNS_PERSONAL_DOT_BIND_IP")=="10.66.77.2","Private bind changed")
    mounts=old["Mounts"]
    destinations={m["Destination"] for m in mounts}
    expected={"/run/mnebydns-personal",
              "/srv/mnebyvpn/apps/service/src/personal-dot-production.ts",
              "/srv/mnebyvpn/packages/dns-policy/src/owner-dns-access.ts",
              "/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts",
              "/srv/mnebyvpn/packages/dns-policy/src/pooled-dot-upstream.ts"}
    ensure(destinations==expected and all(m["Type"]=="bind" and not m["RW"] for m in mounts),
           "Unexpected original container overlays")
    new_env_path=None
    state={"source_sha":SOURCE_SHA,"old_id":old["Id"],"firewall_created":False,
           "stage_completed":False,"promoted":False}
    save_state(state)
    try:
        if not ufw_check():
            ufw_add()
            state["firewall_created"]=True
            update_state(state)
        fd,new_env_path=tempfile.mkstemp(prefix="mnebydns-owner-video-",dir="/dev/shm")
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w") as f:
            for item in old["Config"]["Env"]:
                # Docker envfile accepts raw NAME=VALUE, no key or token logged.
                ensure("\n" not in item and "\r" not in item,"Multiline environment denied")
                f.write(item+"\n")
        cmd=["docker","run","-d","--name",CANARY,"--network","host",
             "--user","1001:1001","--read-only",
             "--tmpfs","/tmp:rw,nosuid,nodev,size=8m",
             "--cap-drop","ALL","--security-opt","no-new-privileges",
             "--pids-limit","96","--memory","256m","--cpus","0.5",
             "--restart","unless-stopped","--env-file",new_env_path,
             "-e","MNEBYDNS_PERSONAL_DOT_PORT="+str(NEW_PORT),
             "-e","MNEBYDNS_PERSONAL_DOT_HEALTH_PORT="+str(NEW_HEALTH)]
        for m in mounts:
            if m["Destination"] in (
               "/srv/mnebyvpn/packages/dns-policy/src/owner-dns-access.ts",
               "/srv/mnebyvpn/packages/dns-policy/src/personal-dot-listener.ts"):
                continue  # Use the CI-tested policy in the pinned new image.
            ensure(pathlib.Path(m["Source"]).exists(),"Original overlay disappeared")
            cmd+=["--mount","type=bind,source="+m["Source"]+
                  ",target="+m["Destination"]+",readonly"]
        cmd+=["--entrypoint","node",IMAGE,
              "--experimental-strip-types","apps/service/src/personal-dot-production.ts"]
        call(cmd)
        ready=False
        for _ in range(35):
            if not running_if_present(CANARY):
                time.sleep(0.6)
                continue
            try:
                response=call(["curl","--noproxy","*","-fsS",
                               "--connect-timeout","1","--max-time","2",
                               "http://127.0.0.1:"+str(NEW_HEALTH)+"/readyz"])
                if '"ready":true' in response:
                    ready=True
                    break
            except Exception:
                pass
            time.sleep(1)
        ensure(ready,"New gateway did not become ready")
        policy_probe("10.66.77.2",NEW_PORT)
        ensure(running(ORIGINAL)["Id"]==old["Id"],"Original gateway changed during stage")
        state["stage_completed"]=True
        update_state(state)
        print("PRIVATE_NEW_CANARY_READY=PASS")
        print("PRIVATE_OLD_8856_UNCHANGED=true")
        print("PRIVATE_PRIVATE_8858_ALLOWED_PEER_ONLY=true")
    except Exception:
        rollback(stage_failure=True)
        raise
    finally:
        if new_env_path and pathlib.Path(new_env_path).exists():
            pathlib.Path(new_env_path).unlink()

def running_if_present(name:str)->bool:
    o=inspect(name)
    return bool(o and o["State"]["Running"])

def verify_public()->None:
    st=read_state()
    ensure(st.get("stage_completed"),"Canary stage not complete")
    running(CANARY)
    # Actual public path: RU -> DE89:853 SNI personal -> RU new :8858.
    policy_probe("89.125.90.101",853)
    print("PUBLIC_PERSONAL_DOT_SMART_AND_LEGACY=PASS")

def promote()->None:
    st=read_state()
    ensure(st.get("stage_completed") and not st.get("promoted"),"Wrong release state")
    ensure(running(ORIGINAL)["Id"]==st["old_id"],"Old gateway identity changed")
    running(CANARY)
    ensure(not inspect(PREVIOUS),"Old backup name already occupied")
    call(["docker","rename",ORIGINAL,PREVIOUS])
    try:
        call(["docker","rename",CANARY,ORIGINAL])
    except Exception:
        call(["docker","rename",PREVIOUS,ORIGINAL])
        raise
    st["promoted"]=True
    update_state(st)
    ensure(running(ORIGINAL)["Config"]["Env"] is not None,"New gateway not running")
    running(PREVIOUS)
    print("PRIVATE_ACTIVE_NAME_UPDATED=true")
    print("PRIVATE_OLD_GATEWAY_STILL_RUNNING_ON_8856=true")

def rollback(stage_failure=False)->None:
    if not STATE.exists():
        print("PRIVATE_ROLLBACK_NOT_STAGED=true")
        return
    st=read_state()
    if st.get("promoted"):
        if inspect(NAME_OLD_BACKUP):
            raise RuntimeError("Existing rollback name collision")
        if inspect(ORIGINAL):
            call(["docker","rename",ORIGINAL,NAME_OLD_BACKUP])
        if inspect(PREVIOUS):
            call(["docker","rename",PREVIOUS,ORIGINAL])
        if inspect(NAME_OLD_BACKUP):
            call(["docker","rm","-f",NAME_OLD_BACKUP])
    else:
        # Restore an interrupted name promotion too, even before state flush.
        if inspect(PREVIOUS):
            ensure(not inspect(ORIGINAL),"Ambiguous original/previous release names")
            call(["docker","rename",PREVIOUS,ORIGINAL])
        if inspect(CANARY):
            call(["docker","rm","-f",CANARY])
    if st.get("firewall_created"):
        ufw_remove()
    STATE.unlink(missing_ok=True)
    ensure(running_if_present(ORIGINAL),"Previous personal gateway unavailable")
    print("PRIVATE_ROLLBACK_RESTORED_8856=true")

def status()->None:
    for name in (ORIGINAL,CANARY,PREVIOUS):
        o=inspect(name)
        if not o:
            print("GATEWAY_"+name+"=absent")
            continue
        env={v.split("=",1)[0]:v.split("=",1)[1] for v in o["Config"]["Env"] if "=" in v}
        print("GATEWAY_"+name+"="+o["State"]["Status"]+"_PORT_"+env.get("MNEBYDNS_PERSONAL_DOT_PORT","unknown"))
    print("OWNER_VIDEO_RELEASE_STATE="+("present" if STATE.exists() else "absent"))

def main()->None:
    if os.geteuid()!=0:raise RuntimeError("Root required")
    if len(sys.argv)!=2 or sys.argv[1] not in ("stage","verify-public","promote","rollback","status"):
        raise RuntimeError("Expected a single release phase")
    pathlib.Path(LOCK).parent.mkdir(parents=True,exist_ok=True)
    with open(LOCK,"w") as handle:
        fcntl.flock(handle,fcntl.LOCK_EX)
        cmd=sys.argv[1]
        if cmd=="stage":stage()
        elif cmd=="verify-public":verify_public()
        elif cmd=="promote":promote()
        elif cmd=="rollback":rollback()
        else:status()

if __name__=="__main__":
    try:main()
    except Exception as exc:
        # Never include subprocess stderr, SQL, labels or environment.
        print("PRIVATE_OWNER_VIDEO_RELEASE_FAILED="+type(exc).__name__+
              ":"+str(exc)[:100],file=sys.stderr)
        sys.exit(2)
