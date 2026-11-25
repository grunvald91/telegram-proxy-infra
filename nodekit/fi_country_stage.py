#!/usr/bin/env python3
"""FI private country migration: retain old route catalog, no public grants."""
import asyncio,json,os,re,secrets,signal,socket,ssl,struct,subprocess,sys,time,uuid
from pathlib import Path
from fi_country_transaction import OLD,NEW,switch
from fi_dns_ssh_stage import FI,FI_ROOT,FI_RUNTIME,CONTROLLER_PIN,host,private_dir,read,immutable,require
from fi_routed_runtime import CONFIG,MARKER,STATE,country_corefile
from fi_dns_origin_canary import HOSTS,EXTERNAL_QUERY,dot_probe,query_bytes
from fi_dns_guarded_ingress import SNAPSHOT,CONTROLLER
from fi_dns_signed_grants import load,hostname_digest
from fi_regional_cert_stage import stage as stage_cert,verify_pair,DEST
from fi_routed_probe import routed_dns_query
from fi_dns_meter_rpc import protected_openssl_meter
from fi_dns_reverse_channel import ReverseTransport
GUARD="mnebyvpn-fi-sni-egress-guard.service"
SNI="mnebyvpn-fi-sni-routed-v3.service"
UNIT=Path("/etc/systemd/system")/NEW
STAMP=b"fi-dns-country-v2\n"
OLD_NAME="aaaaaaaaaaaa.fi.dns.mnebyvpn.site"

def cmd(*args,timeout=25):
    return subprocess.run(args,capture_output=True,timeout=timeout,check=True).stdout
def ctl(*args):return cmd("systemctl",*args)
def active(unit):return subprocess.run(["systemctl","is-active","--quiet",unit],capture_output=True,timeout=5).returncode==0
def enabled(unit):return subprocess.run(["systemctl","is-enabled","--quiet",unit],capture_output=True,timeout=5).returncode==0
def listeners(port,udp=False):
    return [x.split()[3] for x in cmd("ss","-H","-lnu" if udp else "-lnt","sport = :"+str(port)).decode().splitlines()]
async def meter_closed():
    meter=protected_openssl_meter(ReverseTransport(),FI_ROOT/"identity/node-private.pk8",CONTROLLER,CONTROLLER_PIN)
    require(await meter._apply("reserve",uuid.uuid4(),secrets.token_hex(32))=="DENY_DISABLED","meter_gate_not_closed")
def private_gate():
    require(active(SNI) and active(GUARD),"guarded_sni_missing")
    require(not listeners(853) and not listeners(853,True),"unexpected_public_dns")
    require(load(SNAPSHOT,CONTROLLER,CONTROLLER_PIN)["grants"]==[],"unexpected_grants")
    asyncio.run(meter_closed())
def wait_local(unit):
    for _ in range(45):
        if active(unit) and listeners(8853)==["127.0.0.1:8853"] and listeners(18854)==["127.0.0.1:18854"]:return
        time.sleep(1)
    raise RuntimeError("private_runtime_not_ready")
def deny_unknown(name,*,tls12=False):
    ctx=ssl.create_default_context()
    if tls12:ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_2
    with socket.create_connection(("127.0.0.1",18854),timeout=5) as raw:
        with ctx.wrap_socket(raw,server_hostname=name) as tls:
            q=query_bytes(0x4a71,EXTERNAL_QUERY)
            tls.sendall(struct.pack("!H",len(q))+q)
            require(tls.recv(2)==b"","unknown_credential_accepted")
def verify_old_origin():
    q=query_bytes(0x4a71,EXTERNAL_QUERY)
    def exact(tls,n):
        data=b""
        while len(data)<n:
            part=tls.recv(n-len(data));require(bool(part),"old_origin_closed");data+=part
        return data
    with socket.create_connection(("127.0.0.1",8853),timeout=5) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=OLD_NAME) as tls:
            tls.sendall(struct.pack("!H",len(q))+q)
            n=struct.unpack("!H",exact(tls,2))[0]
            require(12<n<=16384,"old_origin_bad_frame")
            answer=exact(tls,n)
            ident,flags,qd,an,_,_=struct.unpack("!HHHHHH",answer[:12])
            require(ident==0x4a71 and flags&0x8000 and not flags&15 and qd==1 and an>0 and answer[12:len(q)]==q[12:],"old_origin_bad_answer")
    deny_unknown(OLD_NAME)
def deny_old_name(port=18854):
    """Observe pre-handshake refusal, not a client-side certificate failure.

    asyncio's SSLProtocol can abort the TCP transport before flushing the
    pending fatal alert. Accept a clean zero-byte EOF, or the exact fatal
    unrecognized_name alert. No timeout, partial record, arbitrary alert,
    ServerHello or negotiated TLS qualifies. The caller must prove same-port
    trusted TLS and unknown-credential denial before and after this probe.
    """
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version=ctx.maximum_version=ssl.TLSVersion.TLSv1_2
    incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO()
    hello=ctx.wrap_bio(incoming,outgoing,server_hostname=OLD_NAME)
    try:hello.do_handshake()
    except ssl.SSLWantReadError:pass
    else:raise RuntimeError("unexpected_client_handshake")
    data=outgoing.read()
    require(bool(data),"missing_client_hello")
    def exact(raw,size):
        result=b""
        while len(result)<size:
            part=raw.recv(size-len(result))
            require(bool(part),"old_sni_partial_record")
            result+=part
        return result
    with socket.create_connection(("127.0.0.1",port),timeout=5) as raw:
        raw.sendall(data)
        first=raw.recv(1)
        if not first:return "PRE_HANDSHAKE_EOF"
        kind,major,minor,size=struct.unpack("!BBBH",first+exact(raw,4))
        require(kind==21 and major==3 and minor in (1,2,3) and size==2,"old_sni_not_explicit_alert")
        alert=exact(raw,size)
        require(alert==bytes((2,ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME)),"old_sni_wrong_alert")
    return "FATAL_UNRECOGNIZED_NAME"

def verify_old_sni_denial():
    from fi_dns_signed_grants import RegionalDnsGrantError
    try:hostname_digest(OLD_NAME)
    except RegionalDnsGrantError:pass
    else:raise RuntimeError("obsolete_hostname_digest_accepted")
    deny_unknown(HOSTS[0],tls12=True)
    result=deny_old_name()
    deny_unknown(HOSTS[0],tls12=True)
    print("FI_COUNTRY_OLD_SNI_DENIAL_VERIFIED="+result+";POSITIVE_CONTROLS=2",flush=True)
def route_samples(policy):
    exact=set(policy["exact"]);families=set(policy["families"])
    def covers(name):return name in exact or any(name==x or name.endswith("."+x) for x in families)
    names=[n for n in ("www.youtube.com","gemini.google.com","api.openai.com","claude.ai","integrate.api.nvidia.com") if covers(n)]
    require(len(names)>=3,"missing_route_samples")
    return names
class Ops:
    def preflight(self):
        host(FI);private_gate()
        require(active(OLD) and enabled(OLD) and not active(NEW) and not enabled(NEW),"unexpected_runtime")
        require(not MARKER.exists() and not MARKER.is_symlink(),"unexpected_marker")
    def mark(self):immutable(MARKER,STAMP)
    def unmark(self):
        if MARKER.exists() or MARKER.is_symlink():
            require(read(MARKER,100)==STAMP,"untrusted_marker");MARKER.unlink()
    def stop(self,unit):ctl("stop",unit)
    def start(self,unit):ctl("start",unit)
    def enable(self,unit):ctl("enable",unit)
    def disable(self,unit):ctl("disable",unit)
    def verify_candidate(self):
        wait_local(NEW)
        require(not active(OLD),"old_runtime_still_active")
        for name in HOSTS:
            hostname_digest(name);require(dot_probe(name,EXTERNAL_QUERY),"country_origin_failed");deny_unknown(name)
        verify_old_sni_denial()
        names=route_samples(json.loads(read(STATE/"shared-routes/policy.json",500000)))
        for name in names:
            for kind in (1,28,5,64,65):routed_dns_query(name,kind)
        private_gate()
        print("FI_COUNTRY_PRIVATE_TLS_ROUTES_VERIFIED="+str(len(names)*5),flush=True)
    def verify_commit(self):
        require(active(NEW) and enabled(NEW) and not active(OLD) and not enabled(OLD),"country_enable_failed")
        private_gate()
    def verify_restore(self):
        wait_local(OLD)
        require(active(OLD) and enabled(OLD) and not active(NEW) and not enabled(NEW),"old_restore_failed")
        private_gate();verify_old_origin()
        print("FI_COUNTRY_OLD_SERVICE_RESTORED=true",flush=True)
def migrate(src):
    require(os.geteuid()==0,"root_required")
    require(FI_RUNTIME==Path("/opt/mnebyvpn-fi-dns-country-v2"),"runtime_path_mismatch")
    host(FI);private_dir(src);private_dir(STATE)
    Ops().preflight()
    stage_cert(src);verify_pair(DEST)
    immutable(CONFIG,country_corefile(read(STATE/"RoutedCorefile",500000)))
    private_dir(FI_RUNTIME,True)
    runtime=src/"runtime";private_dir(runtime)
    files=sorted(runtime.glob("*.py"))
    require(len(files)==15,"unexpected_runtime_file_count")
    for file in files:immutable(FI_RUNTIME/file.name,read(file,200000))
    for base in (UNIT.parent,Path("/run/systemd/system"),Path("/usr/lib/systemd/system"),Path("/lib/systemd/system")):
        drop=base/(NEW+".d")
        require(not drop.exists() and not drop.is_symlink(),"unit_override")
        if base!=UNIT.parent:require(not (base/NEW).exists() and not (base/NEW).is_symlink(),"foreign_unit")
    immutable(UNIT,read(src/NEW,10000))
    cmd("systemd-analyze","verify",str(UNIT))
    ctl("daemon-reload")
    switch(Ops())
    print("FI_COUNTRY_PRIVATE_RUNTIME_VERIFIED=true;PUBLIC_DNS=false;GRANTS=0",flush=True)
if __name__=="__main__":
    os.umask(0o077)
    def interrupt(signum,frame):raise SystemExit(128+signum)
    signal.signal(signal.SIGTERM,interrupt);signal.signal(signal.SIGHUP,interrupt)
    try:
        require(len(sys.argv)==2 and re.fullmatch(r"/run/fi-country-[0-9]+-[0-9]+",sys.argv[1]),"invalid_stage")
        migrate(Path(sys.argv[1]))
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.SubprocessError) as exc:
        reason=str(exc) if re.fullmatch(r"[A-Za-z0-9_]+",str(exc)) else type(exc).__name__
        print("FI_COUNTRY_STAGE_BLOCKED="+reason,file=sys.stderr)
        raise SystemExit(2)
