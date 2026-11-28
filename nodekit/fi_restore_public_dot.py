#!/usr/bin/env python3
"""Restore previously committed FI public DoT socket, without altering grants."""
import hashlib
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import stat

FI="217.11.167.91"
STATE=Path("/var/lib/mnebyvpn-nodekit/fi-test-01/dns-auth")
MARKER=STATE/"public-dot.enable"
CUSTOMER=STATE/"customer-dataplane.enable"
SOCKET="mnebyvpn-fi-public-dot.socket"
SERVICE="mnebyvpn-fi-public-dot.service"
DEPS=("mnebyvpn-fi-dns-country.service","mnebyvpn-fi-sni-routed-v3.service",
      "mnebyvpn-fi-sni-egress-guard.service")
PINS={
    Path("/etc/systemd/system")/SOCKET:"a4ce8b353107e464c018bae66fd33706f82ab671",
    Path("/etc/systemd/system")/SERVICE:"22530c76864b0cc02fcf7531f513ba3bc26f5fcd",
    STATE/"PublicDotRelay.py":"b039d7c5791e6d1dbfbbf9fb2b9a8c62420a1878",
}
NAMES=("aaaaaaaaaaaa.fi.mnebyvpn.site","bbbbbbbbbbbb.fi.mnebyvpn.site")
class Blocked(ValueError):pass
def require(ok,label):
    if not ok:raise Blocked(label)
def run(*args,timeout=10):
    return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=True).stdout.strip()
def active(unit):
    return subprocess.run(["systemctl","is-active","--quiet",unit],capture_output=True,timeout=5).returncode==0
def prop(unit,key):
    return run("systemctl","show",unit,"-p",key,"--value")
def read(path,limit=200000):
    require(not path.is_symlink() and path.is_file(),"missing_or_symlink")
    s=path.stat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and not s.st_mode&0o022 and 0<s.st_size<=limit,"untrusted_file")
    return path.read_bytes()
def blob(data):
    return hashlib.sha1(b"blob "+str(len(data)).encode()+bytes([0])+data).hexdigest()
def listeners(port,udp=False):
    return [line.split()[3] for line in run("ss","-H","-lnu" if udp else "-lnt","sport = :"+str(port)).splitlines()]
def q():
    return struct.pack("!6H",0x4a71,256,1,0,0,0)+bytes([7])+b"example"+bytes([3])+b"com"+bytes([0,0,1,0,1])
def exact(tls,n):
    data=bytearray()
    while len(data)<n:
        part=tls.recv(n-len(data))
        if not part:raise Blocked("origin_closed")
        data.extend(part)
    return bytes(data)
def probe(host,port,name,denied):
    question=q()
    with socket.create_connection((host,port),timeout=6) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname=name) as tls:
            tls.settimeout(6)
            require(("DNS","*.fi.mnebyvpn.site") in tls.getpeercert().get("subjectAltName",()),"wrong_country_cert")
            tls.sendall(struct.pack("!H",len(question))+question)
            if denied:
                require(tls.recv(2)==b"","unknown_credential_accepted")
            else:
                n=struct.unpack("!H",exact(tls,2))[0]
                require(12<n<=16384,"bad_dns_frame")
                response=exact(tls,n)
                ident,flags,qd,an,_,_=struct.unpack("!6H",response[:12])
                require(ident==0x4a71 and flags&0x8000 and not flags&15 and qd==1 and an>0 and response[12:len(question)]==question[12:],"bad_dns_answer")
def preflight():
    require(os.geteuid()==0 and FI in [x.split("/")[0] for x in run("ip","-o","-4","addr","show").split()],"wrong_host")
    require(all(active(u) for u in DEPS),"dependency_inactive")
    require(listeners(8853)==["127.0.0.1:8853"] and listeners(18854)==["127.0.0.1:18854"] and listeners(14443)==["127.0.0.1:14443"] and not listeners(853,True),"listener_drift")
    for path,pin in PINS.items():
        require(blob(read(path))==pin,"installed_artifact_drift")
    for unit in (SOCKET,SERVICE):
        require(prop(unit,"FragmentPath")==str(Path("/etc/systemd/system")/unit) and not prop(unit,"DropInPaths"),"unit_override")
    require(read(MARKER,100)==b"fi-public-dot-v1"+bytes([10]),"public_marker_missing")
    require(prop(SOCKET,"UnitFileState")=="enabled","socket_not_enabled")
    # Verify the existing private resolver and fail-closed meter; no customer grant changes.
    for name in NAMES:
        probe("127.0.0.1",8853,name,False)
        probe("127.0.0.1",18854,name,True)
    if CUSTOMER.exists() or CUSTOMER.is_symlink():
        require(read(CUSTOMER,100)==b"fi-dns-customer-v1"+bytes([10]),"customer_marker_drift")
        print("FI_DOT_CUSTOMER_MARKER=present",flush=True)
    else:print("FI_DOT_CUSTOMER_MARKER=absent",flush=True)
def restore():
    preflight()
    if active(SOCKET):
        require(listeners(853)==[FI+":853"],"public_listener_drift")
        for name in NAMES:probe(FI,853,name,True)
        return "already_active"
    require(not active(SERVICE) and not listeners(853),"unexpected_public_listener")
    try:
        run("systemctl","start",SOCKET,timeout=30)
        require(active(SOCKET) and listeners(853)==[FI+":853"],"public_socket_failed")
        for name in NAMES:probe(FI,853,name,True)
        require(active(SERVICE) and all(active(u) for u in DEPS),"relay_inactive")
        pid=int(prop(SERVICE,"MainPID"))
        require(pid>1,"relay_pid_missing")
        status=dict(x.split(":",1) for x in (Path("/proc")/str(pid)/"status").read_text().splitlines() if ":" in x)
        require(all(int(x)>0 for x in status["Uid"].split()) and int(status["CapEff"].strip(),16)==0,"relay_privilege_drift")
        return "restored_local"
    except BaseException:
        run("systemctl","stop",SOCKET,SERVICE,timeout=30)
        require(not listeners(853),"rollback_unverified")
        raise
def main():
    try:
        result=restore()
        print("FI_DOT_RECOVERY="+result,flush=True)
        return 0
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:
        print("FI_DOT_RECOVERY_BLOCKED="+(str(e) if isinstance(e,Blocked) else type(e).__name__),flush=True)
        return 2
if __name__=="__main__":raise SystemExit(main())
