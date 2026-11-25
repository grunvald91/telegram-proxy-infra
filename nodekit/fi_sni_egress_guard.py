#!/usr/bin/env python3
"""Dedicated UID egress policy; never flush or replace the host firewall."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import socket
import subprocess
import sys
import time

TABLE="mnebyvpn_fi_sni_guard"
USER="mnebyvpn-fi-sni-egress"
STATE=Path("/var/lib/mnebyvpn-nodekit/fi-test-01/dns-auth")
FINGERPRINT=STATE/"sni-egress-fingerprint"
DENIED=("0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
        "169.254.0.0/16","172.16.0.0/12","192.0.0.0/24","192.0.2.0/24",
        "192.88.99.0/24","192.168.0.0/16","198.18.0.0/15","198.51.100.0/24",
        "203.0.113.0/24","224.0.0.0/4","240.0.0.0/4",
        "217.11.167.91/32","188.120.254.223/32","89.125.90.101/32")

def require(ok,label):
    if not ok:raise RuntimeError(label)

def uid():
    p=pwd.getpwnam(USER)
    require(0<p.pw_uid<1000 and p.pw_shell in ("/usr/sbin/nologin","/bin/false"),"unexpected_proxy_user")
    return p.pw_uid

def rules(number):
    require(type(number) is int and 0<number<65536,"invalid_uid")
    # Only the dedicated proxy UID is restricted. Reply packets to clients
    # are not new outbound connections. Explicit DNS resolvers are the only
    # non-HTTPS egress. IPv6 and all other traffic default to reject.
    return f"""table inet {TABLE} {{
 chain output {{
  type filter hook output priority -5; policy accept;
  meta skuid {number} jump proxy_out
 }}
 chain proxy_out {{
  ct direction reply ct state established counter accept
  ip daddr {{ 1.1.1.1, 1.0.0.1 }} udp dport 53 counter accept
  ip daddr {{ 1.1.1.1, 1.0.0.1 }} tcp dport 53 counter accept
  fib daddr type local counter reject
  ip daddr {{ {", ".join(DENIED)} }} counter reject
  ip protocol tcp tcp dport 443 counter accept
  counter reject
 }}
}}
"""

def call(*args,data=None):
    p=subprocess.run(["nft",*args],input=data,capture_output=True,timeout=10)
    require(p.returncode==0,"nft_command_failed")
    return p.stdout

def table():
    p=subprocess.run(["nft","-j","list","tables"],capture_output=True,timeout=8,check=True)
    names=[x["table"]["name"] for x in json.loads(p.stdout)["nftables"] if "table" in x and x["table"]["family"]=="inet"]
    if TABLE not in names:return None
    return json.loads(call("-j","list","table","inet",TABLE))

def digest(value):
    # Ignore kernel-assigned handles and counters only. Any rule, chain,
    # priority or policy drift changes the hash.
    def norm(x):
        if isinstance(x,dict):
            return {k:norm(v) for k,v in x.items() if k not in ("handle","packets","bytes","metainfo")}
        if isinstance(x,list):return [norm(v) for v in x if not (isinstance(v,dict) and "metainfo" in v)]
        return x
    return hashlib.sha256(json.dumps(norm(value),sort_keys=True,separators=(",",":")).encode()).hexdigest()

def install(number,path=FINGERPRINT):
    from fi_dns_ssh_stage import immutable,read
    existing=table()
    if existing is None:
        body=rules(number).encode()
        call("-c","-f","-",data=body)
        call("-f","-",data=body)
        existing=table()
        require(existing is not None,"guard_table_missing")
    else:
        require(path.exists(),"unowned_guard_table")
    value=digest(existing)
    immutable(path,(str(number)+":"+value+"\n").encode())
    require(read(path,100)==(str(number)+":"+value+"\n").encode(),"guard_fingerprint_mismatch")
    return value

def verify(number,expected):
    current=table()
    require(current is not None and digest(current)==expected,"guard_rules_drift")
    require(uid()==number,"proxy_uid_changed")

def notify(value):
    address=os.environ.get("NOTIFY_SOCKET")
    require(bool(address),"notify_socket_missing")
    if address.startswith("@"):address="\0"+address[1:]
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as s:s.sendto(value.encode(),address)

def main():
    from fi_dns_ssh_stage import host,FI,private_dir
    os.umask(0o077);host(FI);private_dir(STATE)
    n=uid();expected=install(n)
    verify(n,expected)
    notify("READY=1")
    print("FI_SNI_EGRESS_GUARD_READY=true",flush=True)
    while True:
        time.sleep(1)
        verify(n,expected)

if __name__=="__main__":
    try:main()
    except (OSError,RuntimeError,ValueError,KeyError,subprocess.SubprocessError):
        print("FI_SNI_EGRESS_GUARD_FAILED=true",file=sys.stderr,flush=True)
        raise SystemExit(2)
