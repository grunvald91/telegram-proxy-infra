#!/usr/bin/env python3
"""One-shot recovery of the already-approved FI217 AWG stack.

No installation, grant issuance, key rotation, DB writes or release changes.
Only start the existing reviewed units after validating local trust and state.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import fcntl

APP = Path("/opt/mnebyvpn-nodekit")
NODE = Path("/var/lib/mnebyvpn-nodekit/fi-test-01")
UNIT_DIR = Path("/etc/systemd/system")
IFACE = Path("/sys/class/net/awg0")
LOCK = Path("/run/lock/mnebyvpn-fi-awg-production.lock")
UNITS = tuple("mnebyvpn-nodekit-"+name+"@fi-test-01.service" for name in
              ("awg", "awg-watchdog", "awg-egress"))
UNIT_FILES = tuple("mnebyvpn-nodekit-"+name+"@.service" for name in
                   ("awg", "awg-watchdog", "awg-egress"))
EXPECTED_UNITS = ["[Unit]\nDescription=MNEBYVPN Nodekit isolated AmneziaWG 3.1 on %i\nDocumentation=https://github.com/amnezia-vpn/amneziawg-go\nAfter=network-online.target\nWants=network-online.target\nConditionPathExists=/var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nTimeoutStartSec=40\nTimeoutStopSec=25\nEnvironment=PATH=/opt/mnebyvpn-amneziawg:/usr/sbin:/usr/bin:/sbin:/bin\nEnvironment=WG_QUICK_USERSPACE_IMPLEMENTATION=/opt/mnebyvpn-amneziawg/amneziawg-go\nExecStartPre=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_lifecycle.py --node-id %i --mode validate\nExecStart=/opt/mnebyvpn-amneziawg/awg-quick up /var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf\nExecStop=/opt/mnebyvpn-amneziawg/awg-quick down /var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf\nKillMode=control-group\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nProtectHome=true\nNoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n","[Unit]\nDescription=MNEBYVPN AWG 3.1 Ed25519 entitlement and expiry watchdog on %i\nRequires=mnebyvpn-nodekit-awg@%i.service\nBindsTo=mnebyvpn-nodekit-awg@%i.service\nAfter=mnebyvpn-nodekit-awg@%i.service\n\n[Service]\nType=simple\nTimeoutStartSec=30\nTimeoutStopSec=20\nEnvironment=PATH=/opt/mnebyvpn-amneziawg:/usr/sbin:/usr/bin:/sbin:/bin\nEnvironment=WG_QUICK_USERSPACE_IMPLEMENTATION=/opt/mnebyvpn-amneziawg/amneziawg-go\nExecStartPre=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_peer_grants.py --node-id %i --mode controller-check\nExecStart=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_peer_grants.py --node-id %i --mode watchdog\nExecStopPost=-/opt/mnebyvpn-amneziawg/awg-quick down /var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf\nRestart=no\nKillMode=control-group\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nProtectHome=true\nProtectSystem=full\nNoNewPrivileges=true\nPrivateTmp=true\nUMask=0077\n\n[Install]\nWantedBy=multi-user.target\n","[Unit]\nDescription=MNEBYVPN Nodekit authorized AWG egress (fail closed) %i\nRequires=mnebyvpn-nodekit-awg-watchdog@%i.service\nBindsTo=mnebyvpn-nodekit-awg-watchdog@%i.service\nAfter=mnebyvpn-nodekit-awg-watchdog@%i.service\nConditionPathExists=/var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nTimeoutStartSec=25\nTimeoutStopSec=30\nNoNewPrivileges=true\nPrivateTmp=true\nProtectHome=true\nUMask=0077\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\nExecStartPre=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_egress.py --node-id %i --mode validate\nExecStart=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_egress.py --node-id %i --mode up\nExecStop=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_egress.py --node-id %i --mode down\nExecStopPost=-/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_egress.py --node-id %i --mode down\nRestart=no\n\n[Install]\nWantedBy=multi-user.target\n"]
SOURCE = {
    "awg_lifecycle.py":"c58d54c0f636645ef1bdedb351d97f9224c79e83",
    "install_components.py":"68d9c578c7690a05fbc9c6024176261762e37896",
    "fi_awg_production_policy.py":"c31ae46df590713a0daf26f79f3bc4916961c22a",
    "awg_egress.py":"4a32a116f1e2c5c967806a4cdf0aee07f1a32985",
    "awg_peer_grants.py":"55fa0940a5a94ebd57cdd3d50041a5a6ed77211c",
}
PINNED = {
    "controller-access.spki":"e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844",
    "identity/node-public.spki":"c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9",
}
class Blocked(ValueError):
    pass

def read(path, maximum=200000, private=True):
    if path.is_symlink():raise Blocked()
    st=path.stat()
    if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1
            or st.st_mode & (0o077 if private else 0o022)
            or not 0<st.st_size<=maximum):raise Blocked()
    return path.read_bytes()

def call(args, timeout=25, check=True):
    return subprocess.run(args,stdin=subprocess.DEVNULL,capture_output=True,
                          text=True,timeout=timeout,check=check)

def systemd(unit, prop):
    return call(["/usr/bin/systemctl","show","--property="+prop,"--value",unit],5).stdout.strip()

def states():
    return tuple(systemd(u,"ActiveState") for u in UNITS)

def matches_host(addr):
    # ip -o -4 addr show uses whitespace-delimited CIDR tokens.
    return any(re.fullmatch(r"217[.]11[.]167[.]91/(?:[0-9]|[12][0-9]|3[0-2])", token)
               for token in addr.split())

def host_and_sources():
    print("FI_AWG_RECOVERY_PREFLIGHT=host",flush=True)
    if os.geteuid()!=0:raise Blocked()
    addr=call(["/usr/sbin/ip","-o","-4","addr","show"],5).stdout
    if not matches_host(addr):
        raise Blocked()
    print("FI_AWG_RECOVERY_PREFLIGHT=protected_directories",flush=True)
    for directory in (APP,NODE,NODE/"amneziawg"):
        st=directory.stat()
        if directory.is_symlink() or not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:
            raise Blocked()
    print("FI_AWG_RECOVERY_PREFLIGHT=installed_sources",flush=True)
    for name,expected in SOURCE.items():
        data=read(APP/name)
        if hashlib.sha1(b"blob "+str(len(data)).encode()+bytes([0])+data).hexdigest()!=expected:
            raise Blocked()
    print("FI_AWG_RECOVERY_PREFLIGHT=node_identity",flush=True)
    for name,expected in PINNED.items():
        if hashlib.sha256(read(NODE/name,100)).hexdigest()!=expected:raise Blocked()
    print("FI_AWG_RECOVERY_PREFLIGHT=unit_identity",flush=True)
    for unit,file,expected in zip(UNITS,UNIT_FILES,EXPECTED_UNITS):
        path=UNIT_DIR/file
        if read(path,private=False)!=expected.encode():raise Blocked()
        if systemd(unit,"FragmentPath")!=str(path) or systemd(unit,"DropInPaths"):
            raise Blocked()
        if systemd(unit,"UnitFileState")!="enabled":raise Blocked()

def local_modules():
    # Imported only after exact source and host checks.
    sys.path.insert(0,str(APP))
    import awg_lifecycle, awg_peer_grants, awg_egress
    return awg_lifecycle,awg_peer_grants,awg_egress

def preflight():
    host_and_sources()
    life,grants,egress=local_modules()
    print("FI_AWG_RECOVERY_PREFLIGHT=signed_configuration",flush=True)
    proof=life.validate(NODE)
    if proof.get("mode")!="production" or proof.get("production_approval")!="signed":
        raise Blocked()
    grants.pinned_controller_key(NODE)
    print("FI_AWG_RECOVERY_PREFLIGHT=egress_configuration",flush=True)
    egress.validate(NODE)
    print("FI_AWG_RECOVERY_PREFLIGHT=existing_ledger",flush=True)
    with grants.LedgerLock(NODE):
        ledger_peers(grants)
    return grants,egress

def ledger_peers(grants):
    # Use existing watchdog clock protection without rewriting its high-water mark.
    now=time.time()
    if not 0<now<4102444800:raise Blocked()
    clock=NODE/"amneziawg"/"clock-highwater.json"
    if clock.exists() or clock.is_symlink():
        raw=json.loads(grants.protected_file(clock,max_bytes=256))
        if (not isinstance(raw,dict) or set(raw)!={"last_seen_ms"} or
                type(raw["last_seen_ms"]) is not int or not 0<=raw["last_seen_ms"]<4102444800000
                or now+5<raw["last_seen_ms"]/1000):raise Blocked()
        now=max(now,raw["last_seen_ms"]/1000)
    ledger=NODE/"amneziawg"/"peer-grants.json"
    if not ledger.exists() or ledger.is_symlink():raise Blocked()
    state=grants.validate_state(json.loads(grants.protected_file(ledger)),NODE.name)
    return grants.active_peers(state,now)

def verify_peers(grants):
    with grants.LedgerLock(NODE):
        grants.assert_runtime_peers(ledger_peers(grants))

def verify_egress(egress, active):
    if active:
        if egress.state() is None or Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()!="1":
            raise Blocked()
        if any(egress.ipt(t,"-C",c,args,check=False).returncode for t,c,args in egress.firewall()):
            raise Blocked()
    else:
        if egress.state() is not None:raise Blocked()
        if any(egress.COMMENT in egress.ipt(t,"-S",c,[]).stdout for t,c,_ in egress.firewall()):
            raise Blocked()

def verify_live(grants,egress):
    if states()!=("active",)*3 or not IFACE.is_dir():raise Blocked()
    port=call([str(APP.parent/"mnebyvpn-amneziawg"/"awg"),"show","awg0","listen-port"],5).stdout.strip()
    if port!="51821":raise Blocked()
    verify_peers(grants)
    verify_egress(egress,True)

def recover():
    print("FI_AWG_RECOVERY_PHASE=preflight",flush=True)
    grants,egress=preflight()
    before=states()
    if before==("active",)*3:
        verify_live(grants,egress)
        return "already_active"
    if any(s not in ("inactive","failed") for s in before) or IFACE.exists():raise Blocked()
    print("FI_AWG_RECOVERY_PREFLIGHT=inactive_network",flush=True)
    verify_egress(egress,False)
    attempted=False
    try:
        for index,unit in enumerate(UNITS):
            print("FI_AWG_RECOVERY_PHASE="+("awg","watchdog","egress")[index],flush=True)
            attempted=True
            call(["/usr/bin/systemctl","start",unit],65)
            if systemd(unit,"ActiveState")!="active":raise Blocked()
            if index==1:
                # Wait for initial signed-ledger reconciliation, not just Type=simple.
                for _ in range(8):
                    try:
                        verify_peers(grants)
                        break
                    except (ValueError,OSError,subprocess.SubprocessError):
                        time.sleep(1)
                else:raise Blocked()
                time.sleep(3)
                verify_peers(grants)
        time.sleep(4)
        verify_live(grants,egress)
        return "restored_local"
    except BaseException:
        if attempted:
            print("FI_AWG_RECOVERY_PHASE=rollback",flush=True)
            for unit in reversed(UNITS):
                try:call(["/usr/bin/systemctl","stop",unit],40,check=False)
                except (OSError,subprocess.SubprocessError):pass
            if IFACE.exists() or any(s not in ("inactive","failed") for s in states()):
                print("FI_AWG_RECOVERY_ROLLBACK=unverified",flush=True)
            else:
                try:
                    verify_egress(egress,False)
                    print("FI_AWG_RECOVERY_ROLLBACK=verified",flush=True)
                except (OSError,ValueError,subprocess.SubprocessError):
                    print("FI_AWG_RECOVERY_ROLLBACK=unverified",flush=True)
        raise

def main():
    try:
        # Lock shared with production activation. Never bypass an active transaction.
        fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            st=os.fstat(fd)
            if st.st_uid!=0 or st.st_nlink!=1 or not stat.S_ISREG(st.st_mode) or st.st_mode&0o077:
                raise Blocked()
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            print("FI_AWG_RECOVERY="+recover(),flush=True)
        finally:os.close(fd)
        return 0
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError) as exc:
        if isinstance(exc,subprocess.CalledProcessError):
            print("FI_AWG_RECOVERY_EXIT_CODE="+str(exc.returncode),flush=True)
        print("FI_AWG_RECOVERY=blocked",flush=True)
        return 2

if __name__=="__main__":
    raise SystemExit(main())
