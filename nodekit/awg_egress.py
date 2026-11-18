#!/usr/bin/env python3
"""Nodekit guarded AWG IPv4 egress service, disabled by default.

Only the approved AWG server + signed-lease expiry watchdog may activate
network ingress. Never alter UFW configuration or unrelated nft/iptables.
The current address pool is intentionally FI-only until fleet IPAM is audited.
"""
from __future__ import annotations
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

from awg_lifecycle import active_unit, enabled_unit, unit_name, validate as validate_awg
from install_components import node_ready, safe_manifest

ROOT=Path("/var/lib/mnebyvpn-nodekit")
APP=Path("/opt/mnebyvpn-nodekit")
UNIT=Path("/etc/systemd/system/mnebyvpn-nodekit-awg-egress@.service")
NODE="fi-test-01"
HOST="fi.mnebyvpn.site"
SUBNET="10.73.91.0/24"
IFACE="eth0"
COMMENT="nodekit-awg-fi-egress"
LOCK=Path("/run/nodekit-awg-fi-egress.lock")
STATE=Path("/run/nodekit-awg-fi-egress.json")
WATCHDOG="mnebyvpn-nodekit-awg-watchdog@"+NODE+".service"

class EgressError(ValueError):
    pass

def call(args,*,check=True,timeout=12):
    return subprocess.run(args,check=check,timeout=timeout,capture_output=True,text=True)

def firewall()->list[tuple[str,str,list[str]]]:
    mark=["-m","comment","--comment",COMMENT]
    return [
        ("filter","INPUT",["-p","udp","--dport","51821",*mark,"-j","ACCEPT"]),
        ("filter","FORWARD",["-i","awg0","-o",IFACE,"-s",SUBNET,*mark,"-j","ACCEPT"]),
        ("filter","FORWARD",["-i",IFACE,"-o","awg0","-d",SUBNET,
                             "-m","conntrack","--ctstate","RELATED,ESTABLISHED",
                             *mark,"-j","ACCEPT"]),
        ("nat","POSTROUTING",["-o",IFACE,"-s",SUBNET,*mark,"-j","MASQUERADE"]),
    ]

def ipt(table,op,chain,args,check=True):
    return call(["iptables","-w","5","-t",table,op,chain,*args],check=check)

def lock():
    fd=os.open(LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    meta=os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o077:
        os.close(fd);raise EgressError("Insecure AWG network lock")
    fcntl.flock(fd,fcntl.LOCK_EX)
    return fd

def unlock(fd):
    fcntl.flock(fd,fcntl.LOCK_UN);os.close(fd)

def state():
    if STATE.is_symlink():raise EgressError("State symlink forbidden")
    if not STATE.exists():return None
    meta=STATE.stat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o077 or meta.st_size>256:
        raise EgressError("Untrusted AWG egress state")
    parsed=json.loads(STATE.read_text())
    if (not isinstance(parsed,dict) or
        set(parsed)!={"schema_version","node_id","previous_forward"} or
        parsed["schema_version"]!=1 or parsed["node_id"]!=NODE or
        parsed["previous_forward"] not in ("0","1")):
        raise EgressError("Invalid egress state")
    return parsed

def record(previous):
    if STATE.exists() or STATE.is_symlink():raise EgressError("Egress already owns state")
    fd=os.open(STATE,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as f:
        json.dump({"schema_version":1,"node_id":NODE,"previous_forward":previous},f)
        f.flush();os.fsync(f.fileno())

def validate(node):
    if node.name!=NODE:raise EgressError("This IPAM network is FI-only")
    validate_awg(node)
    manifest=safe_manifest(node/"manifest.json")
    awg=safe_manifest(node/"amneziawg"/"manifest.json")
    if (manifest.get("advertise_host")!=HOST or
        awg.get("test_address")!="10.73.91.1/24" or
        awg.get("port")!=51821 or
        manifest.get("registration_enabled") is not False or
        manifest.get("activation_enabled") is not False):
        raise EgressError("Unapproved AWG public ingress")
    route=json.loads(call(["ip","-j","route","get","1.1.1.1"]).stdout)
    if not route or route[0].get("dev")!=IFACE:
        raise EgressError("IPv4 exit route differs from reviewed network")
    if Path("/run/nodekit-fi-awg-external.json").exists():
        raise EgressError("Cannot overlap temporary external E2E")
    if not (Path("/opt/mnebyvpn-amneziawg")/"awg").is_file():
        raise EgressError("Official AWG backend missing")
    return {"node_id":NODE,"hostname":HOST,"subnet":SUBNET,"egress_interface":IFACE}

def unit_source():
    return """[Unit]
Description=MNEBYVPN Nodekit authorized AWG egress (fail closed) %i
Requires=mnebyvpn-nodekit-awg-watchdog@%i.service
BindsTo=mnebyvpn-nodekit-awg-watchdog@%i.service
After=mnebyvpn-nodekit-awg-watchdog@%i.service
ConditionPathExists=/var/lib/mnebyvpn-nodekit/%i/amneziawg/awg0.conf

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=25
TimeoutStopSec=30
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
UMask=0077
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
ExecStartPre=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_egress.py --node-id %i --mode validate
ExecStart=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_egress.py --node-id %i --mode up
ExecStop=/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_egress.py --node-id %i --mode down
ExecStopPost=-/usr/bin/python3 /opt/mnebyvpn-nodekit/awg_egress.py --node-id %i --mode down
Restart=no

[Install]
WantedBy=multi-user.target
"""

def install_code(src):
    if APP.is_symlink() or not APP.is_dir() or APP.stat().st_uid!=0:
        raise EgressError("Root-owned Nodekit code path is required")
    if src.is_symlink() or not src.is_file() or src.stat().st_uid!=0:
        raise EgressError("Untrusted egress source")
    if active_unit("mnebyvpn-nodekit-awg-egress@"+NODE+".service") or enabled_unit("mnebyvpn-nodekit-awg-egress@"+NODE+".service"):
        raise EgressError("Never overwrite active/auto-enabled egress")
    for target,content,mode in ((APP/"awg_egress.py",src.read_bytes(),0o600),
                                (UNIT,unit_source().encode(),0o644)):
        if target.is_symlink():raise EgressError("Installed file is symlink")
        if target.exists():
            meta=target.stat()
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or
                meta.st_mode&0o022 or target.read_bytes()!=content):
                raise EgressError("Installed file drift - manual review required")
        else:
            fd,temp=tempfile.mkstemp(prefix=".nodekit-awg-egress-",dir=target.parent)
            try:
                os.fchmod(fd,mode)
                with os.fdopen(fd,"wb") as out:out.write(content);out.flush();os.fsync(out.fileno())
                os.link(temp,target,follow_symlinks=False)
            finally:Path(temp).unlink(missing_ok=True)
    call(["systemctl","daemon-reload"])
    return {"installed":True,"systemd_enabled":False,"started":False,"published":False}

def up():
    fd=lock()
    try:
        if not active_unit(unit_name(NODE)) or not active_unit(WATCHDOG):
            raise EgressError("AWG and signed entitlement watchdog must both run")
        old=state()
        if old is not None:
            for table,chain,args in firewall():
                if ipt(table,"-C",chain,args,check=False).returncode!=0:
                    _down()
                    raise EgressError("Active egress rules drifted; rolled back")
            if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()!="1":
                _down()
                raise EgressError("AWG forwarding drifted; rolled back")
            return {"network_enabled":True,"already_up":True}
        for table,chain,args in firewall():
            if COMMENT in ipt(table,"-S",chain,[]).stdout:
                raise EgressError("Unexpected preexisting Nodekit egress rules")
        original=Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
        if original not in ("0","1"):
            raise EgressError("Unknown original IPv4 forwarding state")
        record(original)
        try:
            for table,chain,args in firewall():
                ipt(table,"-I",chain,["1",*args])
            call(["sysctl","-w","net.ipv4.ip_forward=1"])
            return {"network_enabled":True,"source":SUBNET,"egress":IFACE}
        except BaseException:
            _down()
            raise
    finally:unlock(fd)

def _remove_owned_rules():
    """Remove ALL copies of our exact rules and verify no owned rules remain.

    A stale or manually duplicated NAT rule must never survive one pass.
    We do not touch unrelated UFW chains or broader firewall policies.
    """
    for table, chain, args in reversed(firewall()):
        for _ in range(64):
            result = ipt(table, "-C", chain, args, check=False)
            if result.returncode != 0:
                break
            ipt(table, "-D", chain, args)
    if any(ipt(t, "-C", c, args, check=False).returncode == 0
           for t, c, args in firewall()):
        raise EgressError("Owned AWG firewall rules remain after cleanup")


def _down():
    try:
        old=state()
    except (EgressError, json.JSONDecodeError):
        # Malformed state must not leave a functional public VPN pathway.
        # Do NOT guess a previous value for global ip_forward.
        _remove_owned_rules()
        raise EgressError("Corrupt state: NAT removed, forwarding requires review")
    if old is None:
        # The host could have crashed after inserting firewall entries but
        # before the state file became visible, or state may have been lost.
        # Remove ONLY our exact rules; never change global ip_forward
        # without a previously recorded value.
        _remove_owned_rules()
        return {"network_enabled":False, "orphan_rules_checked":True}
    # Never restore forwarding or delete state until EVERY owned rule is gone.
    _remove_owned_rules()
    if old["previous_forward"]=="0":
        call(["sysctl","-w","net.ipv4.ip_forward=0"])
        if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()!="0":
            raise EgressError("IPv4 forwarding rollback could not be verified")
    STATE.unlink(missing_ok=True)
    return {"network_enabled":False,"rolled_back":True}

def down():
    fd=lock()
    try:return _down()
    finally:unlock(fd)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--node-id",required=True)
    p.add_argument("--mode",required=True,choices=("install","validate","up","down","inspect"))
    args=p.parse_args()
    try:
        if os.geteuid()!=0 or args.node_id!=NODE:
            raise EgressError("Unauthorized Nodekit egress target")
        if args.mode=="down":
            # Cleanup MUST work even if the manifest, installed AWG binaries,
            # or controller verification layer has become corrupt.
            info={"node_id":NODE}
            info.update(down())
            print(json.dumps(info,sort_keys=True))
            return 0
        node=node_ready(ROOT,NODE)
        info=validate(node)
        if args.mode=="install":info.update(install_code(Path(__file__)))
        elif args.mode=="up":info.update(up())
        elif args.mode=="inspect":
            info.update({"network_enabled":state() is not None,
                         "watchdog_running":active_unit(WATCHDOG),
                         "awg_running":active_unit(unit_name(NODE))})
        else:info.update({"network_enabled":False,"validated":True})
        print(json.dumps(info,sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,subprocess.SubprocessError) as err:
        print("NODEKIT_AWG_EGRESS_ERROR="+type(err).__name__,file=sys.stderr)
        return 2

if __name__=="__main__":sys.exit(main())
