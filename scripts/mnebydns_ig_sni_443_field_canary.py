#!/usr/bin/env python3
"""Short, exact-peer Android HTTPS/443 SNI segmentation experiment.

RESEARCH ONLY. Explicit opt-in, root, known RU host, one participant IPv4.
Keeps existing telegram-nfqws.service and its NFQUEUE 210 rule intact.
The existing 210 worker interferes with outgoing SYN-ACK on RU:443, so this
pilot pairs a peer-scoped queue-210 return with a peer-scoped OUTPUT queue-211
window clamp. The watchdog is armed BEFORE either temporary rule is inserted.
No DNS, Nginx, WireGuard, certificates, or TLS bytes are modified.

The copied standalone script can independently roll back its own exact tags
even if the test supervisor dies; it has no import of the worker on rollback.
"""
from __future__ import annotations
import fcntl
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

RU="188.120.254.223"
GEN="/usr/local/sbin/telegram-nfqws-rules"
EXPECTED_GEN_SHA256="8beeffbe10e7da097e10bde4b1ef568219d52c2f1c04b189e71602069de9ec3f"
ROOT=Path("/run/mnebydns-ig-443-frag")
LOCK=Path("/run/lock/mnebydns-nfqws-guard-install.lock")
TAG_PREFIX="MNEBY_IG_FRAG443_"
TEST_TIME=65
WATCHDOG_TIME=100
NETFILTER=("inet","telegram_nfqws","post")
QUEUE=211

def run(args,*,stdin=None,check=True,timeout=14):
    result=subprocess.run(args,input=stdin,text=True,capture_output=True,
                          check=False,timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(args[0]+" failed (code "+str(result.returncode)+")")
    return result

def validate(peer_s,runid):
    peer=ipaddress.IPv4Address(peer_s)
    if not peer.is_global or str(peer)==RU:
        raise ValueError("One distinct public IPv4 client required")
    if not re.fullmatch(r"[1-9][0-9]{8,15}",runid):
        raise ValueError("Run ID must contain 9-16 digits")
    return str(peer)

def tag_for(runid):
    return TAG_PREFIX+runid

def iptables_rule(peer,tag):
    return ["-s",RU,"-d",peer,"-p","tcp","--sport","443",
            "--tcp-flags","SYN,ACK","SYN,ACK",
            "-m","comment","--comment",tag,
            "-j","NFQUEUE","--queue-num",str(QUEUE),"--queue-bypass"]

def nft_rule(peer,tag):
    return (
        "insert rule inet telegram_nfqws post "
        'oifname "ens3" '
        f"ip saddr {RU} ip daddr {peer} tcp sport 443 "
        "tcp flags & (syn | ack) == (syn | ack) "
        "ct reply packets 1-20 meta mark & 0x40000000 == 0 "
        f'counter return comment "{tag}"\n'
    )

def chain():
    return run(["nft","-a","list","chain",*NETFILTER]).stdout

def own_handles(snapshot,tag):
    found=[]
    for line in snapshot.splitlines():
        if f'comment "{tag}"' not in line:
            continue
        match=re.search(r"# handle (\d+)\s*$",line)
        if match: found.append(int(match.group(1)))
        else: raise RuntimeError("Unexpected nft rule handle format")
    return found

def iptables_present(peer,tag):
    result=run(["iptables","-w","-t","mangle","-C","OUTPUT",*iptables_rule(peer,tag)],
               check=False)
    if result.returncode not in (0,1):
        raise RuntimeError("Cannot inspect tagged iptables rule")
    return result.returncode==0

def cleanup(peer,tag):
    """Scoped, idempotent rollback. Never flush chains or restart services."""
    if iptables_present(peer,tag):
        run(["iptables","-w","-t","mangle","-D","OUTPUT",*iptables_rule(peer,tag)])
    handles=own_handles(chain(),tag)
    if len(handles)>1:
        raise RuntimeError("Ambiguous canary nft rule; refuse broad cleanup")
    for handle in handles:
        run(["nft","delete","rule",*NETFILTER,"handle",str(handle)])
    if iptables_present(peer,tag) or own_handles(chain(),tag):
        raise RuntimeError("Scoped rollback not verified")
    print("ig443_scoped_rules_absent=true",flush=True)

def preflight(peer,tag):
    for name in ("nft","iptables","systemd-run","systemctl","python3"):
        if shutil.which(name) is None:
            raise RuntimeError("Required system tool absent: "+name)
    source=Path(GEN)
    if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest()!=EXPECTED_GEN_SHA256:
        raise RuntimeError("Unknown installed queue210 generator; fail closed")
    if Path("/etc/mnebydns/telegram-synack-canary-ipv4").exists():
        raise RuntimeError("Another persistent peer canary already enabled")
    for service in ("telegram-nfqws.service","nginx.service"):
        if run(["systemctl","is-active","--quiet",service],check=False).returncode:
            raise RuntimeError("Stable production service inactive")
    snap=chain()
    if "chain post {" not in snap or "hook postrouting" not in snap or "policy accept" not in snap:
        raise RuntimeError("Unexpected live NFQUEUE chain")
    existing=[l for l in snap.splitlines() if "tcp sport 443" in l and re.search(r"\bto\s+210\b",l)]
    if len(existing)!=1 or "bypass" not in existing[0] or "mark" not in existing[0]:
        raise RuntimeError("Expected exactly one marked 210 queue rule")
    if TAG_PREFIX in snap or "MNEBY_PHONE_TCP_" in snap or "MNEBY_IG_SYNACK_AB_" in snap:
        raise RuntimeError("Previous related canary active")
    if iptables_present(peer,tag):
        raise RuntimeError("Existing tagged iptables rule")
    dump=run(["iptables","-w","-t","mangle","-S","OUTPUT"]).stdout
    if TAG_PREFIX in dump or "MNEBYDNS_SYNACK_CANARY_211" in dump:
        raise RuntimeError("Conflicting OUTPUT queue canary")
    nfq=Path("/proc/net/netfilter/nfnetlink_queue")
    if not nfq.is_file():
        raise RuntimeError("No NFQUEUE kernel status")
    for row in nfq.read_text().splitlines():
        if row.split() and row.split()[0]==str(QUEUE):
            raise RuntimeError("Queue211 already owned")
    # Validate complete nft expression without inserting it.
    run(["nft","--check","-f","-"],stdin=nft_rule(peer,tag))
    print("ig443_live_baseline_verified=true",flush=True)

def queue_ready(worker,marker):
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        if marker.is_file() and worker.poll() is None:
            return
        if worker.poll() is not None:
            raise RuntimeError("Queue211 worker ended before readiness")
        time.sleep(.1)
    raise RuntimeError("Queue211 worker did not report ready")

class OnePeerPacketCounts:
    """Minimal AF_PACKET metadata counters: no payload, SNI, ports or IP logged."""
    def __init__(self,peer):
        self.peer=ipaddress.IPv4Address(peer).packed
        self.server=ipaddress.IPv4Address(RU).packed
        self.inbound_syn=0
        self.outbound_synack=0
        self.inbound_payload=0
        self.outbound_payload=0
        self.inbound_first4=0
        self.inbound_first_other=0
        self._seen_ports=set()

    def observe(self,frame:bytes):
        if len(frame)<54 or frame[12:14]!=b"\x08\x00":
            return
        ip=frame[14:]
        if ip[0] >> 4 != 4 or ip[9]!=6:
            return
        ihl=(ip[0]&15)*4
        if ihl<20 or len(ip)<ihl+20:
            return
        iplen=struct.unpack_from("!H",ip,2)[0]
        if iplen<ihl+20 or iplen>len(ip):
            return
        tcp=ip[ihl:iplen]
        header=(tcp[12]>>4)*4
        if header<20 or len(tcp)<header:
            return
        sport,dport=struct.unpack_from("!HH",tcp)
        flags=tcp[13]
        inbound=ip[12:16]==self.peer and ip[16:20]==self.server and dport==443
        outbound=ip[12:16]==self.server and ip[16:20]==self.peer and sport==443
        if inbound and (flags&0x12)==0x02:
            self.inbound_syn+=1
        if outbound and (flags&0x12)==0x12:
            self.outbound_synack+=1
        if outbound and len(tcp)>header:
            self.outbound_payload+=1
        if inbound and len(tcp)>header:
            self.inbound_payload+=1
            # Ephemeral source ports are used only to dedupe first segments,
            # never printed, persisted, or sent to another system.
            if sport not in self._seen_ports and len(self._seen_ports)<150:
                self._seen_ports.add(sport)
                if len(tcp)-header==4:
                    self.inbound_first4+=1
                else:
                    self.inbound_first_other+=1

    def output(self):
        for name,value in (
            ("phone_ingress_syn",self.inbound_syn),
            ("phone_egress_synack",self.outbound_synack),
            ("phone_inbound_data_packets",self.inbound_payload),
            ("phone_server_data_packets",self.outbound_payload),
            ("phone_first_data_4bytes",self.inbound_first4),
            ("phone_first_data_other_size",self.inbound_first_other),
        ):
            print("ig443_"+name+"="+str(value),flush=True)

def stage_watchdog(peer,runid):
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    if ROOT.is_symlink():
        raise RuntimeError("Unsafe runtime directory")
    snapshot=ROOT/("rollback-"+runid+".py")
    if snapshot.exists() or snapshot.is_symlink():
        raise RuntimeError("Rollback script already exists")
    # The rollback script is a complete standalone copy and uses only stdlib.
    with snapshot.open("x") as dst:
        dst.write(Path(__file__).read_text())
    snapshot.chmod(0o700)
    unit="mneby-ig443-"+runid
    run(["systemd-run","--quiet","--collect","--unit",unit,
         f"--on-active={WATCHDOG_TIME}s",
         "/usr/bin/python3",str(snapshot),"rollback",peer,runid])
    if run(["systemctl","is-active","--quiet",unit+".timer"],check=False).returncode:
        raise RuntimeError("Independent systemd rollback timer is not active")
    print("ig443_independent_rollback_armed=true",flush=True)

def canary(peer,runid):
    tag=tag_for(runid)
    if os.geteuid()!=0:
        raise RuntimeError("Root required")
    LOCK.parent.mkdir(parents=True,exist_ok=True)
    with LOCK.open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        preflight(peer,tag)
        ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
        if ROOT.is_symlink(): raise RuntimeError("Unsafe runtime directory")
        marker=ROOT/("ready-"+runid)
        if marker.exists() or marker.is_symlink():
            raise RuntimeError("Prior queue ready file exists")
        script=Path(__file__).resolve().parent/"mnebydns_ig_sni_443_fragment_worker.py"
        if not script.is_file():
            raise RuntimeError("Exact-peer queue worker not staged")
        worker=subprocess.Popen([sys.executable,str(script),"--client",peer,
                                 "--ready-file",str(marker)],
                                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            queue_ready(worker,marker)
            # Arm independent cleanup before either production hook is touched.
            stage_watchdog(peer,runid)
            try:
                run(["nft","-f","-"],stdin=nft_rule(peer,tag))
                if len(own_handles(chain(),tag))!=1:
                    raise RuntimeError("Tagged SYNACK bypass not installed")
                run(["iptables","-w","-t","mangle","-I","OUTPUT","1",
                     *iptables_rule(peer,tag)])
                if not iptables_present(peer,tag):
                    raise RuntimeError("Queue211 packet rule missing")
                print("ig443_single_ipv4_peer_443_canary=ACTIVE",flush=True)
                print("ig443_window_bytes=4",flush=True)
                print("ig443_duration_seconds="+str(TEST_TIME),flush=True)
                counts=OnePeerPacketCounts(peer)
                # AF_PACKET observes one exact peer/port on ens3. Unlike
                # PCAPdroid this is actual server-side wire metadata.
                with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)) as sniffer:
                    sniffer.bind(("ens3",0))
                    sniffer.settimeout(.3)
                    deadline=time.monotonic()+TEST_TIME
                    while time.monotonic()<deadline:
                        if worker.poll() is not None:
                            raise RuntimeError("Queue211 handler unexpectedly exited")
                        try: counts.observe(sniffer.recv(8192))
                        except socket.timeout: pass
                counts.output()
                snap=chain()
                own=own_handles(snap,tag)
                print("ig443_bypass_rule_present_before_cleanup="+str(len(own)==1).lower(),flush=True)
            finally:
                cleanup(peer,tag)
                if run(["systemctl","is-active","--quiet","telegram-nfqws.service"],
                       check=False).returncode:
                    raise RuntimeError("Telegram worker not active after canary")
                print("ig443_telegram_worker_preserved=true",flush=True)
        finally:
            worker.terminate()
            try: worker.wait(timeout=4)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait(timeout=3)
            if marker.exists(): marker.unlink()

def main():
    if len(sys.argv)!=4 or sys.argv[1] not in ("run","rollback"):
        raise SystemExit("Usage: python3 canary.py run|rollback PEER_PUBLIC_IPV4 RUN_ID")
    mode,peer_s,runid=sys.argv[1:]
    peer=validate(peer_s,runid)
    if mode=="rollback":
        if os.geteuid()!=0: raise RuntimeError("Root required")
        cleanup(peer,tag_for(runid))
    else:
        if os.environ.get("MNEBYDNS_IG_SNI_CANARY")!="YES":
            raise RuntimeError("Explicit MNEBYDNS_IG_SNI_CANARY=YES is required")
        canary(peer,runid)

if __name__=="__main__":
    main()
