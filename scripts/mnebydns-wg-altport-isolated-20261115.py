#!/usr/bin/env python3
"""Isolated short-lived WireGuard alternative-port A/B, never edits tg-relay."""
import concurrent.futures
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
RUN=os.environ.get("GITHUB_RUN_ID","")
if not RUN.isdecimal() or len(RUN)<6:
    raise SystemExit("Invalid GitHub run ID")
IFACE="wgt"+RUN[-6:]
TRUST=ROOT/"ops/mnebydns-owner-ssh-known_hosts"
HOST={"RU":"188.120.254.223","DE":"89.125.90.101"}
PASSWORD={"RU":os.environ.get("RU_PASS"),"DE":os.environ.get("DE_PASS")}
PORT={"RU":"56782","DE":"56781"}
WAN={"RU":"ens3","DE":"eth0"}
ADDR={"RU":"10.66.78.2","DE":"10.66.78.1"}
OTHER={"RU":"DE","DE":"RU"}

def ssh(role,body,args=(),timeout=50):
    env=os.environ.copy()
    env["SSHPASS"]=PASSWORD[role] or ""
    if not env["SSHPASS"]:
        raise RuntimeError("Missing SSH secret for "+role)
    cmd=["sshpass","-e","ssh","-T","-o","ConnectTimeout=12",
         "-o","StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
         "-o","UserKnownHostsFile="+str(TRUST),
         "-o","GlobalKnownHostsFile=/dev/null","-o","UpdateHostKeys=no",
         "-o","LogLevel=ERROR","root@"+HOST[role],"bash","-s","--",*args]
    p=subprocess.run(cmd,input=body,capture_output=True,text=True,env=env,timeout=timeout)
    if p.returncode:
        raise RuntimeError(role+" SSH "+str(p.returncode)+" "+p.stderr[-400:]+p.stdout[-400:])
    return p.stdout

STAGE=r"""
set -Eeuo pipefail
role="$1"; iface="$2"; port="$3"; other="$4"; wan="$5"; ip4="$6"
[[ "$iface" =~ ^wgt[0-9]{6}$ ]]
[[ "$port" =~ ^[0-9]{5}$ ]]
[[ "$wan" == ens3 || "$wan" == eth0 ]]
[[ "$role" == RU || "$role" == DE ]]
[[ "$other" =~ ^[0-9.]+$ ]]
[[ "$ip4" =~ ^10[.]66[.]78[.][12]$ ]]
test "$(id -u)" -eq 0
systemctl is-active --quiet wg-quick@tg-relay.service
command -v wg >/dev/null
command -v iptables >/dev/null
command -v systemd-run >/dev/null
! ip link show "$iface" >/dev/null 2>&1
! ip -4 route show | grep -Fq "10.66.78.0/30"
root="/run/mnebywg-probe-$iface"
test ! -e "$root"
install -d -m 700 "$root"
cat > "$root/cleanup.sh" <<CLEANUP
#!/bin/bash
set +e
ip link del "$iface" 2>/dev/null
if test -e "$root/fw_added"; then
  iptables -D INPUT -i "$wan" -s "$other" -p udp --dport "$port" -j ACCEPT 2>/dev/null
fi
rm -rf -- "$root"
CLEANUP
chmod 700 "$root/cleanup.sh"
systemd-run --quiet --unit="mnebywg-$iface-revert" --on-active=420s --collect /bin/bash "$root/cleanup.sh"
iptables -C INPUT -i "$wan" -s "$other" -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1 && exit 31
iptables -I INPUT 1 -i "$wan" -s "$other" -p udp --dport "$port" -j ACCEPT
touch "$root/fw_added"
umask 077
wg genkey > "$root/private"
wg pubkey < "$root/private" > "$root/public"
ip link add dev "$iface" type wireguard
wg set "$iface" private-key "$root/private" listen-port "$port"
ip addr add "$ip4/30" dev "$iface"
ip link set dev "$iface" mtu 1360 up
echo "STAGE_PUBLIC_KEY=$(cat "$root/public")"
"""
PEER=r"""
set -Eeuo pipefail
iface="$1"; key="$2"; addr="$3"; port="$4"; target="$5"
[[ "$iface" =~ ^wgt[0-9]{6}$ ]]
[[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]]
[[ "$addr" =~ ^10[.]66[.]78[.][12]$ ]]
[[ "$target" =~ ^[0-9.]+$ ]]
test -s "/run/mnebywg-probe-$iface/private"
wg set "$iface" peer "$key" allowed-ips "$addr/32" endpoint "$target:$port" persistent-keepalive 2
echo "ALT_PEER_CONFIGURED=YES"
"""
PROBE=r"""
set -Eeuo pipefail
dest="$1"; size="$2"; count="$3"; iface="$4"
[[ "$dest" =~ ^10[.]66[.]7[78][.][12]$ ]]
[[ "$size" == 32 || "$size" == 1200 ]]
[[ "$count" == 100 ]]
[[ "$iface" =~ ^wgt[0-9]{6}$ ]]
ip link show "$iface" >/dev/null
ip link show tg-relay >/dev/null
ping -n -q -M do -c "$count" -i .20 -s "$size" -W 1 "$dest" || true
"""
STATUS=r"""
set -Eeuo pipefail
iface="$1"
[[ "$iface" =~ ^wgt[0-9]{6}$ ]]
wg show "$iface" latest-handshakes
wg show "$iface" transfer
ip -4 route get 10.66.78.1 || true
"""
CLEAN=r"""
set +e
iface="$1"
[[ "$iface" =~ ^wgt[0-9]{6}$ ]] || exit 4
systemctl stop "mnebywg-$iface-revert.timer" >/dev/null 2>&1
bash "/run/mnebywg-probe-$iface/cleanup.sh" || true
test ! -e "/run/mnebywg-probe-$iface" && ! ip link show "$iface" >/dev/null 2>&1
"""
def pubkey(text):
    m=re.search(r"^STAGE_PUBLIC_KEY=([A-Za-z0-9+/]{43}=)$",text,re.M)
    if not m:raise RuntimeError("Isolated WG interface staging not acknowledged")
    return m.group(1)
def loss(raw):
    m=re.search(r"(\d+) packets transmitted, (\d+) received, ([0-9.]+)% packet loss",raw)
    if not m:raise RuntimeError("Ping result not parseable")
    return {"sent":int(m.group(1)),"received":int(m.group(2)),"lost_pct":float(m.group(3))}
def test(role,version,size):
    ip=ADDR[OTHER[role]] if version=="alternate" else {"RU":"10.66.77.1","DE":"10.66.77.2"}[role]
    raw=ssh(role,PROBE,[ip,str(size),"100",IFACE],timeout=57)
    return role,version,size,loss(raw)

def main():
    if not TRUST.is_file() or not all(PASSWORD.values()):raise RuntimeError("Pinned trust or SSH secrets missing")
    staged=set()
    try:
        keys={}
        for role in ("DE","RU"):
            try:
                out=ssh(role,STAGE,[role,IFACE,PORT[role],HOST[OTHER[role]],WAN[role],ADDR[role]],timeout=38)
            except Exception:
                staged.add(role) # cleanup after partial staging as well
                raise
            staged.add(role)
            keys[role]=pubkey(out)
            print("WG_AB_"+role+"_ISOLATED_STAGED=yes",flush=True)
        for role in ("DE","RU"):
            other=OTHER[role]
            out=ssh(role,PEER,[IFACE,keys[other],ADDR[other],PORT[other],HOST[other]],timeout=25)
            assert "ALT_PEER_CONFIGURED=YES" in out
        time.sleep(7)
        for role in ("DE","RU"):
            print("WG_AB_"+role+"_HANDSHAKE="+json.dumps(ssh(role,STATUS,[IFACE]).splitlines()[:3]),flush=True)
        results=[]
        for size in (32,1200):
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                futures=[pool.submit(test,role,variant,size)
                         for role in ("RU","DE") for variant in ("existing","alternate")]
                for f in futures:
                    role,variant,sz,result=f.result()
                    results.append({"role":role,"variant":variant,"bytes":sz,**result})
            print("WG_AB_SIZE_"+str(size)+"="+json.dumps(results[-4:],sort_keys=True),flush=True)
        print("WG_AB_ISOLATED_TEST_COMPLETED=true",flush=True)
        print("WG_AB_PRODUCTION_INTERFACE_UNCHANGED=true",flush=True)
    finally:
        for role in sorted(staged):
            try:
                ssh(role,CLEAN,[IFACE],timeout=30)
                print("WG_AB_"+role+"_CLEANED=yes",flush=True)
            except Exception as ex:
                print("WG_AB_"+role+"_CLEANUP_ATTEMPT_FAILED="+type(ex).__name__,flush=True)
                print("WG_AB_"+role+"_INDEPENDENT_420S_REVERT_ARMED=true",flush=True)

if __name__=="__main__":
    main()
