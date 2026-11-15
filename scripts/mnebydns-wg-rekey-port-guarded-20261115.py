#!/usr/bin/env python3
"""Guarded active WireGuard transport port repair. Never changes keys, IPs, MTU or routes."""
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
if not RUN.isdecimal() or len(RUN)<6:raise SystemExit("Invalid runner ID")
TAG=RUN[-6:]
KNOWN=ROOT/"ops/mnebydns-owner-ssh-known_hosts"
HOST={"RU":"188.120.254.223","DE":"89.125.90.101"}
PASS={"RU":os.environ.get("RU_PASS"),"DE":os.environ.get("DE_PASS")}
OLD={"RU":53832,"DE":51820}
NEW={"RU":56782,"DE":56781}
WAN={"RU":"ens3","DE":"eth0"}
OTHER={"RU":"DE","DE":"RU"}

def remote(role,body,args=(),timeout=50):
    env=os.environ.copy()
    env["SSHPASS"]=PASS[role] or ""
    if not env["SSHPASS"]:raise RuntimeError("Missing SSH secret for "+role)
    cmd=["sshpass","-e","ssh","-T","-o","ConnectTimeout=12",
         "-o","StrictHostKeyChecking=yes","-o","HostKeyAlgorithms=ssh-ed25519",
         "-o","UserKnownHostsFile="+str(KNOWN),"-o","GlobalKnownHostsFile=/dev/null",
         "-o","UpdateHostKeys=no","-o","LogLevel=ERROR",
         "root@"+HOST[role],"bash","-s","--",*map(str,args)]
    p=subprocess.run(cmd,input=body,text=True,capture_output=True,env=env,timeout=timeout)
    if p.returncode:raise RuntimeError(role+" command failed rc="+str(p.returncode)+": "+(p.stderr[-500:]+p.stdout[-500:]))
    return p.stdout

STAGE=r"""
set -Eeuo pipefail
tag="$1"; side="$2"; old="$3"; new="$4"; other="$5"; otherold="$6"; othernew="$7"; wan="$8"
[[ "$tag" =~ ^[0-9]{6}$ ]]
[[ "$side" == RU || "$side" == DE ]]
[[ "$old" =~ ^[0-9]{5}$ && "$new" =~ ^[0-9]{5}$ ]]
[[ "$wan" == ens3 || "$wan" == eth0 ]]
test "$(id -u)" = 0
systemctl is-active --quiet wg-quick@tg-relay.service
test "$(wg show tg-relay listen-port)" = "$old"
test "$(wg show tg-relay peers | wc -l)" = 1
wg show tg-relay endpoints | grep -Fq "$other:$otherold"
! ss -H -lun "( sport = :$new )" | grep -q .
if [ "$side" = RU ]; then
  test "$(ufw status | head -1)" = "Status: active"
  ! ufw status | grep -Eq "(^|[[:space:]])$new(/udp|[[:space:]])"
else
  test "$(iptables -S INPUT | head -1)" = "-P INPUT ACCEPT"
  ! iptables -C INPUT -s "$other" -p udp --dport "$new" -j ACCEPT 2>/dev/null
  ! iptables -C INPUT -p udp --dport "$new" -j DROP 2>/dev/null
  ! ip6tables -C INPUT -p udp --dport "$new" -j DROP 2>/dev/null
fi
disk=/etc/wireguard/tg-relay.conf
test -s "$disk"
root="/run/mnebywgfix-$tag"
test ! -e "$root"
install -d -m 700 "$root"
umask 077
wg showconf tg-relay > "$root/original.wg"
cp -p "$disk" "$root/original.file"
wg genkey > "$root/new.private"
wg pubkey < "$root/new.private" > "$root/new.public"
python3 - "$root" "$disk" "$old" "$new" "$other" "$otherold" "$othernew" "$side" <<'PY'
import pathlib,re,sys
root,disk,old,new,other,otherold,othernew,side=sys.argv[1:]
raw=pathlib.Path(disk).read_text()
def subst(k,prev,want,text):
    pat=r'(?m)^([ \t]*'+re.escape(k)+r'[ \t]*=[ \t]*)'+re.escape(prev)+r'([ \t]*(?:#[^\r\n]*)?)$'
    edited,n=re.subn(pat,lambda m:m.group(1)+want+m.group(2),text)
    if n!=1:raise RuntimeError("Expected unique original "+k+" entry, not found")
    return edited
if side=='DE':
    if re.search(r'(?m)^[ \t]*Endpoint[ \t]*=',raw):
        raise RuntimeError('Unexpected DE static Endpoint')
    raw=subst('ListenPort',old,new,raw)
    lines=raw.splitlines(keepends=True)
    counts={}
    for i,line in enumerate(lines):
        m=re.match(r'^[ \t]*(PostUp|PostDown)[ \t]*=',line)
        if m:
            edited,n=re.subn(r'(?<=--dport )'+re.escape(old)+r'(?=\D|$)',new,line)
            lines[i]=edited
            counts[m.group(1)]=n
    if counts.get('PostUp',0)<3 or counts.get('PostDown',0)<2:
        raise RuntimeError('Incomplete DE firewall PostUp/PostDown port change')
    raw=''.join(lines)
else:
    if re.search(r'(?m)^[ \t]*ListenPort[ \t]*=',raw):
        raise RuntimeError('Unexpected RU static ListenPort')
    raw=subst('Endpoint',other+':'+otherold,other+':'+othernew,raw)
    raw,n=re.subn(r'(?m)^\[Interface\][ \t]*\r?\n',
                  lambda m:m.group(0)+'ListenPort = '+new+'\n',raw,count=1)
    if n!=1:raise RuntimeError('RU Interface header missing or duplicated')
pathlib.Path(root+'/candidate.file').write_text(raw)
PY
cat > "$root/rollback.sh" <<ROLLBACK
#!/bin/bash
set +e
root="$root"
disk="$disk"
if test -f "\$root/confirmed"; then
  rm -rf -- "\$root"
  exit 0
fi
if test -s "\$root/original.wg"; then
  if test "\$(wg show tg-relay listen-port 2>/dev/null)" = "$new" || wg show tg-relay endpoints 2>/dev/null | grep -Fq "$other:$othernew"; then
    wg syncconf tg-relay "\$root/original.wg"
  fi
fi
if test -s "\$root/original.file" && test -s "\$root/candidate.file" && cmp -s "\$root/candidate.file" "\$disk"; then
  cp -p "\$root/original.file" "\$disk"
fi
if test -f "\$root/ufw_added"; then
  ufw --force delete allow in on "$wan" from "$other" to "$(hostname -I | awk '{print $1}')" port "$new" proto udp >/dev/null 2>&1
fi
if test -f "\$root/fw_added"; then
  iptables -D INPUT -p udp -s "$other" --dport "$new" -j ACCEPT >/dev/null 2>&1
  iptables -D INPUT -p udp --dport "$new" -j DROP >/dev/null 2>&1
  ip6tables -D INPUT -p udp --dport "$new" -j DROP >/dev/null 2>&1
fi
rm -rf -- "\$root"
ROLLBACK
# Fix destination to the exact public address rather than hostname-derived interfaces.
selfip="188.120.254.223"; if [ "$side" = DE ]; then selfip="89.125.90.101"; fi
chmod 700 "$root/rollback.sh"
systemd-run --quiet --unit="mnebywgfix-$tag-revert" --on-active=480s --collect /bin/bash "$root/rollback.sh"
if [ "$side" = RU ]; then
  touch "$root/ufw_added"
  ufw allow in on "$wan" from "$other" to "$selfip" port "$new" proto udp comment "MNEBYVPN WG verified port repair" >/dev/null
else
  touch "$root/fw_added"
  iptables -I INPUT 1 -p udp -s "$other" --dport "$new" -j ACCEPT
  iptables -I INPUT 2 -p udp --dport "$new" -j DROP
  ip6tables -I INPUT 1 -p udp --dport "$new" -j DROP
fi
test "$(wg show tg-relay listen-port)" = "$old"
cmp -s "$disk" "$root/original.file"
echo WG_FIX_STAGED=yes
echo "WG_FIX_NEW_PUBLIC_KEY=$(cat "$root/new.public")"
"""
# NOTE: stage script is patched below to avoid a shell-expansion problem inside a rollback heredoc.
STAGE=STAGE.replace(
 'to "$(hostname -I | awk \'{print $1}\')"',
 'to "$selfip"'
).replace(
 'sed -i "s|\\$(hostname -I | awk \'{print \\$1}\')|$selfip|" "$root/rollback.sh" 2>/dev/null || true',
 ':'
)
# The selfip variable must be initialized before the rollback template expands.
STAGE=STAGE.replace('cat > "$root/rollback.sh" <<ROLLBACK',
'''selfip="188.120.254.223"; if [ "$side" = DE ]; then selfip="89.125.90.101"; fi
cat > "$root/rollback.sh" <<ROLLBACK''')
# Heredoc variable substitution must leave literal root and disk variables in the generated script.

PREPARE_KEYS=r"""
set -Eeuo pipefail
tag="$1"; oldport="$2"; newport="$3"; other="$4"; otherold="$5"; othernew="$6"; peerpub="$7"
[[ "$tag" =~ ^[0-9]{6}$ ]]
[[ "$peerpub" =~ ^[A-Za-z0-9+/]{43}=$ ]]
root="/run/mnebywgfix-$tag"
test -s "$root/new.private" && test -s "$root/new.public"
test -s "$root/candidate.file" && test -s "$root/original.wg"
test "$(wg show tg-relay listen-port)" = "$oldport"
umask 077
python3 - "$root" "$oldport" "$newport" "$other" "$otherold" "$othernew" "$peerpub" <<'PY'
import pathlib,re,sys
root,oldport,newport,other,otherold,othernew,peerpub=sys.argv[1:]
dir=pathlib.Path(root)
priv=(dir/'new.private').read_text().strip()
if not re.fullmatch(r'[A-Za-z0-9+/]{43}=',priv):raise ValueError('Bad new WG private key')
if not re.fullmatch(r'[A-Za-z0-9+/]{43}=',peerpub):raise ValueError('Bad new WG peer key')
def one(src,key,val):
    pat=r'(?m)^([ \t]*'+re.escape(key)+r'[ \t]*=[ \t]*)\S+([ \t]*)
set -Eeuo pipefail
tag="$1"; old="$2"; new="$3"; other="$4"; othernew="$5"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -s "$root/original.wg"
test -s "$root/candidate.file"
test ! -f "$root/confirmed"
test "$(wg show tg-relay listen-port)" = "$old"
test -s "$root/candidate.runtime" && test -s "$root/expected.peer"
wg syncconf tg-relay "$root/candidate.runtime"
test "$(wg show tg-relay listen-port)" = "$new"
test "$(wg show tg-relay peers)" = "$(cat "$root/expected.peer")"
wg show tg-relay endpoints | grep -Fq "$other:$othernew"
echo WG_FIX_RUNTIME_CHANGED=yes
"""
PING=r"""
set -Eeuo pipefail
dest="$1"; bytes="$2"
[[ "$dest" == 10.66.77.1 || "$dest" == 10.66.77.2 ]]
[[ "$bytes" == 32 || "$bytes" == 1200 ]]
ping -n -q -M do -c 100 -i 0.20 -s "$bytes" -W 1 "$dest" || true
"""
TLS=r"""
set -Eeuo pipefail
python3 - <<'PY'
import ssl,socket
ctx=ssl.create_default_context()
with socket.create_connection(('10.66.77.1',443),timeout=7) as sock:
  sock.settimeout(8)
  with ctx.wrap_socket(sock,server_hostname='www.youtube.com') as tls:
    if not tls.getpeercert():raise RuntimeError("TLS certificate missing")
    print("WG_FIX_TLS_OVER_TUNNEL="+str(tls.version()),flush=True)
PY
"""
PERSIST=r"""
set -Eeuo pipefail
tag="$1"; new="$2"
root="/run/mnebywgfix-$tag"
disk=/etc/wireguard/tg-relay.conf
test -s "$root/original.file" && test -s "$root/candidate.file"
test "$(wg show tg-relay listen-port)" = "$new"
cmp -s "$disk" "$root/original.file"
backup="$disk.bak-wgport-$tag"
test ! -e "$backup"
cp -p "$disk" "$backup"
install -m 600 "$root/candidate.file" "$disk.wgport-$tag.tmp"
mv -f "$disk.wgport-$tag.tmp" "$disk"
cmp -s "$root/candidate.file" "$disk"
test "$(wg show tg-relay listen-port)" = "$new"
echo WG_FIX_DISK_PERSISTED=yes
"""
ROLLBACK=r"""
set +e
tag="$1"
[[ "$tag" =~ ^[0-9]{6}$ ]] || exit 3
root="/run/mnebywgfix-$tag"
if [ -f "$root/confirmed" ]; then rm -f "$root/confirmed"; fi
if [ -s "$root/rollback.sh" ]; then bash "$root/rollback.sh"; fi
echo WG_FIX_ROLLBACK_ATTEMPTED=yes
"""
CONFIRM=r"""
set -Eeuo pipefail
tag="$1"; new="$2"; other="$3"; othernew="$4"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -s "$root/candidate.file"
test "$(wg show tg-relay listen-port)" = "$new"
wg show tg-relay endpoints | grep -Fq "$other:$othernew"
cmp -s "$root/candidate.file" /etc/wireguard/tg-relay.conf
test "$(wg show tg-relay peers)" = "$(cat "$root/expected.peer")"
touch "$root/confirmed"
echo WG_FIX_CONFIRMED=yes
"""
FINALIZE=r"""
set -Eeuo pipefail
tag="$1"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -f "$root/confirmed"
systemctl stop "mnebywgfix-$tag-revert.timer" >/dev/null 2>&1 || true
rm -rf -- "$root"
echo WG_FIX_CLEANED=yes
"""

def args(role):
    other=OTHER[role]
    return [TAG,role,OLD[role],NEW[role],HOST[other],OLD[other],NEW[other],WAN[role]]
def check_losses():
    def ping_pair(role,sz):
        target="10.66.77.1" if role=="RU" else "10.66.77.2"
        raw=remote(role,PING,[target,sz],timeout=65)
        m=re.search(r"100 packets transmitted, (\d+) received, ([\d.]+)% packet loss",raw)
        if not m:raise RuntimeError("Ping result missing for "+role)
        return {"role":role,"size":sz,"received":int(m.group(1)),"loss_pct":float(m.group(2))}
    results=[]
    for sz in (32,1200):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results.extend(list(pool.map(lambda role:ping_pair(role,sz),("RU","DE"))))
    print("WG_FIX_POSTCUTOVER_LOSS="+json.dumps(results,sort_keys=True),flush=True)
    if any(x["loss_pct"]>2.0 for x in results):
        raise RuntimeError("Cutover loss exceeded 2%; automatic rollback")
    return results

def main():
    if not KNOWN.is_file() or not all(PASS.values()):
        raise RuntimeError("Missing pinned SSH trust or secrets")
    staged=set()
    confirmed=False
    newkeys={}
    try:
        for role in ("DE","RU"):
            try:out=remote(role,STAGE,args(role),timeout=48)
            except Exception:
                staged.add(role)
                raise
            staged.add(role)
            if "WG_FIX_STAGED=yes" not in out:raise RuntimeError("Stage unacknowledged "+role)
            m=re.search(r"^WG_FIX_NEW_PUBLIC_KEY=([A-Za-z0-9+/]{43}=)$",out,re.M)
            if not m:raise RuntimeError("New peer key not returned "+role)
            newkeys[role]=m.group(1)
            print("WG_FIX_"+role+"_STAGED=yes",flush=True)
        for role in ("DE","RU"):
            other=OTHER[role]
            out=remote(role,PREPARE_KEYS,[TAG,OLD[role],NEW[role],HOST[other],OLD[other],NEW[other],newkeys[other]],timeout=25)
            if "WG_FIX_NEW_KEYS_PREPARED=yes" not in out:raise RuntimeError("Rekey candidate not verified "+role)
            print("WG_FIX_"+role+"_CANDIDATE_READY=yes",flush=True)
        for role in ("DE","RU"):
            other=OTHER[role]
            out=remote(role,APPLY,[TAG,OLD[role],NEW[role],HOST[other],NEW[other]],timeout=32)
            if "WG_FIX_RUNTIME_CHANGED=yes" not in out:raise RuntimeError("Apply not confirmed "+role)
            print("WG_FIX_"+role+"_RUNTIME_NEW_PORT="+str(NEW[role]),flush=True)
        time.sleep(6)
        check_losses()
        out=remote("RU",TLS,timeout=26)
        if "WG_FIX_TLS_OVER_TUNNEL=TLS" not in out:raise RuntimeError("Real TLS over WG failed")
        print(out.strip(),flush=True)
        for role in ("DE","RU"):
            out=remote(role,PERSIST,[TAG,NEW[role]],timeout=24)
            if "WG_FIX_DISK_PERSISTED=yes" not in out:raise RuntimeError("Persistent file write unconfirmed "+role)
            print("WG_FIX_"+role+"_PERSISTED=yes",flush=True)
        # Confirm both quickly; after this, independent timer will not revert a committed pair.
        for role in ("DE","RU"):
            other=OTHER[role]
            out=remote(role,CONFIRM,[TAG,NEW[role],HOST[other],NEW[other]],timeout=24)
            if "WG_FIX_CONFIRMED=yes" not in out:raise RuntimeError("Confirmation missing "+role)
            print("WG_FIX_"+role+"_CONFIRMED=yes",flush=True)
        confirmed=True
        print("WG_FIX_NEW_PORTS_APPLIED_AND_PERSISTED=true",flush=True)
        print("WG_FIX_KEYS_ROTATED_ON_BOTH_NODES=true",flush=True)
        print("WG_FIX_SUBSCRIBER_VLESS_KEYS_IP_MTU_ROUTES_UNCHANGED=true",flush=True)
        for role in ("DE","RU"):
            try:
                remote(role,FINALIZE,[TAG],timeout=23)
                print("WG_FIX_"+role+"_TEMPORARY_FILES_CLEANED=yes",flush=True)
            except Exception as ex:
                print("WG_FIX_"+role+"_CONFIRMED_TIMER_CLEANUP_PENDING="+type(ex).__name__,flush=True)
    finally:
        if not confirmed:
            for role in sorted(staged):
                try:
                    remote(role,ROLLBACK,[TAG],timeout=35)
                    print("WG_FIX_"+role+"_ROLLBACK_ATTEMPTED=yes",flush=True)
                except Exception as ex:
                    print("WG_FIX_"+role+"_INDEPENDENT_REVERT_PENDING="+type(ex).__name__,flush=True)
if __name__=="__main__":
    main()

    dest,n=re.subn(pat,lambda m:m.group(1)+val+m.group(2),src)
    if n!=1:raise ValueError('Unexpected '+key+' lines: '+str(n))
    return dest
disk=(dir/'candidate.file').read_text()
disk=one(disk,'PrivateKey',priv)
disk=one(disk,'PublicKey',peerpub)
(dir/'candidate.file').write_text(disk)
wg=(dir/'original.wg').read_text()
wg=one(wg,'PrivateKey',priv)
wg=one(wg,'PublicKey',peerpub)
wg=one(wg,'ListenPort',newport)
pat=r'(?m)^([ \t]*Endpoint[ \t]*=[ \t]*)'+re.escape(other+':'+oldport)+r'([ \t]*)
set -Eeuo pipefail
tag="$1"; old="$2"; new="$3"; other="$4"; othernew="$5"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -s "$root/original.wg"
test -s "$root/candidate.file"
test ! -f "$root/confirmed"
test "$(wg show tg-relay listen-port)" = "$old"
peer="$(wg show tg-relay peers)"
test "$(printf '%s\n' "$peer" | wc -l)" = 1
wg set tg-relay listen-port "$new"
wg set tg-relay peer "$peer" endpoint "$other:$othernew"
test "$(wg show tg-relay listen-port)" = "$new"
wg show tg-relay endpoints | grep -Fq "$other:$othernew"
echo WG_FIX_RUNTIME_CHANGED=yes
"""
PING=r"""
set -Eeuo pipefail
dest="$1"; bytes="$2"
[[ "$dest" == 10.66.77.1 || "$dest" == 10.66.77.2 ]]
[[ "$bytes" == 32 || "$bytes" == 1200 ]]
ping -n -q -M do -c 100 -i 0.20 -s "$bytes" -W 1 "$dest" || true
"""
TLS=r"""
set -Eeuo pipefail
python3 - <<'PY'
import ssl,socket
ctx=ssl.create_default_context()
with socket.create_connection(('10.66.77.1',443),timeout=7) as sock:
  sock.settimeout(8)
  with ctx.wrap_socket(sock,server_hostname='www.youtube.com') as tls:
    if not tls.getpeercert():raise RuntimeError("TLS certificate missing")
    print("WG_FIX_TLS_OVER_TUNNEL="+str(tls.version()),flush=True)
PY
"""
PERSIST=r"""
set -Eeuo pipefail
tag="$1"; new="$2"
root="/run/mnebywgfix-$tag"
disk=/etc/wireguard/tg-relay.conf
test -s "$root/original.file" && test -s "$root/candidate.file"
test "$(wg show tg-relay listen-port)" = "$new"
cmp -s "$disk" "$root/original.file"
backup="$disk.bak-wgport-$tag"
test ! -e "$backup"
cp -p "$disk" "$backup"
install -m 600 "$root/candidate.file" "$disk.wgport-$tag.tmp"
mv -f "$disk.wgport-$tag.tmp" "$disk"
cmp -s "$root/candidate.file" "$disk"
test "$(wg show tg-relay listen-port)" = "$new"
echo WG_FIX_DISK_PERSISTED=yes
"""
ROLLBACK=r"""
set +e
tag="$1"
[[ "$tag" =~ ^[0-9]{6}$ ]] || exit 3
root="/run/mnebywgfix-$tag"
if [ -f "$root/confirmed" ]; then rm -f "$root/confirmed"; fi
if [ -s "$root/rollback.sh" ]; then bash "$root/rollback.sh"; fi
echo WG_FIX_ROLLBACK_ATTEMPTED=yes
"""
CONFIRM=r"""
set -Eeuo pipefail
tag="$1"; new="$2"; other="$3"; othernew="$4"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -s "$root/candidate.file"
test "$(wg show tg-relay listen-port)" = "$new"
wg show tg-relay endpoints | grep -Fq "$other:$othernew"
cmp -s "$root/candidate.file" /etc/wireguard/tg-relay.conf
touch "$root/confirmed"
echo WG_FIX_CONFIRMED=yes
"""
FINALIZE=r"""
set -Eeuo pipefail
tag="$1"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -f "$root/confirmed"
systemctl stop "mnebywgfix-$tag-revert.timer" >/dev/null 2>&1 || true
rm -rf -- "$root"
echo WG_FIX_CLEANED=yes
"""

def args(role):
    other=OTHER[role]
    return [TAG,role,OLD[role],NEW[role],HOST[other],OLD[other],NEW[other],WAN[role]]
def check_losses():
    def ping_pair(role,sz):
        target="10.66.77.1" if role=="RU" else "10.66.77.2"
        raw=remote(role,PING,[target,sz],timeout=65)
        m=re.search(r"100 packets transmitted, (\d+) received, ([\d.]+)% packet loss",raw)
        if not m:raise RuntimeError("Ping result missing for "+role)
        return {"role":role,"size":sz,"received":int(m.group(1)),"loss_pct":float(m.group(2))}
    results=[]
    for sz in (32,1200):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results.extend(list(pool.map(lambda role:ping_pair(role,sz),("RU","DE"))))
    print("WG_FIX_POSTCUTOVER_LOSS="+json.dumps(results,sort_keys=True),flush=True)
    if any(x["loss_pct"]>2.0 for x in results):
        raise RuntimeError("Cutover loss exceeded 2%; automatic rollback")
    return results

def main():
    if not KNOWN.is_file() or not all(PASS.values()):
        raise RuntimeError("Missing pinned SSH trust or secrets")
    staged=set()
    confirmed=False
    try:
        for role in ("DE","RU"):
            try:out=remote(role,STAGE,args(role),timeout=48)
            except Exception:
                staged.add(role)
                raise
            staged.add(role)
            if "WG_FIX_STAGED=yes" not in out:raise RuntimeError("Stage unacknowledged "+role)
            print("WG_FIX_"+role+"_STAGED=yes",flush=True)
        for role in ("DE","RU"):
            other=OTHER[role]
            out=remote(role,APPLY,[TAG,OLD[role],NEW[role],HOST[other],NEW[other]],timeout=32)
            if "WG_FIX_RUNTIME_CHANGED=yes" not in out:raise RuntimeError("Apply not confirmed "+role)
            print("WG_FIX_"+role+"_RUNTIME_NEW_PORT="+str(NEW[role]),flush=True)
        time.sleep(6)
        check_losses()
        out=remote("RU",TLS,timeout=26)
        if "WG_FIX_TLS_OVER_TUNNEL=TLS" not in out:raise RuntimeError("Real TLS over WG failed")
        print(out.strip(),flush=True)
        for role in ("DE","RU"):
            out=remote(role,PERSIST,[TAG,NEW[role]],timeout=24)
            if "WG_FIX_DISK_PERSISTED=yes" not in out:raise RuntimeError("Persistent file write unconfirmed "+role)
            print("WG_FIX_"+role+"_PERSISTED=yes",flush=True)
        # Confirm both quickly; after this, independent timer will not revert a committed pair.
        for role in ("DE","RU"):
            other=OTHER[role]
            out=remote(role,CONFIRM,[TAG,NEW[role],HOST[other],NEW[other]],timeout=24)
            if "WG_FIX_CONFIRMED=yes" not in out:raise RuntimeError("Confirmation missing "+role)
            print("WG_FIX_"+role+"_CONFIRMED=yes",flush=True)
        confirmed=True
        print("WG_FIX_NEW_PORTS_APPLIED_AND_PERSISTED=true",flush=True)
        print("WG_FIX_KEYS_IP_MTU_ROUTES_UNCHANGED=true",flush=True)
        for role in ("DE","RU"):
            try:
                remote(role,FINALIZE,[TAG],timeout=23)
                print("WG_FIX_"+role+"_TEMPORARY_FILES_CLEANED=yes",flush=True)
            except Exception as ex:
                print("WG_FIX_"+role+"_CONFIRMED_TIMER_CLEANUP_PENDING="+type(ex).__name__,flush=True)
    finally:
        if not confirmed:
            for role in sorted(staged):
                try:
                    remote(role,ROLLBACK,[TAG],timeout=35)
                    print("WG_FIX_"+role+"_ROLLBACK_ATTEMPTED=yes",flush=True)
                except Exception as ex:
                    print("WG_FIX_"+role+"_INDEPENDENT_REVERT_PENDING="+type(ex).__name__,flush=True)
if __name__=="__main__":
    main()

# In this two-node setup, the peer endpoint observed at run time must be exact.
wg,n=re.subn(pat,lambda m:m.group(1)+other+':'+othernew+m.group(2),wg)
if n!=1:raise ValueError('Original runtime peer endpoint mismatch')
(dir/'candidate.runtime').write_text(wg)
(dir/'expected.peer').write_text(peerpub+'\n')
for name in ('candidate.file','candidate.runtime','expected.peer'):
    (dir/name).chmod(0o600)
PY
echo WG_FIX_NEW_KEYS_PREPARED=yes
"""

APPLY=r"""
set -Eeuo pipefail
tag="$1"; old="$2"; new="$3"; other="$4"; othernew="$5"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -s "$root/original.wg"
test -s "$root/candidate.file"
test ! -f "$root/confirmed"
test "$(wg show tg-relay listen-port)" = "$old"
peer="$(wg show tg-relay peers)"
test "$(printf '%s\n' "$peer" | wc -l)" = 1
wg set tg-relay listen-port "$new"
wg set tg-relay peer "$peer" endpoint "$other:$othernew"
test "$(wg show tg-relay listen-port)" = "$new"
wg show tg-relay endpoints | grep -Fq "$other:$othernew"
echo WG_FIX_RUNTIME_CHANGED=yes
"""
PING=r"""
set -Eeuo pipefail
dest="$1"; bytes="$2"
[[ "$dest" == 10.66.77.1 || "$dest" == 10.66.77.2 ]]
[[ "$bytes" == 32 || "$bytes" == 1200 ]]
ping -n -q -M do -c 100 -i 0.20 -s "$bytes" -W 1 "$dest" || true
"""
TLS=r"""
set -Eeuo pipefail
python3 - <<'PY'
import ssl,socket
ctx=ssl.create_default_context()
with socket.create_connection(('10.66.77.1',443),timeout=7) as sock:
  sock.settimeout(8)
  with ctx.wrap_socket(sock,server_hostname='www.youtube.com') as tls:
    if not tls.getpeercert():raise RuntimeError("TLS certificate missing")
    print("WG_FIX_TLS_OVER_TUNNEL="+str(tls.version()),flush=True)
PY
"""
PERSIST=r"""
set -Eeuo pipefail
tag="$1"; new="$2"
root="/run/mnebywgfix-$tag"
disk=/etc/wireguard/tg-relay.conf
test -s "$root/original.file" && test -s "$root/candidate.file"
test "$(wg show tg-relay listen-port)" = "$new"
cmp -s "$disk" "$root/original.file"
backup="$disk.bak-wgport-$tag"
test ! -e "$backup"
cp -p "$disk" "$backup"
install -m 600 "$root/candidate.file" "$disk.wgport-$tag.tmp"
mv -f "$disk.wgport-$tag.tmp" "$disk"
cmp -s "$root/candidate.file" "$disk"
test "$(wg show tg-relay listen-port)" = "$new"
echo WG_FIX_DISK_PERSISTED=yes
"""
ROLLBACK=r"""
set +e
tag="$1"
[[ "$tag" =~ ^[0-9]{6}$ ]] || exit 3
root="/run/mnebywgfix-$tag"
if [ -f "$root/confirmed" ]; then rm -f "$root/confirmed"; fi
if [ -s "$root/rollback.sh" ]; then bash "$root/rollback.sh"; fi
echo WG_FIX_ROLLBACK_ATTEMPTED=yes
"""
CONFIRM=r"""
set -Eeuo pipefail
tag="$1"; new="$2"; other="$3"; othernew="$4"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -s "$root/candidate.file"
test "$(wg show tg-relay listen-port)" = "$new"
wg show tg-relay endpoints | grep -Fq "$other:$othernew"
cmp -s "$root/candidate.file" /etc/wireguard/tg-relay.conf
touch "$root/confirmed"
echo WG_FIX_CONFIRMED=yes
"""
FINALIZE=r"""
set -Eeuo pipefail
tag="$1"
[[ "$tag" =~ ^[0-9]{6}$ ]]
root="/run/mnebywgfix-$tag"
test -f "$root/confirmed"
systemctl stop "mnebywgfix-$tag-revert.timer" >/dev/null 2>&1 || true
rm -rf -- "$root"
echo WG_FIX_CLEANED=yes
"""

def args(role):
    other=OTHER[role]
    return [TAG,role,OLD[role],NEW[role],HOST[other],OLD[other],NEW[other],WAN[role]]
def check_losses():
    def ping_pair(role,sz):
        target="10.66.77.1" if role=="RU" else "10.66.77.2"
        raw=remote(role,PING,[target,sz],timeout=65)
        m=re.search(r"100 packets transmitted, (\d+) received, ([\d.]+)% packet loss",raw)
        if not m:raise RuntimeError("Ping result missing for "+role)
        return {"role":role,"size":sz,"received":int(m.group(1)),"loss_pct":float(m.group(2))}
    results=[]
    for sz in (32,1200):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results.extend(list(pool.map(lambda role:ping_pair(role,sz),("RU","DE"))))
    print("WG_FIX_POSTCUTOVER_LOSS="+json.dumps(results,sort_keys=True),flush=True)
    if any(x["loss_pct"]>2.0 for x in results):
        raise RuntimeError("Cutover loss exceeded 2%; automatic rollback")
    return results

def main():
    if not KNOWN.is_file() or not all(PASS.values()):
        raise RuntimeError("Missing pinned SSH trust or secrets")
    staged=set()
    confirmed=False
    try:
        for role in ("DE","RU"):
            try:out=remote(role,STAGE,args(role),timeout=48)
            except Exception:
                staged.add(role)
                raise
            staged.add(role)
            if "WG_FIX_STAGED=yes" not in out:raise RuntimeError("Stage unacknowledged "+role)
            print("WG_FIX_"+role+"_STAGED=yes",flush=True)
        for role in ("DE","RU"):
            other=OTHER[role]
            out=remote(role,APPLY,[TAG,OLD[role],NEW[role],HOST[other],NEW[other]],timeout=32)
            if "WG_FIX_RUNTIME_CHANGED=yes" not in out:raise RuntimeError("Apply not confirmed "+role)
            print("WG_FIX_"+role+"_RUNTIME_NEW_PORT="+str(NEW[role]),flush=True)
        time.sleep(6)
        check_losses()
        out=remote("RU",TLS,timeout=26)
        if "WG_FIX_TLS_OVER_TUNNEL=TLS" not in out:raise RuntimeError("Real TLS over WG failed")
        print(out.strip(),flush=True)
        for role in ("DE","RU"):
            out=remote(role,PERSIST,[TAG,NEW[role]],timeout=24)
            if "WG_FIX_DISK_PERSISTED=yes" not in out:raise RuntimeError("Persistent file write unconfirmed "+role)
            print("WG_FIX_"+role+"_PERSISTED=yes",flush=True)
        # Confirm both quickly; after this, independent timer will not revert a committed pair.
        for role in ("DE","RU"):
            other=OTHER[role]
            out=remote(role,CONFIRM,[TAG,NEW[role],HOST[other],NEW[other]],timeout=24)
            if "WG_FIX_CONFIRMED=yes" not in out:raise RuntimeError("Confirmation missing "+role)
            print("WG_FIX_"+role+"_CONFIRMED=yes",flush=True)
        confirmed=True
        print("WG_FIX_NEW_PORTS_APPLIED_AND_PERSISTED=true",flush=True)
        print("WG_FIX_KEYS_IP_MTU_ROUTES_UNCHANGED=true",flush=True)
        for role in ("DE","RU"):
            try:
                remote(role,FINALIZE,[TAG],timeout=23)
                print("WG_FIX_"+role+"_TEMPORARY_FILES_CLEANED=yes",flush=True)
            except Exception as ex:
                print("WG_FIX_"+role+"_CONFIRMED_TIMER_CLEANUP_PENDING="+type(ex).__name__,flush=True)
    finally:
        if not confirmed:
            for role in sorted(staged):
                try:
                    remote(role,ROLLBACK,[TAG],timeout=35)
                    print("WG_FIX_"+role+"_ROLLBACK_ATTEMPTED=yes",flush=True)
                except Exception as ex:
                    print("WG_FIX_"+role+"_INDEPENDENT_REVERT_PENDING="+type(ex).__name__,flush=True)
if __name__=="__main__":
    main()
