#!/usr/bin/env bash
# Production AmneziaWG cutover for tg-relay, with always-available WireGuard rollback.
# Only run after the same script has staged and armed BOTH endpoints.
set -Eeuo pipefail
umask 077
ACTION="${1:?stage/arm/switch/check/commit/rollback/status}"
ROLE="${2:?DE/RU}"
[[ "$ROLE" == DE || "$ROLE" == RU ]] || exit 2
DIR=/opt/mnebydns-awg-prod-20261116
BIN="$DIR/bin"
CONFIG=/etc/amnezia/amneziawg/tg-relay.conf
OLD=/etc/wireguard/tg-relay.conf
OLDUNIT=wg-quick@tg-relay.service
NEWUNIT=mneby-awg-tg-relay.service
ROLLBACK=mneby-awg-auto-rollback-20261116
if [[ "$ROLE" == DE ]]; then
  PORT=56783; OLDPORT=56781; PEER_PUBLIC=188.120.254.223
  LOCAL_INNER=10.66.77.1
else
  PORT=56784; OLDPORT=56782; PEER_PUBLIC=89.125.90.101
  LOCAL_INNER=10.66.77.2
fi
msg() { echo "AWG_PROD_${ROLE}_$1=$2"; }
healthy_old() {
  wg show tg-relay listen-port >/dev/null 2>&1 &&
  [[ "$(wg show tg-relay listen-port)" == "$OLDPORT" ]] &&
  systemctl is-active --quiet "$OLDUNIT"
}
healthy_awg() {
  [[ "$(env PATH="$BIN:$PATH" "$BIN/awg" show tg-relay listen-port 2>/dev/null || true)" == "$PORT" ]] &&
  systemctl is-active --quiet "$NEWUNIT"
}
case "$ACTION" in
 stage)
   healthy_old || { msg PRECHECK_OLD false; exit 10; }
   ip -4 -br addr show tg-relay | grep -Fq "$LOCAL_INNER/24" || { msg ORIGINAL_ADDRESS_MISMATCH true; exit 10; }
   [[ ! -e "$DIR" ]] || { msg STAGE_COLLISION true; exit 11; }
   [[ ! -e "$CONFIG" ]] || { msg CONFIG_EXISTS true; exit 11; }
   [[ -f /tmp/mneby-awg-prod-bundle-20261116.tar.gz && -s /tmp/mneby-awg-prod-header-20261116.txt ]] || exit 11
   if ss -H -lun | grep -Eq ":${PORT}[[:space:]]"; then msg PORT_OCCUPIED true; exit 12; fi
   mkdir -p "$BIN" "$DIR/backup" /etc/amnezia/amneziawg
   chmod 700 "$DIR" "$DIR/backup" /etc/amnezia/amneziawg
   cp -p "$OLD" "$DIR/backup/wireguard-tg-relay.conf"
   cp /tmp/mneby-awg-prod-bundle-20261116.tar.gz "$DIR/backup/awg-binary-bundle.tar.gz"
   tar -xzf "$DIR/backup/awg-binary-bundle.tar.gz" -C "$BIN"
   (cd "$BIN" && sha256sum -c SHA256SUMS >/dev/null)
   chmod 700 "$BIN/awg" "$BIN/awg-quick" "$BIN/amneziawg-go"
   cp /tmp/mneby-awg-prod-header-20261116.txt "$DIR/header.key"
   chmod 600 "$DIR/header.key"
   python3 - "$OLD" "$CONFIG" "$DIR/header.key" "$ROLE" "$PORT" "$PEER_PUBLIC" <<'PY'
import sys,pathlib,re,base64
old,new,hfile,role,port,peer=sys.argv[1:]
s=pathlib.Path(old).read_text()
h=pathlib.Path(hfile).read_text().strip()
assert len(base64.b64decode(h,validate=True))==32
assert s.count("[Interface]")==1 and s.count("[Peer]")==1
assert s.count("PrivateKey =")==1 and s.count("PublicKey =")==1
assert "PostUp =" in s and "PostDown =" in s
assert s.count("ListenPort =")==1 and s.count("MTU =")==1
original_port="56781" if role=="DE" else "56782"
assert re.search(r"(?m)^ListenPort\s*=\s*"+original_port+r"\s*$",s)
s=re.sub(r"(?m)^(ListenPort\s*=\s*)"+original_port+r"\s*$",lambda m:m.group(1)+port,s)
s=re.sub(r"(?m)^(MTU\s*=\s*)1360\s*$",r"\g<1>1280",s)
assert "MTU = 1280" in s
if role=="RU":
    assert s.count("Endpoint = 89.125.90.101:56781")==1
    s=s.replace("Endpoint = 89.125.90.101:56781","Endpoint = 89.125.90.101:56783")
    assert "Table = off" in s
else:
    assert "Endpoint =" not in s
insert="""
Jc = 5
Jmin = 20
Jmax = 95
S1 = 32
S2 = 32
S3 = 32
S4 = 32
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = {header}
ContentPaddingAddition = 0-16
RandomTrailers = off
PostUp = iptables -C INPUT -s {peer} -p udp --dport {port} -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -s {peer} -p udp --dport {port} -j ACCEPT
PostDown = iptables -D INPUT -s {peer} -p udp --dport {port} -j ACCEPT 2>/dev/null || true
""".format(header=h,peer=peer,port=port)
s=s.replace("[Peer]",insert+"\n[Peer]",1)
original=pathlib.Path(old).read_text()
for directive in ("PostUp","PostDown","PreUp","PreDown"):
    pattern=r"(?m)^"+directive+r"\s*=.*$"
    v0=re.findall(pattern,original);v1=re.findall(pattern,s)
    assert v0==v1[:len(v0)],directive
pathlib.Path(new).write_text(s)
pathlib.Path(new).chmod(0o600)
PY
   rm -f /tmp/mneby-awg-prod-header-20261116.txt
   env PATH="$BIN:$PATH" "$BIN/awg-quick" strip "$CONFIG" >/dev/null
   install -m 0700 /tmp/mneby-awg-prod-manage-20261116.sh "$DIR/manage.sh"
   cat >/etc/systemd/system/$NEWUNIT <<EOF
[Unit]
Description=MNEBYDNS AmneziaWG 3.1 production tg-relay
After=network-online.target
Wants=network-online.target
OnFailure=mneby-awg-fallback-$ROLE.service
[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PATH=$BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=$BIN/amneziawg-go
ExecStart=$BIN/awg-quick up tg-relay
ExecStop=$BIN/awg-quick down tg-relay
TimeoutStartSec=70
TimeoutStopSec=40
[Install]
WantedBy=multi-user.target
EOF
   cat >/etc/systemd/system/mneby-awg-fallback-$ROLE.service <<EOF
[Unit]
Description=Automatic fallback to WireGuard if AmneziaWG fails on $ROLE
[Service]
Type=oneshot
ExecStart=$DIR/manage.sh rollback $ROLE
EOF
   systemctl daemon-reload
   systemctl is-enabled --quiet "$OLDUNIT" || { msg OLD_BOOT_NOT_ENABLED true; exit 13; }
   msg STAGED true ;;
 arm)
   [[ -x "$DIR/manage.sh" && -f "$CONFIG" ]] || exit 14
   healthy_old || { msg OLD_NOT_HEALTHY true; exit 14; }
   if systemctl is-active --quiet "$ROLLBACK.timer"; then msg TIMER_COLLISION true; exit 14; fi
   systemd-run --quiet --unit="$ROLLBACK" --on-active=7min "$DIR/manage.sh" rollback "$ROLE"
   systemctl is-active --quiet "$ROLLBACK.timer" || exit 15
   msg TIMER_ARMED true ;;
 switch)
   [[ -x "$DIR/manage.sh" && -f "$CONFIG" ]] || exit 16
   systemctl is-active --quiet "$ROLLBACK.timer" || { msg NO_ROLLBACK_TIMER true; exit 16; }
   healthy_old || { msg OLD_NOT_HEALTHY true; exit 17; }
   systemctl stop "$OLDUNIT"
   if ip link show tg-relay >/dev/null 2>&1; then
      msg OLD_INTERFACE_STILL_EXISTS true
      "$DIR/manage.sh" rollback "$ROLE" || true
      exit 18
   fi
   if ! systemctl start "$NEWUNIT"; then
      msg NEW_UNIT_START_FAILED true
      "$DIR/manage.sh" rollback "$ROLE" || true
      exit 19
   fi
   if ! healthy_awg; then
      msg NEW_NOT_HEALTHY true
      "$DIR/manage.sh" rollback "$ROLE" || true
      exit 20
   fi
   msg SWITCHED true ;;
 check)
   healthy_awg || { msg CHECK_INTERFACE false; exit 21; }
   rc=0
   if [[ "$ROLE" == RU ]]; then
      ip -4 rule show | grep -q 'fwmark 0x77 lookup 51820' || rc=1
      ip -4 route show table 51820 | grep -q 'default dev tg-relay' || rc=1
   else
      iptables -t nat -S | grep -q -- '-o eth0 -j MASQUERADE' || rc=1
   fi
   age="$(env PATH="$BIN:$PATH" "$BIN/awg" show tg-relay latest-handshakes | awk '{if ($2>0)print systime()-$2}')"
   [[ "$age" =~ ^[0-9]+$ && "$age" -lt 120 ]] || rc=1
   msg HANDSHAKE_AGE_SEC "${age:-missing}"
   msg ROUTE_AND_NAT_OK "$([[ "$rc" == 0 ]] && echo true || echo false)"
   [[ "$rc" == 0 ]] || exit 22 ;;
 commit)
   "$DIR/manage.sh" check "$ROLE" || exit 23
   systemctl enable "$NEWUNIT" >/dev/null
   systemctl disable "$OLDUNIT" >/dev/null
   touch "$DIR/COMMITTED"
   systemctl stop "$ROLLBACK.timer" >/dev/null
   systemctl is-enabled --quiet "$NEWUNIT" || exit 24
   [[ "$(systemctl is-enabled "$OLDUNIT" 2>/dev/null || true)" == disabled ]] || exit 24
   msg COMMITTED true ;;
 rollback)
   # Used both by watchdog and workflow failure trap. Never delete original key.
   systemctl disable "$NEWUNIT" >/dev/null 2>&1 || true
   if systemctl is-active --quiet "$NEWUNIT"; then
      systemctl stop "$NEWUNIT" >/dev/null 2>&1 || true
   fi
   if [[ -f "$CONFIG" ]] && ip link show tg-relay >/dev/null 2>&1; then
      if ! wg show tg-relay listen-port >/dev/null 2>&1; then
         env PATH="$BIN:$PATH" "$BIN/awg-quick" down "$CONFIG" >/dev/null 2>&1 || ip link delete tg-relay || true
      fi
   fi
   systemctl enable "$OLDUNIT" >/dev/null 2>&1 || true
   systemctl reset-failed "$OLDUNIT" >/dev/null 2>&1 || true
   systemctl start "$OLDUNIT" >/dev/null 2>&1 || true
   if healthy_old; then
      rm -f "$DIR/COMMITTED"
      msg ROLLBACK_OLD_WORKING true
      exit 0
   fi
   msg ROLLBACK_OLD_WORKING false
   exit 30 ;;
 status)
   if healthy_awg; then msg ACTIVE AWG; elif healthy_old; then msg ACTIVE WIREGUARD; else msg ACTIVE UNHEALTHY; fi
   msg AWG_BOOT_ENABLED "$(systemctl is-enabled "$NEWUNIT" 2>/dev/null || true)"
   msg WG_BOOT_ENABLED "$(systemctl is-enabled "$OLDUNIT" 2>/dev/null || true)"
   ;;
 *) exit 2 ;;
esac
