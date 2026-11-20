#!/usr/bin/env bash
# Real production FI217 AmneziaWG E2E: one ephemeral signed test client.
set -Eeuo pipefail
umask 077
test "$FI_USER" = root
test -n "$FI_PASSWORD"
test -n "$RU_PASSWORD"
ext="$RUNNER_TEMP/awgbin"
test -x "$ext/awg"
test -x "$ext/awg-quick"
test -x "$ext/amneziawg-go"
work="$RUNNER_TEMP/fi-awg-real-e2e"
mkdir -m 0700 "$work"
iface=awge2e0
ru_dir=''
fi_dir=''
grant_applied=no
revoke_applied=no
client_up=no
echo_ip=''
cat > "$work/ru.cfg" <<CFG
Host ru-controller
 HostName 188.120.254.223
 User root
 UserKnownHostsFile $GITHUB_WORKSPACE/ops/mnebydns-owner-ssh-known_hosts
 GlobalKnownHostsFile /dev/null
 HostKeyAlgorithms ssh-ed25519
 StrictHostKeyChecking yes
 UpdateHostKeys no
 PasswordAuthentication yes
 PubkeyAuthentication no
 KbdInteractiveAuthentication no
 BatchMode no
 ForwardAgent no
 ClearAllForwardings yes
 ControlMaster no
 ProxyCommand none
 ConnectTimeout 12
 LogLevel ERROR
CFG
ru(){ SSHPASS="$RU_PASSWORD" sshpass -e ssh -T -F "$work/ru.cfg" ru-controller "$@"; }
ru_put(){ SSHPASS="$RU_PASSWORD" sshpass -e scp -F "$work/ru.cfg" "$1" "ru-controller:$ru_dir/$2"; }
ru 'test -f /root/mnebyvpn-controller/fi-known_hosts; test ! -L /root/mnebyvpn-controller/fi-known_hosts; test "$(stat -c "%u:%a" /root/mnebyvpn-controller/fi-known_hosts)" = "0:600"; cat /root/mnebyvpn-controller/fi-known_hosts' > "$work/fi-known"
python3 - "$work/fi-known" <<'PY'
import base64,pathlib,sys
data=pathlib.Path(sys.argv[1]).read_bytes()
assert data.endswith(b'\n') and data.count(b'\n')==1 and len(data)<512
host,kind,key=data.decode('ascii').strip().split()
assert (host,kind)==('fi.mnebyvpn.site','ssh-ed25519')
raw=base64.b64decode(key,validate=True)
assert len(raw)==51 and raw.startswith(b'\0\0\0\x0bssh-ed25519\0\0\0\x20')
PY
cat > "$work/fi.cfg" <<CFG
Host fi-node
 HostName 217.11.167.91
 User root
 UserKnownHostsFile $work/fi-known
 HostKeyAlias fi.mnebyvpn.site
 GlobalKnownHostsFile /dev/null
 HostKeyAlgorithms ssh-ed25519
 StrictHostKeyChecking yes
 UpdateHostKeys no
 PasswordAuthentication yes
 PubkeyAuthentication no
 KbdInteractiveAuthentication no
 BatchMode no
 ForwardAgent no
 ClearAllForwardings yes
 ControlMaster no
 ProxyCommand none
 ConnectTimeout 12
 LogLevel ERROR
CFG
fi_node(){ SSHPASS="$FI_PASSWORD" sshpass -e ssh -T -F "$work/fi.cfg" fi-node "$@"; }
fi_put(){ SSHPASS="$FI_PASSWORD" sshpass -e scp -F "$work/fi.cfg" "$1" "fi-node:$fi_dir/$2"; }
revoke(){
  set +e
  if [[ "$grant_applied" != yes || "$revoke_applied" == yes || -z "$ru_dir" || -z "$fi_dir" ]];then return;fi
  python3 - "$work/request.json" "$work/revoke-request.json" <<'PY'
import json,sys
obj=json.load(open(sys.argv[1]));obj['op']='revoke'
with open(sys.argv[2],'w') as f:json.dump(obj,f)
PY
  ru_put "$work/revoke-request.json" revoke-request.json >/dev/null 2>&1 || return
  ru "timeout 15s python3 '$ru_dir/fi_awg_live_customer_e2e.py' --mode ru-sign --request '$ru_dir/revoke-request.json'" > "$work/revoke.json" 2>/dev/null || return
  fi_put "$work/revoke.json" revoke.json >/dev/null 2>&1 || return
  fi_node "timeout 35s python3 /opt/mnebyvpn-nodekit/awg_peer_grants.py --node-id fi-test-01 --mode apply --command '$fi_dir/revoke.json'" > "$work/revoke-applied.json" 2>/dev/null || return
  revoke_applied=yes
}
cleanup(){
  rc=$?
  trap - EXIT
  set +e
  sudo ip route del 10.73.91.1/32 dev "$iface" >/dev/null 2>&1
  if [[ -n "$echo_ip" ]];then sudo ip route del "$echo_ip/32" dev "$iface" >/dev/null 2>&1;fi
  if [[ "$client_up" == yes ]];then
    sudo env PATH="$ext:/usr/sbin:/usr/bin:/sbin:/bin" WG_QUICK_USERSPACE_IMPLEMENTATION="$ext/amneziawg-go" "$ext/awg-quick" down "$work/$iface.conf" >/dev/null 2>&1
  fi
  revoke
  if [[ "$ru_dir" =~ ^/run/fi-awg-real-e2e\.[A-Za-z0-9]{8}$ ]];then ru "rm -rf -- '$ru_dir'" >/dev/null 2>&1;fi
  if [[ "$fi_dir" =~ ^/run/fi-awg-real-e2e\.[A-Za-z0-9]{8}$ ]];then fi_node "rm -rf -- '$fi_dir'" >/dev/null 2>&1;fi
  rm -rf -- "$work"
  exit "$rc"
}
trap cleanup EXIT
ru_dir=$(ru 'umask 077; mktemp -d /run/fi-awg-real-e2e.XXXXXXXX')
fi_dir=$(fi_node 'umask 077; mktemp -d /run/fi-awg-real-e2e.XXXXXXXX')
[[ "$ru_dir" =~ ^/run/fi-awg-real-e2e\.[A-Za-z0-9]{8}$ ]] || exit 2
[[ "$fi_dir" =~ ^/run/fi-awg-real-e2e\.[A-Za-z0-9]{8}$ ]] || exit 2
for name in fi_awg_live_customer_e2e.py fi_awg_signed_canary.py fi_awg_production_policy.py awg_lifecycle.py install_components.py;do
  ru_put "nodekit/$name" "$name"
  fi_put "nodekit/$name" "$name"
done
ru "chmod 0600 '$ru_dir/'*.py"
fi_node "chmod 0600 '$fi_dir/'*.py"
fi_node 'systemctl is-active --quiet mnebyvpn-nodekit-awg@fi-test-01.service && systemctl is-active --quiet mnebyvpn-nodekit-awg-watchdog@fi-test-01.service && systemctl is-active --quiet mnebyvpn-nodekit-awg-egress@fi-test-01.service && test -z "$(/opt/mnebyvpn-amneziawg/awg show awg0 peers)"'
ru 'test "$(docker exec mnebyvpn-stage-postgres psql -AtX -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage -c "SELECT enabled::text FROM public.vpn_release_flags WHERE feature='\''vpn_awg_clients'\''")" = false'
fi_node "timeout 30s python3 '$fi_dir/fi_awg_live_customer_e2e.py' --mode fi-material" > "$work/material.json"
"$ext/awg" genkey > "$work/client.key"
"$ext/awg" pubkey < "$work/client.key" > "$work/client.pub"
python3 - "$work" <<'PY'
import json,uuid,sys,pathlib
root=pathlib.Path(sys.argv[1])
m=json.loads((root/'material.json').read_text())
assert m['nodeId']=='fi-test-01' and m['hostname']=='fi.mnebyvpn.site'
assert m['clientIp']=='10.73.91.253' and m['port']==51821
pub=(root/'client.pub').read_text().strip()
assert len(pub)==44 and pub.endswith('=')
req={'op':'grant','entitlementId':str(uuid.uuid4()),
     'peerPublicKey':pub,'clientIpv4':'10.73.91.253'}
(root/'request.json').write_text(json.dumps(req))
PY
ru_put "$work/request.json" request.json
ru "timeout 15s python3 '$ru_dir/fi_awg_live_customer_e2e.py' --mode ru-sign --request '$ru_dir/request.json'" > "$work/grant.json"
fi_put "$work/grant.json" grant.json
fi_node "timeout 35s python3 /opt/mnebyvpn-nodekit/awg_peer_grants.py --node-id fi-test-01 --mode apply --command '$fi_dir/grant.json'" > "$work/grant-applied.json"
grant_applied=yes
echo 'FI_AWG_LIVE_E2E_SIGNED_GRANT=PASS'
echo_ip=$(getent ahostsv4 api.ipify.org | awk '/STREAM/ {print $1;exit}')
[[ "$echo_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
export FI_E2E_WORK="$work" FI_E2E_ECHO="$echo_ip"
python3 - <<'PY'
import json,pathlib,os
root=pathlib.Path(os.environ['FI_E2E_WORK'])
m=json.loads((root/'material.json').read_text())
key=(root/'client.key').read_text().strip()
lines=['[Interface]','Address = 10.73.91.253/32','PrivateKey = '+key,
'ListenPort = 0','MTU = 1280','Table = off','Jc = 0','Jmin = 0','Jmax = 0',
'S1 = 16','S2 = 16','S3 = 16','S4 = 16','H1 = 1','H2 = 2','H3 = 3','H4 = 4',
'HeaderProtectionKey = '+m['headerKey'],'RandomTrailers = on','DisableCookies = off','',
'[Peer]','PublicKey = '+m['serverPublicKey'],'Endpoint = 217.11.167.91:51821',
'AllowedIPs = 10.73.91.1/32, '+os.environ['FI_E2E_ECHO']+'/32',
'PersistentKeepalive = 10','']
file=root/'awge2e0.conf';file.write_text('\n'.join(lines));file.chmod(0o600)
PY
sudo env PATH="$ext:/usr/sbin:/usr/bin:/sbin:/bin" WG_QUICK_USERSPACE_IMPLEMENTATION="$ext/amneziawg-go" "$ext/awg-quick" up "$work/$iface.conf" >/dev/null
client_up=yes
sudo ip route add 10.73.91.1/32 dev "$iface"
sudo ip route add "$echo_ip/32" dev "$iface"
sudo ping -I "$iface" -n -c 3 -W 4 10.73.91.1 >/dev/null
handshake=$(sudo "$ext/awg" show "$iface" latest-handshakes | awk 'NF==2 {print $2;exit}')
[[ "$handshake" =~ ^[1-9][0-9]*$ ]] || exit 2
curl --noproxy '*' --interface "$iface" -4 --fail --silent --show-error --connect-timeout 8 --max-time 16 -o "$work/observed-ip" --resolve "api.ipify.org:443:$echo_ip" https://api.ipify.org
[[ "$(cat "$work/observed-ip")" == 217.11.167.91 ]] || exit 2
transfer=$(sudo "$ext/awg" show "$iface" transfer | awk 'NF==3 && $2~/^[0-9]+$/ && $3~/^[0-9]+$/ && $2>0 && $3>0 {print "yes"}')
[[ "$transfer" == yes ]] || exit 2
echo 'FI_AWG_LIVE_E2E_HANDSHAKE=PASS'
echo 'FI_AWG_LIVE_E2E_HTTPS_EGRESS=PASS'
echo 'FI_AWG_LIVE_E2E_ENCRYPTED_BYTES=PASS'
revoke
[[ "$revoke_applied" == yes ]] || exit 2
fi_node 'test -z "$(/opt/mnebyvpn-amneziawg/awg show awg0 peers)"'
echo 'FI_AWG_LIVE_E2E_REVOKE=PASS'
python3 - "$work" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
read=lambda f:json.loads((p/f).read_text())
record={'magic':'FI_AWG_LIVE_E2E_V1',
'grant':read('grant.json'),'grantApplied':read('grant-applied.json'),
'revoke':read('revoke.json'),'revokeApplied':read('revoke-applied.json'),
'external':{'handshake':True,'encryptedBytes':True,'ping':True,
'https':True,'egressIp':'217.11.167.91'},
'serverPublicKey':read('material.json')['serverPublicKey']}
(p/'proof.json').write_text(json.dumps(record,separators=(',',':')))
(p/'proof.json').chmod(0o600)
PY
ru_put "$work/proof.json" proof.json
ru "timeout 40s python3 '$ru_dir/fi_awg_live_customer_e2e.py' --mode ru-record --request '$ru_dir/proof.json'"
echo 'FI_AWG_LIVE_E2E_POOL_FRESH=PASS'
