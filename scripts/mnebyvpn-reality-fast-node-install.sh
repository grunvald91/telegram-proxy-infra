#!/usr/bin/env bash
# Staged, fail-closed optional REALITY ingress under the existing expiry agent.
# NOT triggered automatically. Before calling, copy the reviewed agent Python
# source to /tmp/mnebyvpn-vpn-provisioner-reality.py on the foreign node.
# Never touches shared xray.service, Nginx, WireGuard or firewall.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == 0 ]] || exit 2
exec 9>/run/lock/mnebyvpn-reality-fast-install.lock
flock -n 9 || exit 2
AGENT=/opt/mnebyvpn/vpn-provisioner.py
SOURCE=/tmp/mnebyvpn-vpn-provisioner-reality.py
CONF=/etc/mnebyvpn/xray-canary.json
PUBLIC=/etc/mnebyvpn/reality-public.json
ANNOUNCE=/etc/mnebyvpn/reality-announce-enabled
SERVICE=mnebyvpn-vpn-provisioner.service
XRAY=/opt/xray/xray
test -s "$SOURCE"
test -s "$AGENT"
test -s "$CONF"
test ! -e "$PUBLIC"
test ! -e "$ANNOUNCE"
test "$("$XRAY" version >/dev/null 2>&1; echo $?)" = 0
test "$(systemctl is-active "$SERVICE")" = active
test "$(systemctl is-active xray.service)" = active
ss -H -lnt | awk '{print $4}' | grep -Eq ':2053$' && {
  echo "reality_port_2053_in_use"; exit 2;
} || true
python3 -m py_compile "$SOURCE"
BACKUP="$(mktemp -d /opt/mnebyvpn/backups/reality-fast-XXXXXXXX)"
chmod 700 "$BACKUP"
cp -p "$AGENT" "$BACKUP/agent"
cp -p "$CONF" "$BACKUP/config"
STAGE="$(mktemp -d /etc/mnebyvpn/.reality-fast-stage-XXXXXXXX)"
chmod 700 "$STAGE"
restore(){
  set +e
  cp -p "$BACKUP/agent" "$AGENT"
  cp -p "$BACKUP/config" "$CONF"
  rm -f "$PUBLIC" "$ANNOUNCE"
  systemctl restart "$SERVICE" >/dev/null 2>&1 || true
  rm -rf "$STAGE"
  echo "reality_fast_install_rolled_back=true"
  exit 2
}
trap restore ERR
python3 - "$CONF" "$STAGE" "$XRAY" <<'PY'
import base64,json,pathlib,re,secrets,subprocess,sys
conf,stage,xray=map(pathlib.Path,sys.argv[1:])
current=json.loads(conf.read_text())
ins=current.get('inbounds')
if not isinstance(ins,list) or len(ins)!=1:
    raise SystemExit('Unexpected pre-existing Xray inbounds')
legacy=ins[0]
if (legacy.get('protocol')!='vless' or
    legacy.get('listen')!='127.0.0.1' or
    legacy.get('port')!=18943 or
    legacy.get('streamSettings',{}).get('network')!='ws'):
    raise SystemExit('Unexpected original listener')
if not current.get('routing') or not current.get('outbounds'):
    raise SystemExit('Missing original egress safety policy')
keyout=subprocess.run([str(xray),'x25519'],check=True,capture_output=True,text=True).stdout
found=re.search(r'(?im)^\s*private\s*key\s*:\s*(\S+)',keyout)
if not found or not re.fullmatch(r'[A-Za-z0-9_-]{43}',found.group(1)):
    raise SystemExit('Unsupported Xray x25519 key format')
private=found.group(1)
pkcs8=bytes.fromhex('302e020100300506032b656e04220420')+base64.urlsafe_b64decode(private+'==')
spki=subprocess.run(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],
                    input=pkcs8,check=True,capture_output=True).stdout
prefix=bytes.fromhex('302a300506032b656e032100')
if not spki.startswith(prefix) or len(spki)!=len(prefix)+32:
    raise SystemExit('Invalid X25519 public key')
public=base64.urlsafe_b64encode(spki[len(prefix):]).rstrip(b'=').decode()
sid=secrets.token_hex(8)
current['inbounds'].append({
    'listen':'0.0.0.0','port':2053,'protocol':'vless',
    'tag':'mnebyvpn-reality-inbound',
    'settings':{'clients':[],'decryption':'none'},
    'streamSettings':{'network':'tcp','security':'reality',
        'realitySettings':{'show':False,'target':'www.cloudflare.com:443',
            'xver':0,'serverNames':['www.cloudflare.com'],
            'privateKey':private,'shortIds':[sid]}}})
(stage/'config.json').write_text(json.dumps(current))
(stage/'public.json').write_text(json.dumps({
    'port':2053,'publicKey':public,'shortId':sid}))
PY
chmod 600 "$STAGE/config.json" "$STAGE/public.json"
"$XRAY" run -test -config "$STAGE/config.json" >/dev/null
# After prevalidation the existing agent is restarted exactly once.
install -m 700 "$SOURCE" "$AGENT"
install -m 600 "$STAGE/public.json" "$PUBLIC"
install -m 640 -o root -g mnebyvpn-xray "$STAGE/config.json" "$CONF"
systemctl restart "$SERVICE"
READY=no
for attempt in $(seq 1 30); do
  code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 2 \
    http://10.66.77.1:18944/healthz || true)"
  if [[ "$code" == 200 ]] &&
     ss -H -lnt | awk '{print $4}' | grep -Eq ':2053$' &&
     ss -H -lnt | awk '{print $4}' | grep -Fqx '127.0.0.1:18943'; then
    READY=yes; break
  fi
  sleep 1
done
[[ "$READY" == yes ]]
test "$(systemctl is-active xray.service)" = active
test ! -e "$ANNOUNCE"
rm -rf "$STAGE"
trap - ERR
echo "reality_fast_stage_ready=true"
echo "reality_public_2053_listener=true"
echo "existing_websocket_fallback_preserved=true"
echo "reality_profile_announcement=disabled_until_E2E"
echo "production_services_not_otherwise_changed=true"
