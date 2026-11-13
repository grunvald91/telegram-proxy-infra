#!/usr/bin/env bash
# Guarded DNS A-only SmartDNS fast path: exact host addresses to RU ingress.
# Nginx, CoreDNS TLS config, proxy service, WireGuard and other RR remain unchanged.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 2 && "$1" =~ ^[1-9][0-9]{8,12}$ ]] || exit 2
id="$1"; work="$2"
[[ "$work" == "/tmp/mnebydns-fastpath-$id" ]] || exit 2
base="/opt/mnebydns-fastpath/$id"
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
pointer=/opt/mnebydns-stable-checkpoints/current
unit="mnebydns-fastpath-rollback-$id"
for f in dns.before dns.pilot plan.json rollback.sh commit.sh reload.sh; do
  [[ -s "$work/$f" && ! -L "$work/$f" ]] || exit 3
done
python3 - "$work" <<'PY'
import hashlib,json,pathlib,sys
p=pathlib.Path(sys.argv[1])
d=json.loads((p/'plan.json').read_text())
assert d['read_only'] is True and d['selected_count']>=3
assert d['selected_count']==len(set(d['selected']))
for file,key in (('dns.before','sha_before'),('dns.pilot','sha_pilot')):
    assert hashlib.sha256((p/file).read_bytes()).hexdigest()==d[key]
print('FASTPATH_STAGED_HASHES_VERIFIED=true',flush=True)
PY
old="$(cat "$pointer")"
[[ "$old" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 3
(cd "$old" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$old/dns.stable" "$dns"
cmp -s "$old/nginx.stable" "$nginx"
cmp -s "$old/proxy.stable" "$proxy"
cmp -s "$work/dns.before" "$dns"
! cmp -s "$work/dns.pilot" "$dns"
nginx -t >/dev/null 2>&1
for service in nginx mnebydns-dot.service mnebydns-googlepilot.service xray.service; do
  systemctl is-active --quiet "$service"
done
test -x /opt/mnebydns-dot/coredns
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 50 9 || exit 3
test "$(cat "$pointer")" = "$old"
cmp -s "$old/dns.stable" "$dns"
cmp -s "$old/nginx.stable" "$nginx"
cmp -s "$old/proxy.stable" "$proxy"
test ! -e "$base"
install -d -m 700 /opt/mnebydns-fastpath "$base"
cp -p "$work/dns.before" "$base/dns.before"
cp -p "$work/dns.pilot" "$base/dns.pilot"
for f in rollback commit reload; do
  install -m 700 "$work/$f.sh" "$base/$f.sh"
done
printf '%s\n' "$old" > "$base/checkpoint.before"
cp -p "$work/plan.json" "$base/plan.json"
# Reuse group-readable metadata from the active DynamicUser resolver.
chown --reference="$dns" "$base/dns.pilot"
chmod --reference="$dns" "$base/dns.pilot"
test "$(stat -c '%a:%u:%g' "$base/dns.pilot")" = "$(stat -c '%a:%u:%g' "$dns")"
# Validate the COMPLETE candidate in an isolated loopback DoT process.
python3 - "$base/dns.pilot" "$base/dns.preflight" <<'PY'
from pathlib import Path
import sys
source=Path(sys.argv[1]).read_text()
assert source.count('tls://.:853 {')==1
assert source.count('    bind 89.125.90.101')==1
candidate=source.replace('tls://.:853 {','tls://.:18553 {',1)
candidate=candidate.replace('    bind 89.125.90.101','    bind 127.0.0.1',1)
dst=Path(sys.argv[2])
dst.write_text(candidate)
dst.chmod(0o600)
PY
test -z "$(ss -H -lnt 'sport = :18553')"
/opt/mnebydns-dot/coredns -conf "$base/dns.preflight" >"$base/preflight.log" 2>&1 &
preflight_pid=$!
cleanup_preflight() {
  if [[ -n "${preflight_pid:-}" ]]; then
    kill "$preflight_pid" >/dev/null 2>&1 || true
    wait "$preflight_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup_preflight EXIT
for attempt in $(seq 1 55); do
  if ! kill -0 "$preflight_pid" 2>/dev/null; then
    echo "FASTPATH_CANDIDATE_CONFIG_INVALID=true" >&2
    exit 3
  fi
  if ss -H -lnt 'sport = :18553' | grep -Fq '127.0.0.1:18553'; then break; fi
  sleep .2
done
ss -H -lnt 'sport = :18553' | grep -Fq '127.0.0.1:18553'
python3 - "$base/plan.json" <<'PY'
import ipaddress,json,socket,ssl,struct,sys
selected=json.load(open(sys.argv[1]))['selected']
def read(conn,n):
    b=b''
    while len(b)<n:
        t=conn.recv(n-len(b))
        if not t:raise EOFError("invalid DNS length")
        b+=t
    return b
def query(host):
    name=b''.join(bytes([len(x)])+x.encode() for x in host.split('.'))+b'\x00'
    payload=struct.pack('!HHHHHH',0x7891,0x100,1,0,0,0)+name+struct.pack('!HH',1,1)
    with socket.create_connection(('127.0.0.1',18553),timeout=3) as tcp:
        tcp.settimeout(5)
        with ssl.create_default_context().wrap_socket(tcp,server_hostname='dns.mnebyvpn.site') as tls:
            tls.sendall(len(payload).to_bytes(2,'big')+payload)
            data=read(tls,int.from_bytes(read(tls,2),'big'))
    if data[:2]!=payload[:2] or data[3]&15:raise RuntimeError("Bad preflight DNS reply")
    if host in selected and ipaddress.IPv4Address('188.120.254.223').packed not in data:
        raise RuntimeError("Selected name did not map to RU: "+host)
for item in selected+['example.org','api.telegram.org']:
    query(item)
print("FASTPATH_ISOLATED_DOT_VERIFIED="+str(len(selected)),flush=True)
PY
cleanup_preflight
preflight_pid=""
trap - EXIT
# Independent reversion if runner disconnects before successful commit.
systemd-run --quiet --unit="$unit" --on-active=45m \
  /bin/bash "$base/rollback.sh" "$base"
systemctl is-active --quiet "$unit.timer"
armed=true
abort() {
  code=$?
  trap - EXIT
  flock -u 9 || true
  if [[ "${armed:-false}" == true ]]; then
    bash "$base/rollback.sh" "$base" || echo "FASTPATH_ROLLBACK_UNVERIFIED=true" >&2
  fi
  exit "$code"
}
trap abort EXIT
cp -p "$base/dns.pilot" "$dns.fastpath-$id"
mv -f "$dns.fastpath-$id" "$dns"
cmp -s "$base/dns.pilot" "$dns"
bash "$base/reload.sh" "$dns"
systemctl is-active --quiet mnebydns-dot.service
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
cmp -s "$old/nginx.stable" "$nginx"
cmp -s "$old/proxy.stable" "$proxy"
test "$(cat "$pointer")" = "$old"
echo "FASTPATH_STAGED_WITH_45M_ROLLBACK=true"
trap - EXIT
flock -u 9
