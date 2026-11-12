#!/usr/bin/env bash
# One-time, guarded production migration of the existing public CoreDNS DoT.
# Never rewrites SNI routing, nginx, proxy credentials, or hostname templates.
set -Eeuo pipefail
(( EUID == 0 )) || exit 2
[[ $# == 2 && "$1" =~ ^[0-9]{9,13}$ ]] || exit 2
runid="$1"; stagedir="$2"
[[ "$stagedir" == "/tmp/mnebydns-resilience-$runid" ]] || exit 2
test -s "$stagedir/mnebydns-dot-resilience-20261111.py"
test -s "$stagedir/mnebydns-dot-resilience-rollback-20261111.sh"
dns=/opt/mnebydns-dot/Corefile
nginx=/etc/nginx/nginx.conf
proxy=/etc/mnebydns-googlepilot/nginx.conf
checkpoint_dir=/opt/mnebydns-stable-checkpoints
pointer="$checkpoint_dir/current"
base="/opt/mnebydns-resilience/$runid"
unit="mnebydns-resilience-rollback-$runid"
mkdir -p -m 700 /opt/mnebydns-resilience
exec 9>/run/lock/mnebyvpn-public-route.lock
flock -w 40 9 || exit 3
test ! -e "$base"
mkdir -m 700 "$base"
armed=0
completed=0
preflight_pid=""
abort() {
  code=$?
  trap - EXIT
  if [[ -n "$preflight_pid" ]]; then
    kill "$preflight_pid" >/dev/null 2>&1 || true
    wait "$preflight_pid" >/dev/null 2>&1 || true
  fi
  if (( completed == 0 && armed == 1 )); then
    flock -u 9 || true
    bash "$base/rollback.sh" "$base" ||
      echo 'resilience_abort_rollback_requires_manual_inspection=true'
  fi
  exit "$code"
}
trap abort EXIT

current="$(cat "$pointer")"
[[ "$current" =~ ^/opt/mnebydns-stable-checkpoints/[0-9]+$ ]] || exit 4
(cd "$current" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$current/dns.stable" "$dns"
cmp -s "$current/nginx.stable" "$nginx"
cmp -s "$current/proxy.stable" "$proxy"
shopt -s nullglob
owner_timers=(/etc/systemd/system/mnebydns-owner-rollback-*.timer)
(( ${#owner_timers[@]} == 0 )) || {
  echo 'resilience_denied_active_owner_rollback_timer=true'
  exit 4
}
systemctl is-active --quiet mnebydns-dot.service
systemctl is-active --quiet nginx.service
nginx -t >/dev/null 2>&1

# Validate that the running binary supports the directives before any write.
/opt/mnebydns-dot/coredns -version
plugins="$(/opt/mnebydns-dot/coredns -plugins 2>&1)"
grep -Eq '(^|[[:space:].])reload([[:space:]]|$)' <<< "$plugins"
grep -Eq '(^|[[:space:].])forward([[:space:]]|$)' <<< "$plugins"
grep -Eq '(^|[[:space:].])cache([[:space:]]|$)' <<< "$plugins"

cp -p "$dns" "$base/dns.before"
printf '%s\n' "$current" > "$base/checkpoint.before"
python3 "$stagedir/mnebydns-dot-resilience-20261111.py" render \
   --input "$base/dns.before" --output "$base/dns.candidate"
chmod --reference="$dns" "$base/dns.candidate"
chown --reference="$dns" "$base/dns.candidate"
# The installed CoreDNS 1.15.0 binary has no -validate option.
# Parse and serve the complete candidate in a private loopback-only DoT
# instance. Neither the public listener nor any live file is touched.
python3 - "$base/dns.candidate" "$base/dns.preflight" <<'PY'
import pathlib,sys
original=pathlib.Path(sys.argv[1]).read_text()
port="tls://.:853 {"
bind="    bind 89.125.90.101"
if original.count(port)!=1 or original.count(bind)!=1:
    raise SystemExit("MNEBYDNS_PREFLIGHT_UNEXPECTED_LISTENER")
replacement=original.replace(port,"tls://.:18553 {",1).replace(
    bind,"    bind 127.0.0.1",1)
if "tls://.:853 {" in replacement or "    bind 89.125.90.101" in replacement:
    raise SystemExit("MNEBYDNS_PREFLIGHT_PUBLIC_BIND_FORBIDDEN")
path=pathlib.Path(sys.argv[2])
path.write_text(replacement)
path.chmod(0o600)
print("mnebydns_candidate_loopback_rewrite=PASS",flush=True)
PY
/opt/mnebydns-dot/coredns -conf "$base/dns.preflight" >"$base/preflight.log" 2>&1 &
preflight_pid=$!
for attempt in $(seq 1 35); do
  if ! kill -0 "$preflight_pid" 2>/dev/null; then
    tail -n 20 "$base/preflight.log" >&2
    echo 'mnebydns_candidate_validation_start_failed=true' >&2
    exit 3
  fi
  if ss -H -lnt 'sport = :18553' | grep -Fq '127.0.0.1:18553'; then
    break
  fi
  sleep .2
done
ss -H -lnt 'sport = :18553' | grep -Fq '127.0.0.1:18553'
python3 - <<'PY'
import socket,ssl,struct
def recv(s,n):
    data=b''
    while len(data)<n:
        chunk=s.recv(n-len(data))
        if not chunk: raise EOFError("loopback DoT truncated")
        data+=chunk
    return data
def query(host):
    qname=b''.join(bytes([len(label)])+label.encode() for label in host.split('.'))+b'\0'
    payload=struct.pack('!HHHHHH',0x7b32,0x0100,1,0,0,0)+qname+struct.pack('!HH',1,1)
    with socket.create_connection(('127.0.0.1',18553),timeout=5) as plain:
        plain.settimeout(6)
        with ssl.create_default_context().wrap_socket(
                plain,server_hostname='dns.mnebyvpn.site') as tls:
            tls.sendall(struct.pack('!H',len(payload))+payload)
            response=recv(tls,struct.unpack('!H',recv(tls,2))[0])
    if response[:2]!=payload[:2] or len(response)<12:
        raise RuntimeError('invalid preflight DNS response')
    return response[3]&15
for hostname in ('example.org','claude.ai','api.telegram.org'):
    code=query(hostname)
    print('PREFLIGHT_DOT='+hostname+' rcode='+str(code),flush=True)
    if code!=0:raise RuntimeError('preflight resolution failed: '+hostname)
print('mnebydns_candidate_isolated_tls_diagnostic=PASS',flush=True)
PY
kill "$preflight_pid" >/dev/null 2>&1 || true
wait "$preflight_pid" >/dev/null 2>&1 || true
preflight_pid=""
install -m 700 "$stagedir/mnebydns-dot-resilience-rollback-20261111.sh" "$base/rollback.sh"

# On runner disconnect or crash this independent timer restores ONLY the
# identical uncommitted candidate, never a newer/confirmed stable checkpoint.
systemd-run --quiet --unit="$unit" --on-active=20m \
    /bin/bash "$base/rollback.sh" "$base"
systemctl is-active --quiet "$unit.timer"
armed=1

cp -p "$base/dns.candidate" "$dns.resilience-$runid"
mv -f "$dns.resilience-$runid" "$dns"
cmp -s "$base/dns.candidate" "$dns"
# First enablement of reload requires one controlled restart. All later
# exact-host updates use the reload plugin with unchanged serving PID.
systemctl restart mnebydns-dot.service
for attempt in $(seq 1 65); do
  if systemctl is-active --quiet mnebydns-dot.service &&
     ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'; then
    break
  fi
  sleep .2
done
systemctl is-active --quiet mnebydns-dot.service
ss -H -lnt 'sport = :853' | grep -Fq '89.125.90.101:853'
# Confirm certificate, DNS answer codes, and preserved exact SmartDNS routes.
python3 - <<'PY'
import socket,ssl,struct,time
edge="89.125.90.101"
def read(s,n):
    data=b""
    while len(data)<n:
        q=s.recv(n-len(data))
        if not q:raise EOFError("empty DoT response")
        data+=q
    return data
def query(name):
    labels=b"".join(bytes((len(part),))+part.encode() for part in name.split("."))+b"\x00"
    packet=struct.pack("!HHHHHH",0x6341,0x0100,1,0,0,0)+labels+struct.pack("!HH",1,1)
    with socket.create_connection((edge,853),timeout=5) as tcp:
        tcp.settimeout(6)
        with ssl.create_default_context().wrap_socket(tcp,server_hostname="dns.mnebyvpn.site") as tls:
            tls.sendall(struct.pack("!H",len(packet))+packet)
            reply=read(tls,struct.unpack("!H",read(tls,2))[0])
    if len(reply)<12 or reply[:2]!=packet[:2]:raise RuntimeError("invalid DNS reply")
    return reply[3]&15
checks=("claude.ai","antigravity.google","www.youtube.com",
        "copilot.microsoft.com","xbox.com","example.org","api.telegram.org")
for name in checks:
    codes=[]
    for attempt in range(3):
        result=query(name)
        codes.append(result)
        if result==0:break
        time.sleep(.2)
    print("RESILIENCE_DOT_CHECK="+name+" rcode="+str(result),flush=True)
    if result!=0:raise RuntimeError("post-migration DoT failed "+name)
print("RESILIENCE_DOT_SMOKE=PASS",flush=True)
PY
cmp -s "$base/dns.candidate" "$dns"
cmp -s "$current/nginx.stable" "$nginx"
cmp -s "$current/proxy.stable" "$proxy"
nginx -t >/dev/null 2>&1

# Promote an integrity-checked new checkpoint under the same route lock,
# atomically. Preserve all unrelated checkpoint files and metadata.
next="$checkpoint_dir/$(date -u +%s)"
test ! -e "$next"
mkdir -m 700 "$next"
cp -a "$current/." "$next/"
cp -p "$base/dns.candidate" "$next/dns.stable"
(cd "$next" && sha256sum nginx.stable dns.stable proxy.stable > stable-manifest.sha256)
(cd "$next" && sha256sum -c stable-manifest.sha256 >/dev/null)
cmp -s "$next/dns.stable" "$dns"
cmp -s "$next/nginx.stable" "$nginx"
cmp -s "$next/proxy.stable" "$proxy"
tmp="$(mktemp "$checkpoint_dir/current.resilience.XXXXXXXX")"
printf '%s\n' "$next" > "$tmp"
chmod --reference="$pointer" "$tmp"
mv -f "$tmp" "$pointer"
test "$(cat "$pointer")" = "$next"
completed=1
# The timer also refuses rollback once it sees the new committed checkpoint.
systemctl stop "$unit.timer" >/dev/null 2>&1 || true
echo "mnebydns_resilience_checkpoint=$next"
echo 'mnebydns_resilience_redundant_upstream_live=true'
trap - EXIT
flock -u 9
