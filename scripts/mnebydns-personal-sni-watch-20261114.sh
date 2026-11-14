#!/usr/bin/env bash
# Keep the existing free DoT route available. A repeated SNI proxy failure
# removes ONLY the personal NAT redirect, returning TCP/853 to live CoreDNS.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || exit 2
ROOT=/run/mnebydns-personal-sni-watch
mkdir -p -m 700 "$ROOT"
FAILURES="$ROOT/failure-count"
LOCK="$ROOT/watch.lock"
exec 9>"$LOCK"
flock -w 2 9 || { echo 'PERSONAL_SNI_WATCH_LOCK=BUSY'; exit 0; }
NAT=(-i eth0 -d 89.125.90.101 -p tcp --dport 853 -j REDIRECT --to-ports 8854)
nat_present(){ iptables -w -t nat -C PREROUTING "${NAT[@]}" >/dev/null 2>&1; }
if ! nat_present; then
  echo 0 > "$FAILURES"
  echo 'PERSONAL_SNI_WATCH=NO_PERSONAL_REDIRECT_TO_CHECK'
  exit 0
fi
if python3 - <<'PY'
import socket,ssl,struct,secrets
ctx=ssl.create_default_context()
for name in ('dns.mnebyvpn.site','aaaaaaaaaaaa.dns.mnebyvpn.site'):
    with socket.create_connection(('127.0.0.1',8854),timeout=4) as raw:
        raw.settimeout(4)
        with ctx.wrap_socket(raw,server_hostname=name) as tls:
            assert bool(tls.getpeercert())
            if name=='dns.mnebyvpn.site':
                tid=secrets.randbelow(65534)+1
                q=struct.pack('!HHHHHH',tid,256,1,0,0,0)
                q+=b'\x07example\x03com\x00'+struct.pack('!HH',1,1)
                tls.sendall(struct.pack('!H',len(q))+q)
                size=tls.recv(2)
                assert len(size)==2
                n=struct.unpack('!H',size)[0]
                assert 12<=n<=65535
                data=b''
                while len(data)<n:
                    part=tls.recv(n-len(data))
                    assert part
                    data+=part
                assert struct.unpack('!H',data[:2])[0]==tid and (data[2]&128)
print('PERSONAL_SNI_WATCH_ROUTING=PASS')
PY
then
  echo 0 > "$FAILURES"
  echo 'PERSONAL_SNI_WATCH=HEALTHY_NO_CHANGES'
  exit 0
fi
previous="$(cat "$FAILURES" 2>/dev/null || echo 0)"
[[ "$previous" =~ ^[0-9]+$ ]] || previous=0
failures=$((previous+1))
echo "$failures" > "$FAILURES"
echo "PERSONAL_SNI_WATCH_CONSECUTIVE_FAILURES=$failures"
if (( failures < 3 )); then exit 0; fi
# Do not roll back to an unhealthy backend. The original public CoreDNS
# socket must first pass a fresh verified TLS probe.
if ! python3 - <<'PY'
import socket,ssl
with socket.create_connection(('89.125.90.101',853),timeout=5) as raw:
    raw.settimeout(5)
    with ssl.create_default_context().wrap_socket(raw,server_hostname='dns.mnebyvpn.site') as tls:
        assert bool(tls.getpeercert())
PY
then
  echo 'PERSONAL_SNI_WATCH=COREDNS_ORIGIN_UNHEALTHY_NO_REDIRECT_CHANGE'
  exit 1
fi
if systemctl is-active --quiet mnebydns-personal-sni-redirect.service; then
  systemctl stop mnebydns-personal-sni-redirect.service
else
  # The proxy may have crashed while the NAT was left behind.
  if nat_present; then
    iptables -w -t nat -D PREROUTING "${NAT[@]}"
  fi
fi
! nat_present || { echo 'PERSONAL_SNI_WATCH_FALLBACK_INCOMPLETE'; exit 2; }
echo 'PERSONAL_SNI_WATCH=FELL_BACK_TO_UNCHANGED_CORE_DNS'
exit 0
