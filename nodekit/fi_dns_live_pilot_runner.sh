#!/usr/bin/env bash
# Run one loopback canary on FI. The current listener and RU billing are untouched.
set -Eeuo pipefail
umask 077
[[ "$FI_USER" == root && -n "$RU_PASSWORD" && -n "$FI_PASSWORD" ]]
work=$(mktemp -d "$RUNNER_TEMP/fi-dns-live.XXXXXXXX")
stage="/run/fi-dns-pilot-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
[[ "$stage" =~ ^/run/fi-dns-pilot-[0-9]+-[0-9]+$ ]]
created=no
common=(-F /dev/null -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null
  -o HostKeyAlgorithms=ssh-ed25519 -o UpdateHostKeys=no -o ForwardAgent=no
  -o ClearAllForwardings=yes -o ControlMaster=no -o PubkeyAuthentication=no
  -o PreferredAuthentications=password -o ConnectTimeout=12 -o LogLevel=ERROR)
fi_opts=("${common[@]}" -o "UserKnownHostsFile=$work/fi-known" -o HostKeyAlias=fi.mnebyvpn.site)
fi_node() { SSHPASS="$FI_PASSWORD" sshpass -e ssh -T "${fi_opts[@]}" root@217.11.167.91 "$@"; }
cleanup() {
  if [[ "$created" == yes ]]; then
    fi_node "rm -rf -- '$stage'" >/dev/null 2>&1 || echo 'FI_LIVE_PILOT_CLEANUP_UNCONFIRMED=true'
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT
sudo apt-get update -qq
sudo apt-get install -y -qq --no-install-recommends sshpass >/dev/null
grep -q '^188\.120\.254\.223 ssh-ed25519 ' ops/mnebydns-owner-ssh-known_hosts
SSHPASS="$RU_PASSWORD" sshpass -e ssh -T "${common[@]}" -o "UserKnownHostsFile=$PWD/ops/mnebydns-owner-ssh-known_hosts" root@188.120.254.223 \
  'p=/root/mnebyvpn-controller/fi-known_hosts; test -f "$p" && test ! -L "$p" && test "$(stat -c %u:%a "$p")" = 0:600 && cat "$p"' > "$work/fi-known"
python3 - "$work/fi-known" <<'PY'
import base64
from pathlib import Path
import sys

data = Path(sys.argv[1]).read_bytes()
assert len(data) < 512 and data.count(b"\n") == 1 and data.endswith(b"\n")
name, kind, key = data.decode("ascii").strip().split()
assert (name, kind) == ("fi.mnebyvpn.site", "ssh-ed25519")
raw = base64.b64decode(key, validate=True)
assert len(raw) == 51 and raw.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20")
PY
python3 -B nodekit/fi_dns_pilot_build.py nodekit "$work/runtime"
fi_node "umask 077; mkdir -m 0700 '$stage'; mkdir -m 0700 '$stage/runtime'"
created=yes
SSHPASS="$FI_PASSWORD" sshpass -e scp "${fi_opts[@]}" "$work/runtime/"*.py "root@217.11.167.91:$stage/runtime/"
SSHPASS="$FI_PASSWORD" sshpass -e scp "${fi_opts[@]}" nodekit/fi_dns_live_pilot_probe.py "root@217.11.167.91:$stage/"
fi_node "systemctl is-active --quiet mnebyvpn-fi-dns-country.service mnebyvpn-fi-public-dot.socket &&
  PYTHONPATH='$stage/runtime' timeout --kill-after=5s 55s python3 -B '$stage/fi_dns_live_pilot_probe.py' '$stage'"

# Independently check that an unentitled TLS connection to the public socket
# still gets no DNS reply after the loopback canary.
python3 - <<'PY'
import secrets
import socket
import ssl
import struct

name = secrets.token_hex(6) + ".fi.mnebyvpn.site"
query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
with socket.create_connection((name, 853), timeout=8) as raw:
    with ssl.create_default_context().wrap_socket(raw, server_hostname=name) as tls:
        tls.sendall(struct.pack("!H", len(query)) + query)
        if tls.recv(2) != b"":
            raise SystemExit("FI_PUBLIC_DNS_UNENTITLED_QUERY_ACCEPTED")
print("FI_PUBLIC_DNS_UNENTITLED_DENIAL_REVERIFIED=true")
PY
