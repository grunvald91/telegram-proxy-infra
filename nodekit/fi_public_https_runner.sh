#!/usr/bin/env bash
# Stage external HTTPS with customer DNS issuance closed.
set -Eeuo pipefail
umask 077
[[ "$FI_USER" == root && -n "$RU_PASSWORD" && -n "$FI_PASSWORD" ]]
work=$(mktemp -d "$RUNNER_TEMP/fi-public-https.XXXXXXXX")
stage="/run/fi-public-https-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
[[ "$stage" =~ ^/run/fi-public-https-[0-9]+-[0-9]+$ ]]
created=no
verified=no
common=(-F /dev/null -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null
  -o HostKeyAlgorithms=ssh-ed25519 -o UpdateHostKeys=no -o ForwardAgent=no
  -o ClearAllForwardings=yes -o ControlMaster=no -o PubkeyAuthentication=no
  -o PreferredAuthentications=password -o ConnectTimeout=12 -o LogLevel=ERROR)
fi_opts=("${common[@]}" -o "UserKnownHostsFile=$work/fi-known" -o HostKeyAlias=fi.mnebyvpn.site)
fi_node() { SSHPASS="$FI_PASSWORD" sshpass -e ssh -T "${fi_opts[@]}" root@217.11.167.91 "$@"; }
cleanup() {
  if [[ "$created" == yes && "$verified" != yes ]]; then
    if ! fi_node "bash '$stage/stage.sh' rollback '$stage'"; then
      echo FI_PUBLIC_HTTPS_ROLLBACK_UNCONFIRMED=true
      return
    fi
  fi
  if [[ "$created" == yes ]]; then
    fi_node "rm -rf -- '$stage'" >/dev/null 2>&1 || echo FI_PUBLIC_HTTPS_CLEANUP_UNCONFIRMED=true
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
python3 -B nodekit/fi_public_https_probe.py
fi_node "umask 077; mkdir -m 0700 '$stage'"
created=yes
SSHPASS="$FI_PASSWORD" sshpass -e scp "${fi_opts[@]}" nodekit/fi_public_https_relay.py nodekit/systemd/fi-public-https/* "root@217.11.167.91:$stage/"
SSHPASS="$FI_PASSWORD" sshpass -e scp "${fi_opts[@]}" nodekit/fi_public_https_stage.sh "root@217.11.167.91:$stage/stage.sh"
fi_node "timeout --kill-after=15s 90s bash '$stage/stage.sh' stage '$stage'"
python3 -B nodekit/fi_public_https_probe.py https
fi_node "timeout --kill-after=15s 60s bash '$stage/stage.sh' commit '$stage'"
verified=yes
