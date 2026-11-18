#!/usr/bin/env bash
# Only PUBLIC FI/RU188 enrollment keys; no subscriber or service activation.
# Credentials are taken from the existing node-fi GitHub environment.
set -Eeuo pipefail
umask 077
[[ "$FI_USER" == root && -n "$FI_PASSWORD" && -n "$RU_PASSWORD" ]] || {
  echo 'FI_PUBLIC_STAGE_CREDENTIALS_UNAVAILABLE' >&2; exit 2;
}
[[ -d "$RUNNER_TEMP" ]] || exit 2
command -v sshpass >/dev/null
grep -q '^188\.120\.254\.223 ssh-ed25519 ' ops/mnebydns-owner-ssh-known_hosts
work="$(mktemp -d "$RUNNER_TEMP/fi-public-key-stage.XXXXXXXX")"
known="$work/fi-known-host"
ru_opts=(-F /dev/null -o ConnectTimeout=12 -o BatchMode=no
  -o PasswordAuthentication=yes -o PubkeyAuthentication=no
  -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes
  -o HostKeyAlgorithms=ssh-ed25519
  -o "UserKnownHostsFile=$PWD/ops/mnebydns-owner-ssh-known_hosts"
  -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no
  -o ForwardAgent=no -o ClearAllForwardings=yes -o ControlMaster=no
  -o ProxyCommand=none -o LogLevel=ERROR)
ru() { SSHPASS="$RU_PASSWORD" sshpass -e ssh -T "${ru_opts[@]}" root@188.120.254.223 "$@"; }
ruscp() { SSHPASS="$RU_PASSWORD" sshpass -e scp "${ru_opts[@]}" "$@"; }

# Pull no private key from RU188; read only root-protected PUBLIC material.
ru 'python3 -' > "$work/controller.json" <<'PY'
import base64,hashlib,json,pathlib,stat
root=pathlib.Path('/root/mnebyvpn-controller')
def read(name,limit):
    p=root/name
    s=p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077 or not 1<=s.st_size<=limit:
        raise SystemExit('Unsafe root-owned public controller key')
    return p.read_bytes()
controller=read('controller-public.spki',100)
if (len(controller)!=44 or
    hashlib.sha256(controller).hexdigest()!='e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844'):
    raise SystemExit('Unapproved controller SPKI')
public_ssh=read('fi-enrollment-ssh.pub',512)
print(json.dumps({'controller':base64.b64encode(controller).decode(),
                  'ssh_pub':base64.b64encode(public_ssh).decode()},separators=(',',':')))
PY
python3 - "$work" <<'PY'
import base64,hashlib,json,os,pathlib
root=pathlib.Path(__import__('sys').argv[1])
data=json.loads((root/'controller.json').read_text())
if set(data)!={'controller','ssh_pub'}:raise SystemExit('Unexpected controller payload')
public=base64.b64decode(data['controller'],validate=True)
ssh=base64.b64decode(data['ssh_pub'],validate=True)
if (len(public)!=44 or
    hashlib.sha256(public).hexdigest()!='e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844' or
    not ssh.startswith(b'ssh-ed25519 ') or b'\n' in ssh.strip()):
    raise SystemExit('Unapproved controller public inputs')
for name,value in (('controller.spki',public),('fi-enrollment-ssh.pub',ssh)):
    fd=os.open(root/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as out:out.write(value)
PY

# RU188 persisted host pin already exists. Do not accept-new on CI runner.
ru 'python3 - --country fi --node-id fi-test-01 --ip 217.11.167.91' \
  < nodekit/fleet_host_trust.py > "$known"
test "$(wc -l < "$known")" = 1
grep -q '^217\.11\.167\.91 ssh-ed25519 ' "$known"
fi_opts=(-F /dev/null -o ConnectTimeout=12 -o BatchMode=no
  -o PasswordAuthentication=yes -o PubkeyAuthentication=no
  -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes
  -o HostKeyAlgorithms=ssh-ed25519 -o "UserKnownHostsFile=$known"
  -o GlobalKnownHostsFile=/dev/null -o UpdateHostKeys=no
  -o ForwardAgent=no -o ClearAllForwardings=yes -o ControlMaster=no
  -o ProxyCommand=none -o HostKeyAlias=217.11.167.91 -o LogLevel=ERROR)
fi_remote() { SSHPASS="$FI_PASSWORD" sshpass -e ssh -T "${fi_opts[@]}" root@217.11.167.91 "$@"; }
fiscp() { SSHPASS="$FI_PASSWORD" sshpass -e scp "${fi_opts[@]}" "$@"; }
fi_dir=''
ru_dir=''
cleanup(){
  if [[ "$fi_dir" =~ ^/root/fi-public-stage\.[A-Za-z0-9]{8}$ ]]; then
    fi_remote "rm -rf -- '$fi_dir'" >/dev/null 2>&1 || true
  fi
  if [[ "$ru_dir" =~ ^/root/fi-public-stage\.[A-Za-z0-9]{8}$ ]]; then
    ru "rm -rf -- '$ru_dir'" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT

fi_dir="$(fi_remote 'umask 077; mktemp -d /root/fi-public-stage.XXXXXXXX')"
[[ "$fi_dir" =~ ^/root/fi-public-stage\.[A-Za-z0-9]{8}$ ]] || exit 2
handler_sha="$(sha256sum nodekit/fi_enrollment_ssh.py | cut -d' ' -f1)"
fiscp nodekit/fi_public_enrollment_stage.py nodekit/fi_enrollment_ssh.py \
  "$work/controller.spki" "$work/fi-enrollment-ssh.pub" \
  "root@217.11.167.91:$fi_dir/"
fi_remote "chmod 600 '$fi_dir'/* && python3 '$fi_dir/fi_public_enrollment_stage.py' \
  --role fi --mode stage --controller-spki '$fi_dir/controller.spki' \
  --enrollment-ssh-public '$fi_dir/fi-enrollment-ssh.pub' \
  --handler-source '$fi_dir/fi_enrollment_ssh.py' --handler-sha256 '$handler_sha'"

# Read FI identity ONLY as public DER, checked against previously reviewed SHA.
fi_remote 'python3 -' > "$work/fi-public-base64" <<'PY'
import base64,hashlib,pathlib,stat
p=pathlib.Path('/var/lib/mnebyvpn-nodekit/fi-test-01/identity/node-public.spki')
s=p.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_mode&0o077 or s.st_size!=44:
    raise SystemExit('Untrusted FI node public key')
blob=p.read_bytes()
if hashlib.sha256(blob).hexdigest()!='c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9':
    raise SystemExit('FI node key does not match committed inventory')
print(base64.b64encode(blob).decode())
PY
python3 - "$work" <<'PY'
import base64,hashlib,os,pathlib,sys
root=pathlib.Path(sys.argv[1])
public=base64.b64decode((root/'fi-public-base64').read_text().strip(),validate=True)
if (len(public)!=44 or
    hashlib.sha256(public).hexdigest()!='c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9'):
    raise SystemExit('FI public node key mismatch')
fd=os.open(root/'fi-node.spki',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
with os.fdopen(fd,'wb') as out:out.write(public)
PY
cp "$known" "$work/fi_host_known_hosts"
ru_dir="$(ru 'umask 077; mktemp -d /root/fi-public-stage.XXXXXXXX')"
[[ "$ru_dir" =~ ^/root/fi-public-stage\.[A-Za-z0-9]{8}$ ]] || exit 2
ruscp nodekit/fi_public_enrollment_stage.py \
  "$work/fi-node.spki" "$work/fi_host_known_hosts" \
  "root@188.120.254.223:$ru_dir/"
ru "chmod 600 '$ru_dir'/* && python3 '$ru_dir/fi_public_enrollment_stage.py' \
  --role controller --mode stage --fi-node-public '$ru_dir/fi-node.spki' \
  --fi-host-pin '$ru_dir/fi_host_known_hosts'"

# End-to-end idempotent, PUBLIC-only postchecks on both real hosts.
fi_remote "python3 '$fi_dir/fi_public_enrollment_stage.py' --role fi --mode check \
  --controller-spki '$fi_dir/controller.spki' \
  --enrollment-ssh-public '$fi_dir/fi-enrollment-ssh.pub' \
  --handler-source '$fi_dir/fi_enrollment_ssh.py' --handler-sha256 '$handler_sha'"
ru "python3 '$ru_dir/fi_public_enrollment_stage.py' --role controller --mode check \
  --fi-node-public '$ru_dir/fi-node.spki' --fi-host-pin '$ru_dir/fi_host_known_hosts'"
echo 'FI_PUBLIC_TRUST_STAGED=true'
echo 'FI_DB_ENROLLMENT_STARTED=false'
echo 'FI_CLIENTS_PUBLISHED=false'
echo 'FI_AWG_DNS_TELEMT_NOT_MODIFIED=true'
