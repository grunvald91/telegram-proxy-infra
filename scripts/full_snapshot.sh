#!/usr/bin/env bash
set -euo pipefail

: "${SERVER188_HOST:?missing SERVER188_HOST}"
: "${RELAY89_HOST:?missing RELAY89_HOST}"
: "${SERVER188_PASSWORD:?missing SERVER188_PASSWORD}"
: "${RELAY89_PASSWORD:?missing RELAY89_PASSWORD}"

ROOT=/tmp/proxy-snapshot
OUT=legacy-mtproxy/live-snapshot
rm -rf "$ROOT"
mkdir -p "$ROOT/server188" "$ROOT/relay89"

ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)

collect_files() {
  local host="$1" pass="$2" target="$3" raw_list="$4"
  local one_line
  one_line="$(printf '%s\n' "$raw_list" | tr '\n' ' ')"
  export SSHPASS="$pass"
  # Fixed whitelist only. Globs are expanded by the remote shell.
  sshpass -e ssh "${ssh_opts[@]}" "root@$host"     "tar -czf - --ignore-failed-read $one_line 2>/dev/null"     | tar -xzf - -C "$target"
}

collect_state() {
  local host="$1" pass="$2" target="$3"
  export SSHPASS="$pass"
  mkdir -p "$target/runtime"
  sshpass -e ssh "${ssh_opts[@]}" "root@$host" 'bash -s'     > "$target/runtime/system-state.txt" <<'REMOTE'
set +e
echo "===== DATE ====="; date -Is
echo "===== HOST ====="; hostnamectl; uname -a; uptime
echo "===== ADDRESSES ====="; ip -brief address
echo "===== ROUTES ====="; ip -4 route; ip -6 route; ip rule
echo "===== LISTENERS ====="; ss -lntup
echo "===== PROXY PROCESSES ====="
ps -eo pid,ppid,user,comm,args | grep -Ei 'telemt|mtg|mtproxy|telegram|xray|wireguard|wg-quick|nfqws|zapret|nginx|caddy|redsocks|tinyproxy|docker' | grep -v grep
echo "===== SYSTEMD UNITS ====="
systemctl list-unit-files --no-pager | grep -Ei 'telemt|mtg|mtproxy|telegram|xray|wireguard|wg-quick|nfqws|zapret|nginx|caddy|redsocks|tinyproxy|docker'
echo "===== ACTIVE SERVICES ====="; systemctl --type=service --state=running --no-pager
echo "===== TIMERS ====="; systemctl list-timers --all --no-pager
echo "===== ROOT CRONTAB ====="; crontab -l 2>/dev/null
echo "===== CRON.D FILES ====="; find /etc/cron.d -maxdepth 1 -type f -print 2>/dev/null
echo "===== UFW ====="; ufw status verbose 2>/dev/null
echo "===== NFTABLES ====="; nft list ruleset 2>/dev/null
echo "===== IPTABLES ====="; iptables-save 2>/dev/null; ip6tables-save 2>/dev/null
echo "===== WIREGUARD ====="; wg show 2>/dev/null
echo "===== DOCKER ====="; docker ps -a --no-trunc --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null
echo "===== DOCKER COMPOSE ====="; docker compose ls 2>/dev/null
echo "===== PACKAGES ====="
dpkg-query -W -f='\${binary:Package}\t\${Version}\n' 2>/dev/null | grep -Ei 'telemt|wireguard|nginx|caddy|tinyproxy|redsocks|docker|iptables|nftables|xray|python|openssl'
echo "===== BINARY LOCATIONS ====="
for b in telemt mtg nginx caddy tinyproxy redsocks wg docker iptables nft; do command -v "$b" 2>/dev/null || true; done
echo "===== BINARY HASHES ====="
for b in /usr/bin/telemt /usr/local/bin/mtg /opt/xray/xray /opt/zapret2/nfqws2 /opt/caddy-pq/caddy /usr/sbin/nginx /usr/bin/tinyproxy /usr/sbin/redsocks; do
  [ -f "$b" ] && sha256sum "$b"
done
echo "===== RELEVANT FILE TREE ====="
find /etc/nginx /etc/telemt /etc/mtg /etc/zapret2 /etc/tinyproxy /etc/xray /etc/wireguard /opt/mtproto-canary \
     /root/proxy-backups /root/telemt-upgrades /root/proxy-hotfix-* /root/nginx-backup-* \
     -maxdepth 6 -printf '%y %m %u:%g %s %p\n' 2>/dev/null
exit 0
REMOTE
}

copy_binary() {
  local host="$1" pass="$2" target="$3" remote="$4" name="$5"
  export SSHPASS="$pass"
  mkdir -p "$target/binaries"
  echo "Trying binary $name from $host..."
  local size
  size="$(timeout 20s sshpass -e ssh "${ssh_opts[@]}" "root@$host" \
    "test -f '$remote' && stat -c %s '$remote' || echo 0" 2>/dev/null || echo 0)"
  if [[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -gt 0 ] && [ "$size" -le 25000000 ]; then
    if ! timeout 30s sshpass -e scp -q "${ssh_opts[@]}" "root@$host:$remote" "$target/binaries/$name"; then
      echo "Binary $name skipped after copy timeout/failure"
      rm -f "$target/binaries/$name"
    fi
  else
    echo "Binary $name absent or too large; skipped"
  fi
}

read -r -d '' FILES_188 <<'EOF' || true
/etc/nginx/nginx.conf
/etc/nginx/streams.d
/etc/nginx/conf.d
/etc/nginx/sites-enabled
/etc/systemd/system/telemt*.service
/etc/systemd/system/telemt*.service.d
/etc/systemd/system/mtproxy*.service
/etc/systemd/system/telegram*.service
/etc/systemd/system/caddy*.service
/etc/systemd/system/nginx.service.d
/etc/telemt
/etc/telegram-redsocks.conf
/etc/redsocks.conf
/etc/tinyproxy
/etc/wireguard
/etc/sysctl.d/99-telegram-proxy-keepalive.conf
/etc/sysctl.d/99-mtproxy-tuning.conf
/opt/mtproto-canary
/usr/local/sbin/mtproxy*
/usr/local/sbin/telegram*
/root/start-mtproxy.sh
/root/mtproxy-info.txt
/root/mtproxy-relay-links.txt
/root/proxy-backups
/root/telemt-upgrades
/root/proxy-hotfix-*
/root/nginx-backup-*
EOF

read -r -d '' FILES_89 <<'EOF' || true
/etc/nginx/nginx.conf
/etc/nginx/streams.d
/etc/nginx/conf.d
/etc/nginx/sites-enabled
/etc/systemd/system/mtg*.service
/etc/systemd/system/telemt*.service
/etc/systemd/system/telemt*.service.d
/etc/systemd/system/direct-mtproxy*.service
/etc/systemd/system/telegram*.service
/etc/systemd/system/xray.service
/etc/systemd/system/nginx.service.d
/etc/telemt
/etc/mtg
/etc/zapret2
/etc/xray/config.json
/etc/wireguard
/etc/sysctl.d/99-telegram-proxy-keepalive.conf
/etc/sysctl.d/99-mtproxy-tuning.conf
/usr/local/sbin/direct-mtproxy*
/usr/local/sbin/telegram*
/root/telemt-upgrades
/root/proxy-backups
/root/proxy-hotfix-*
/root/nginx-backup-*
EOF

echo "Collecting files from server188..."
collect_files "$SERVER188_HOST" "$SERVER188_PASSWORD" "$ROOT/server188" "$FILES_188"
echo "Collecting runtime state from server188..."
collect_state "$SERVER188_HOST" "$SERVER188_PASSWORD" "$ROOT/server188"

echo "Collecting files from relay89..."
collect_files "$RELAY89_HOST" "$RELAY89_PASSWORD" "$ROOT/relay89" "$FILES_89"
echo "Collecting runtime state from relay89..."
collect_state "$RELAY89_HOST" "$RELAY89_PASSWORD" "$ROOT/relay89"

copy_binary "$SERVER188_HOST" "$SERVER188_PASSWORD" "$ROOT/server188" /usr/bin/telemt telemt
copy_binary "$SERVER188_HOST" "$SERVER188_PASSWORD" "$ROOT/server188" /opt/caddy-pq/caddy caddy-pq
copy_binary "$RELAY89_HOST" "$RELAY89_PASSWORD" "$ROOT/relay89" /usr/bin/telemt telemt
copy_binary "$RELAY89_HOST" "$RELAY89_PASSWORD" "$ROOT/relay89" /usr/local/bin/mtg mtg
copy_binary "$RELAY89_HOST" "$RELAY89_PASSWORD" "$ROOT/relay89" /opt/zapret2/nfqws2 nfqws2
copy_binary "$RELAY89_HOST" "$RELAY89_PASSWORD" "$ROOT/relay89" /opt/xray/xray xray

python3 - <<'PY'
from pathlib import Path
import hashlib, re, shutil

srcroot=Path('/tmp/proxy-snapshot')
dstroot=Path('legacy-mtproxy/live-snapshot')
if dstroot.exists():
    shutil.rmtree(dstroot)

assign = re.compile(
    r'(?i)^(\s*[^#\n]*(?:secret|password|passwd|token|api[_-]?key|private[_-]?key|preshared[_-]?key|credential|uuid)[^=:\n]*\s*[=:]\s*).*$'
)
cli = re.compile(r'(?i)(--?secret|-S|--?password|--?token|--?uuid)\s+\S+')
uri_cred = re.compile(r'(?i)(https?://)[^/@\s:]+:[^/@\s]+@')
query_secret = re.compile(r'(?i)([?&](?:secret|token|key|password|uuid)=)[^&\s]+')
private_key_marker = re.compile(r'-----BEGIN (?:OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----')
long_hex = re.compile(r'\b[0-9a-fA-F]{32,}\b')
long_b64 = re.compile(r'(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{43,}={0,2}(?![A-Za-z0-9+/=_-])')

def sanitize(text):
    out=[]
    skip_private=False
    for line in text.splitlines():
        if private_key_marker.search(line):
            out.append('<PRIVATE_KEY_BLOCK_REDACTED>')
            skip_private=True
            continue
        if skip_private:
            if '-----END ' in line and 'PRIVATE KEY-----' in line:
                skip_private=False
            continue
        m=assign.match(line)
        if m:
            line=m.group(1)+'<REDACTED>'
        line=cli.sub(lambda m: m.group(1)+' <REDACTED>', line)
        line=uri_cred.sub(r'\1<REDACTED>@', line)
        line=query_secret.sub(r'\1<REDACTED>', line)
        line=long_hex.sub('<HEX_REDACTED>', line)
        line=long_b64.sub('<B64_REDACTED>', line)
        out.append(line)
    return '\n'.join(out)+'\n'

manifest=[]
for server in ('server188','relay89'):
    root=srcroot/server
    for p in sorted(root.rglob('*')):
        if not p.is_file():
            continue
        rel=p.relative_to(root)
        raw=p.read_bytes()
        dest=dstroot/server/rel
        lname=p.name.lower()
        forbidden=(
            lname.endswith(('.key','.pem','.p12','.pfx','.jks','.kdbx')) or
            lname in ('id_rsa','id_ed25519','shadow','gshadow') or
            'privatekey' in lname
        )
        if forbidden:
            manifest.append(f'{server}/{rel}|SECRET_FILE_SKIPPED|sha256={hashlib.sha256(raw).hexdigest()}|size={len(raw)}')
            continue
        if str(rel).startswith('binaries/'):
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(raw)
            manifest.append(f'{server}/{rel}|binary_saved|sha256={hashlib.sha256(raw).hexdigest()}|size={len(raw)}')
            continue
        try:
            text=raw.decode('utf-8')
        except UnicodeDecodeError:
            manifest.append(f'{server}/{rel}|binary_skipped|sha256={hashlib.sha256(raw).hexdigest()}|size={len(raw)}')
            continue
        clean=sanitize(text)
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_text(clean)
        manifest.append(
            f'{server}/{rel}|source_sha256={hashlib.sha256(raw).hexdigest()}|'
            f'sanitized_sha256={hashlib.sha256(clean.encode()).hexdigest()}|size={len(raw)}'
        )

dstroot.mkdir(parents=True,exist_ok=True)
(dstroot/'README.md').write_text(
    '# Full sanitized live snapshot\n\n'
    'Maximum practical backup of the Telegram/proxy infrastructure on both live hosts.\n'
    'Active and historical configs, units, scripts, runtime/network state and selected binaries are preserved.\n'
    'Passwords, SSH/private keys, TLS private keys, WireGuard private/preshared keys, proxy secrets, UUIDs and tokens are redacted or skipped.\n'
)
(dstroot/'MANIFEST.sha256.txt').write_text('\n'.join(manifest)+'\n')
PY

# Fail closed if obvious secret material remains.
python3 - <<'PY'
from pathlib import Path
import re, sys

root = Path('legacy-mtproxy/live-snapshot')
bad = []

private_marker = re.compile(r'-----BEGIN (?:OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----', re.I)
assignment = re.compile(
    r'(?i)^\s*([^#\n]*(?:private[_-]?key|preshared[_-]?key|password|passwd|secret|token|api[_-]?key|credential|uuid)[^=:\n]*)\s*[=:]\s*(.*?)\s*$'
)
allowed_prefixes = (
    '<REDACTED>',
    '<B64_REDACTED>',
    '<HEX_REDACTED>',
    '<PRIVATE_KEY_BLOCK_REDACTED>',
)

for p in root.rglob('*'):
    if not p.is_file() or p.name == 'MANIFEST.sha256.txt':
        continue
    try:
        text = p.read_text(errors='strict')
    except (UnicodeDecodeError, OSError):
        continue
    if private_marker.search(text):
        bad.append((p, 'private-key block'))
        continue
    for lineno, line in enumerate(text.splitlines(), 1):
        m = assignment.match(line)
        if not m:
            continue
        value = m.group(2).strip().strip('"\'')
        if value and not value.startswith(allowed_prefixes):
            bad.append((p, f'credential-like assignment at line {lineno}'))
            break

if bad:
    for p, why in bad:
        print(f'Possible unredacted secret in {p}: {why}', file=sys.stderr)
    sys.exit(1)
PY

# snapshot-trigger: v5
