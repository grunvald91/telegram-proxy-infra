#!/usr/bin/env bash
# Repeatable non-disruptive host preparation. No application deployment or network changes.
set -Eeuo pipefail
umask 027
say() { printf '%s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }
state() { systemctl is-active "$1" 2>/dev/null || true; }
[ "$(id -u)" = 0 ] || die "Requires root via existing SSH channel"
. /etc/os-release
[ "$ID" = ubuntu ] && [ "$VERSION_ID" = 24.04 ] || die "Unexpected OS: $PRETTY_NAME"
[ "$(nproc)" -ge 2 ] || die "Resize CPU not applied"
mem_kib=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
[ "$mem_kib" -ge 3500000 ] || die "Resize memory not applied"
free_kib=$(df -Pk / | awk 'END {print $4}')
[ "$free_kib" -ge 20000000 ] || die "Less than 20 GiB free disk space"
command -v docker >/dev/null || die "Existing Docker not found; refuse to change installation"
[ "$(state docker)" = active ] || die "Existing Docker is not active"
say "=== BEFORE ==="
say "UTC=$(date -u +%FT%TZ)"
say "HOST=$(hostname)"
say "CPU=$(nproc) RAM_KiB=$mem_kib DISK_AVAILABLE_KiB=$free_kib"
docker --version
docker compose version || true
services=(docker telemt telemt-yandex telemt-gosuslugi tinyproxy redsocks nginx)
declare -A initial
for svc in "${services[@]}"; do
  initial["$svc"]="$(state "$svc")"
  say "before.$svc=${initial[$svc]}"
done
mtg_before=$(docker inspect --format '{{.State.Running}}' mtproto-proxy 2>/dev/null || true)
say "before.mtproto_proxy_running=$mtg_before"
if [ -e /opt/mnebyvpn ] && [ ! -f /opt/mnebyvpn/.mnebyvpn-prepared ]; then
  if [ -n "$(find /opt/mnebyvpn -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    die "/opt/mnebyvpn already contains unknown data"
  fi
fi
say "=== PACKAGES ==="
packages=(ca-certificates curl git jq rsync unzip)
missing=()
for pkg in "${packages[@]}"; do
  dpkg -s "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
done
need_compose=0
docker compose version >/dev/null 2>&1 || need_compose=1
if [ "${#missing[@]}" -gt 0 ] || [ "$need_compose" = 1 ]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  if [ "$need_compose" = 1 ]; then
    if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
      missing+=(docker-compose-v2)
    elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
      missing+=(docker-compose-plugin)
    else
      die "No distribution Docker Compose V2 package; Docker left unchanged"
    fi
  fi
  apt-get install -y --no-install-recommends "${missing[@]}"
  say "installed_packages=${missing[*]}"
else
  say "All deployment CLI packages already installed"
fi
docker compose version || die "Docker Compose V2 unavailable"
docker info >/dev/null || die "Docker daemon not responsive"
say "=== PREPARE ISOLATED DIRECTORIES ==="
getent group mnebyvpn >/dev/null || groupadd --system mnebyvpn
if ! id -u mnebyvpn >/dev/null 2>&1; then
  useradd --system --gid mnebyvpn --home-dir /opt/mnebyvpn --no-create-home --shell /usr/sbin/nologin mnebyvpn
fi
[ "$(id -gn mnebyvpn)" = mnebyvpn ] || die "Unexpected mnebyvpn primary group"
[ "$(getent passwd mnebyvpn | cut -d: -f7)" = /usr/sbin/nologin ] || die "Unexpected mnebyvpn login shell"
install -d -o root -g root -m 0755 /opt/mnebyvpn
install -d -o root -g mnebyvpn -m 0750 /opt/mnebyvpn/releases /opt/mnebyvpn/shared
install -d -o root -g root -m 0700 /opt/mnebyvpn/secrets /opt/mnebyvpn/backups
install -d -o root -g mnebyvpn -m 0750 /etc/mnebyvpn
install -d -o mnebyvpn -g mnebyvpn -m 0750 /var/lib/mnebyvpn
touch /opt/mnebyvpn/.mnebyvpn-prepared
chown root:root /opt/mnebyvpn/.mnebyvpn-prepared
chmod 0644 /opt/mnebyvpn/.mnebyvpn-prepared
say "=== AFTER ==="
for svc in "${services[@]}"; do
  current="$(state "$svc")"
  say "after.$svc=$current"
  if [ "${initial[$svc]}" = active ] && [ "$current" != active ]; then
    die "Previously active service changed state: $svc"
  fi
done
mtg_after=$(docker inspect --format '{{.State.Running}}' mtproto-proxy 2>/dev/null || true)
say "after.mtproto_proxy_running=$mtg_after"
if [ "$mtg_before" = true ] && [ "$mtg_after" != true ]; then
  die "Existing mtproto-proxy container is no longer running"
fi
for path in /opt/mnebyvpn/releases /opt/mnebyvpn/shared /opt/mnebyvpn/secrets /opt/mnebyvpn/backups /etc/mnebyvpn /var/lib/mnebyvpn; do
  stat -c '%A %U:%G %n' "$path"
done
say "LISTENING_TCP_PORTS="
ss -ltnH | awk '{print $4}' | sort -u
say "mnebyvpn_host_prepared=yes"
say "mnebyvpn_application_installed=no"
say "mnebyvpn_ports_modified=no"
