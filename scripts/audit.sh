#!/usr/bin/env bash
set -u

section() { printf '\n===== %s =====\n' "$1"; }

section "HOST"
hostnamectl 2>/dev/null || true
uname -a 2>/dev/null || true
printf '\nUptime:\n'
uptime 2>/dev/null || true

section "OS"
cat /etc/os-release 2>/dev/null || true

section "RESOURCES"
free -h 2>/dev/null || true
df -hT 2>/dev/null || true

section "LISTENERS"
ss -lntup 2>/dev/null || ss -lntp 2>/dev/null || true

section "PROXY-RELATED PROCESSES"
ps auxww 2>/dev/null | grep -Ei 'mtproxy|telegram|tproxy|proxy|v2ray|xray|nginx|caddy|haproxy' | grep -v grep || true

section "SYSTEMD UNITS"
systemctl list-units --type=service --all --no-pager 2>/dev/null | grep -Ei 'mtproxy|telegram|tproxy|proxy|v2ray|xray|nginx|caddy|docker' || true

section "ENABLED UNITS"
systemctl list-unit-files --type=service --no-pager 2>/dev/null | grep -Ei 'mtproxy|telegram|tproxy|proxy|v2ray|xray|nginx|caddy|docker' || true

section "DOCKER"
docker ps --no-trunc 2>/dev/null || true
docker compose ls 2>/dev/null || true

section "FIREWALL-UFW"
ufw status verbose 2>/dev/null || true

section "FIREWALL-NFT"
nft list ruleset 2>/dev/null || true

section "IPTABLES"
iptables -S 2>/dev/null || true
ip6tables -S 2>/dev/null || true

section "CADDY"
caddy version 2>/dev/null || true
systemctl status caddy --no-pager --full 2>/dev/null | head -80 || true

section "NGINX"
nginx -v 2>&1 || true
systemctl status nginx --no-pager --full 2>/dev/null | head -80 || true

section "CANDIDATE FILES"
for root in /etc /opt /srv /usr/local /root /home; do
  [ -d "$root" ] || continue
  find "$root" -maxdepth 4 -type f \(     -iname '*mtproxy*' -o     -iname '*tproxy*' -o     -iname '*telegram*proxy*' -o     -iname '*docker-compose*.yml' -o     -iname '*docker-compose*.yaml' -o     -iname 'compose.yml' -o     -iname 'compose.yaml'   \) 2>/dev/null
done

section "IMPORTANT"
echo "Audit only. No services were changed."
echo "Do NOT paste secret values, private keys, or full .env contents into chat or Git."
