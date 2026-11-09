#!/usr/bin/env bash
set -Eeuo pipefail
cmp -s /opt/mnebydns-stable-checkpoints/42541741159/dns.stable /opt/mnebydns-dot/Corefile
chmod 0755 /opt/mnebydns-dot
chmod 0644 /opt/mnebydns-dot/Corefile
systemctl reset-failed mnebydns-dot.service
systemctl restart mnebydns-dot.service
systemctl is-active --quiet mnebydns-dot.service

ss -H -lnt 'sport = :853' | grep -Fq ':853'
echo 'stable_DoT853_repaired=true'
