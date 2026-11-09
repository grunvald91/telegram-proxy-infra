#!/usr/bin/env bash
set -Eeuo pipefail
chmod 0755 /opt/mnebydns-dot
chmod 0644 /opt/mnebydns-dot/Corefile
systemctl reset-failed mnebydns-dot.service
systemctl restart mnebydns-dot.service
systemctl is-active --quiet mnebydns-dot.service
