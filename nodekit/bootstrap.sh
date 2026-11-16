#!/usr/bin/env bash
# v1: preflight/stage only; no package installation, service changes or registration.
set -Eeuo pipefail
umask 077
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [[ $# -ne 2 ]]; then
  echo 'Usage: bash nodekit/bootstrap.sh preflight|stage /root/private-node-spec.json' >&2
  exit 2
fi
case "$1" in preflight|stage) mode="$1";; *) echo 'Invalid mode' >&2; exit 2;; esac
spec="$2"
[[ -f "$spec" && ! -L "$spec" ]] || { echo 'Missing or symlinked spec' >&2; exit 2; }
exec python3 "$DIR/nodekit.py" "$mode" --spec "$spec"
