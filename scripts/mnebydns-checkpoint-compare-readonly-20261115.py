#!/usr/bin/env python3
"""Read-only safe checkpoint audit, using the existing verified owner SSH helper."""
import importlib.util
import pathlib
import shlex

p=pathlib.Path(__file__).resolve().parent/"mnebydns-owner-domain-controller-20261110.py"
spec=importlib.util.spec_from_file_location("owner",p)
owner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)

# Run only stat and cmp. Do not copy or print configuration contents.
cmd=(
  "set -eu; "
  "root=$(cat /opt/mnebydns-stable-checkpoints/current); "
  "test -d \"$root\"; "
  "(cd \"$root\" && sha256sum -c stable-manifest.sha256 >/dev/null) && "
  "echo CHECKPOINT_INTEGRITY=PASS || echo CHECKPOINT_INTEGRITY=FAIL; "
  "for item in "
  "'CoreDNS|dns.stable|/opt/mnebydns-dot/Corefile' "
  "'Nginx-main|nginx.stable|/etc/nginx/nginx.conf' "
  "'Nginx-proxy|proxy.stable|/etc/mnebydns-googlepilot/nginx.conf'; do "
  "IFS='|' read -r label snap live <<EOF\n$item\nEOF\n"
  "if ! test -f \"$root/$snap\" || ! test -f \"$live\"; then "
  "echo \"$label=MISSING\"; "
  "elif cmp -s \"$root/$snap\" \"$live\"; then "
  "echo \"$label=MATCH\"; "
  "else echo \"$label=DIFFERENT\"; fi; done"
)
print(owner.ssh("de",cmd,timeout=45),flush=True)
print("READ_ONLY_INSPECTION=PASS",flush=True)
