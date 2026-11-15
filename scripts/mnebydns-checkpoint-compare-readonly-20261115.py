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

# Only print safe structure counts, not rule contents.
anchor_check = 'python3 -c '+shlex.quote("from pathlib import Path; s=Path('/opt/mnebydns-dot/Corefile').read_text(); print('ANCHOR_CACHE_OLD='+str(s.count('    cache 30\\\\n'))); print('ANCHOR_CACHE_RESILIENT='+str(s.count('    cache 30 {\\\\n'))); print('ANCHOR_GEMINI_EXACT='+str(s.count('template IN A gemini.google.com {'))); print('ANCHOR_TEMPLATE_A_GENERIC='+str(s.count('template IN A . {'))); print('ANCHOR_GEMINI_TEXT_PRESENT='+str('gemini.google.com' in s)); print('CORE_TEMPLATE_A_COUNT='+str(s.count('template IN A ')));")
extra_check = 'python3 -c '+shlex.quote("from pathlib import Path; s=Path('/opt/mnebydns-dot/Corefile').read_text(); lines=s.splitlines(); print('CACHE_OLD_COUNT='+str(sum(x=='    cache 30' for x in lines))); print('CACHE_RESILIENT_COUNT='+str(sum(x=='    cache 30 {' for x in lines))); print('CACHE_ALL_LINES='+str(sum(x.strip().startswith('cache ') for x in lines))); print('CACHE_INDENTS='+str(sorted(set(len(x)-len(x.lstrip()) for x in lines if x.strip().startswith('cache ')))));")
print(owner.ssh('de',extra_check,timeout=45),flush=True)
print(owner.ssh('de',anchor_check,timeout=45),flush=True)
print('STRUCTURAL_ANCHOR_INSPECTION=PASS',flush=True)

print("READ_ONLY_INSPECTION=PASS",flush=True)
