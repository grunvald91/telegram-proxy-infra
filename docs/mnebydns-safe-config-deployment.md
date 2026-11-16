# MNEBYDNS safe configuration releases (16 November 2026)

## Production status and provenance

The safe deployment coordinator was installed on the DE89 node in GitHub Actions
[run 43896959363](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43896959363).
Its installation changed only files in /opt/mnebydns-maintenance, not the active
CoreDNS, shared Nginx, or GooglePilot configurations.

As reported by that run, all three services were active and their TCP listeners
were present; the CoreDNS reader group invariant was explicitly checked. This
does not prove end-user YouTube playback.

The 8 November historic Google policy was previously restored selectively from
backup /opt/mnebydns-googlepilot-backups/42519046699. The historical eight Google
DNS families are still represented in the expanded policy; static parity audit:
[43893827715](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43893827715).

## Architecture

The canonical source files are:

- scripts/mnebydns_safe_deploy.py -- entrypoint
- scripts/mnebydns_nov8_restore_safety.py -- audited safety primitives
- scripts/test_mnebydns_safe_deploy.py and scripts/test_mnebydns_nov8_restore_safety.py
  -- isolated regression tests

Production installation:

- /opt/mnebydns-maintenance/mnebydns_safe_deploy.py
- /opt/mnebydns-maintenance/mnebydns_nov8_restore_safety.py
- /opt/mnebydns-maintenance/stage -- private candidate staging area
- /var/lib/mnebydns-safe-deploy -- private transaction recovery checkpoints

Never use the archived 2026-11-16 one-time Google restorer again. It was
deliberately disabled after its review.

## Release contract

For a future owner-approved configuration modification:

1. Work through GitHub Actions, not manual copy/paste by the customer.
2. Derive candidate config files from the *current* on-server files without
   exporting personal DNS records, credentials, or subscriber data to logs.
3. Stage a private root-owned directory:
   /opt/mnebydns-maintenance/stage/<release-id> with mode 0700.
4. Include manifest.json with:
   - version: 1
   - id: the directory name (lowercase alphanumeric / hyphens)
   - files: dictionary with keys only among dns, shared and pilot
   - per changed file, expected_sha256 of the current on-node file and
     candidate_sha256 of its proposed replacement
5. Put candidate files beside the manifest using names dns.new, shared.new
   and/or pilot.new. Content is hashed again before deployment; symlinks and
   non-root/private stage folders are rejected.
6. Invoke the installed command via an authorized, reviewed GitHub Actions
   workflow only after the new release and its scope have been reviewed.

Example manifest structure (example hashes are placeholders and must never be used
as real deployment approval):

    {
      "version": 1,
      "id": "google-policy-update",
      "files": {
        "dns": {
          "expected_sha256": "<current-sha256>",
          "candidate_sha256": "<new-sha256>"
        }
      }
    }

The status command is read-only and may be called to collect live source hashes
and service/listener status. It is not a media playback test.

## Safety invariants

- The same /run/lock/mnebyvpn-public-route.lock guards release/rollback and
  existing owner-domain changes.
- The approved bytes are verified before any mutation, including against
  concurrent config drift.
- Original owner, restricted group, mode, and extended attributes are preserved.
  CoreDNS Corefile must be root-owned, mode 0640, and readable by
  mnebydns-corefile-readers via its DynamicUser supplementary group.
- Recovery backups live in the private transaction directory and preserve
  original config bytes plus file metadata.
- An independent systemd OnCalendar timer with Persistent=true and retry
  cadence is activated **before** editing production.
- If post-apply service/listener checks fail, rollback applies only to bytes
  belonging to that transaction. It will **not** overwrite intervening edits.
- COMMITTED is durable and checked by recovery. A completed release cannot be
  reverted by its obsolete watchdog.
- No-op candidates do not create timers, checkpoints, or reload services.
- DNS, GooglePilot, and shared Nginx checks are distinguished from user-side
  YouTube or other Google service behavior.

## Verified offline regressions

GitHub Actions: [successful 32-case full audit run](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43896052432).
The main-branch pull request should also pass the isolated offline CI workflow.
No user needs to run commands manually.

## Known boundary

The coordinator installs safe **future changes**, not a second DNS rollback.
Release automation still needs a specifically reviewed candidate and its pinned
manifest; successful installation alone does not justify changing DNS rules.


---

## Review remediation: version 3 (16 Nov 2026)

The v3 coordinator replaces the unsafe default CoreDNS \`systemctl restart\`
on normal configuration changes with a verified, PID-preserving CoreDNS reload.
It refuses a DNS config release without \`reload 5s 1s\` and the compiled reload
plugin. Starting a stopped CoreDNS instance is only permitted as an emergency
rollback recovery, never as the normal config-update path.

Before applying a Corefile change, the coordinator parses the complete old and
candidate sets of DNS templates. In the default \`additive\` scope it refuses
deletion or modification of any existing template, including personalized DNS
access. A proposed Google-specific change requires an explicit
\`"scope": "google"\` in the DNS manifest and still protects non-Google templates
and TLS/bind/import/forward/reload directives. Hash pinning alone does not waive
these checks.

The coordinator also verifies protected Google, YouTube and other existing
AI/social service A-record routes via CA-validated DNS-over-TLS before and after
a DNS release and after a DNS rollback. A service active flag is not proof of
DNS answer correctness. These checks occur **only when actually changing DNS**,
not on a regular status request.

Legacy owner-domain canary additions, removals and their independent rollback
continue using the established owner timer/DB confirmation flow, but their
actual Nginx and CoreDNS file swaps now invoke the shared v3
\`owner-publish\` path. That path uses the same compare-and-swap,
owner/group/mode/xattrs preserving atomic writer and refuses other intervening
edits. Its calling shell holds the existing global route lock.

A durable COMMITTED marker is written **before** disabling the recovery timer.
If disabling the timer fails, the already committed release is still successful:
any subsequently triggered recovery checks COMMITTED and performs no rollback.
The warning must be retained as \`watchdog_disarmed: false\`.

**Verification limitations:** offline CI exercises simulated interrupted releases
and rollback behavior, not a live VPS reboot or end-user media playback.
The production v3 installation only updates the maintenance scripts, never the
current CoreDNS configuration, Nginx routes, certificates or subscriber records.


### 16 Nov 2026 stable-checkpoint reconciliation

The historic Google DNS recovery changed two live config hashes (CoreDNS and
GooglePilot), while the former stable-checkpoint pointer still referenced the
pre-recovery hashes. This blocked otherwise safe owner-domain workflows.

[Run 43904037640](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43904037640)
verified that the live configuration was exactly the previously reviewed
Google restoration, all three listeners/services were healthy and no sensitive
rollback timer was outstanding.

[Run 43904288633](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43904288633)
atomically advanced only the stable-checkpoint pointer from `1794809391` to
`1794845357`. All DNS/Nginx/GooglePilot configuration bytes and customer
credentials were unchanged. The previous checkpoint remains available.

[Run 43905222328](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43905222328)
validated the exact Oracle owner-route dry-run against the reconciled baseline.
The original CoreDNS main-zone insertion location is now selected relative to
the unique Gemini template and the first subsequent cache within that same
zone, avoiding a false failure when a separate Google zone also contains a
cache directive. Already installed exact owner domains are recognized and not
re-added.

One-time reconciliation and read-only probe workflows were retired after
success. Operational policy changes still use the root-owned, hash-pinned
maintenance manager and preserve the personal routes.
