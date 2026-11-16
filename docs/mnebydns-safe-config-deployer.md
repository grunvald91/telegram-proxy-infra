# MNEBYDNS: safe production configuration deployment

## Status — 16 November 2026

The safe deployment manager is **installed** on DE89 (`89.125.90.101`) at
`/opt/mnebydns-maintenance/mnebydns_safe_deploy.py`, with
`mnebydns_nov8_restore_safety.py` in the same private directory.

One-time installation: [GitHub Actions 43896197941](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43896197941).
The installation **did not alter live CoreDNS or Nginx configuration**. Its
read-only status check confirmed that the DNS (TCP853), shared HTTPS (TCP443)
and GooglePilot (TCP15449) services were active.

The 8 November Google configuration restoration was previously applied:
[Actions 43888040399](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43888040399).
The CoreDNS permissions incident caused by that historical, unsafe restore
was separately fixed and DoT service state verified:
[Actions 43891571867](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/43891571867).

**Do not rerun the historical restoration workflow.** It is archived.

## Allowlisted configuration files

| Name | On-server path | Activation |
|---|---|---|
| `dns` | `/opt/mnebydns-dot/Corefile` | Restart `mnebydns-dot.service`, verify TCP853 |
| `shared` | `/etc/nginx/nginx.conf` | `nginx -t`, reload `nginx.service`, verify TCP443 |
| `pilot` | `/etc/mnebydns-googlepilot/nginx.conf` | `nginx -t -c`, reload local GooglePilot Nginx, verify TCP15449 |

The manager does not accept paths for subscriber data, certificates,
VPN configurations, keys or other services.

## Read-only status

Run from an authorized GitHub Actions job over the configured authenticated
SSH connection:

```bash
python3 -B /opt/mnebydns-maintenance/mnebydns_safe_deploy.py status
```

Output contains file hashes, POSIX owner/group/mode and service/listener
states. It does **not** contain any subscriber secrets or config content.

## How a future approved change is staged

A reviewed job prepares a *private, root-owned* directory
`/opt/mnebydns-maintenance/stage/<deployment-id>/` (mode 0700).
Only files explicitly being changed are included, each named
`dns.new`, `shared.new` or `pilot.new`.

`manifest.json` in the same directory (version 1) contains both the
**independently reviewed** SHA256 of the already installed live file and the
SHA256 of the proposed candidate. Example structure:

```json
{
  "version": 1,
  "id": "approved-update-20261116",
  "files": {
    "dns": {
      "expected_sha256": "<64 lowercase hexadecimal characters>",
      "candidate_sha256": "<64 lowercase hexadecimal characters>"
    }
  }
}
```

Do not substitute a freshly computed live hash for independent source
review: the current revision must be pinned *before* deployment.
Do not commit a full private Corefile or subscriber-specific configuration
into GitHub. Stage candidate data privately over the approved SSH channel.

The approved GitHub Actions job then invokes:

```bash
python3 -B /opt/mnebydns-maintenance/mnebydns_safe_deploy.py apply approved-update-20261116
```

The deployer refuses unrecognized paths, mismatching hashes, symlinks and
unowned staging directories. It holds the existing
`/run/lock/mnebyvpn-public-route.lock` throughout. Files are replaced
atomically, **preserving uid/gid/mode/xattrs (including ACL xattrs)**.

If no data would change, it returns a no-op and does not restart services.

## Rollback and reboot

Before the first production write the tool saves original bytes and metadata
under `/var/lib/mnebydns-safe-deploy/<transaction-id>/` and arms an
eight-minute **persistent systemd calendar watchdog**. If a deployment fails
or is interrupted, the rollback procedure restores only files that still
match exactly this deployment's own staged hashes and metadata. It refuses
to overwrite any intervening third-party change.

After service/listener and config-hash checks succeed, a durable
`COMMITTED` marker is written before disarming the watchdog. A watchdog
invoked after commit cannot undo that deployment.

This design is tested with independent offline unit tests, including failed
activation, concurrent edits, metadata preservation, symlink rejection and
no-op operation.

## Safety and limitations

- The code was deployed to DE89; it was *not* applied to RU188.
- Installing the deployer did not change Google routes or users' DNS access.
- Testing service state and TCP listeners does not prove YouTube video playback
  on a specific phone/network or uninterrupted reachability for every Google
  product.
- The historical 8 November snapshot covers specific Google names and domain
  families. It cannot prove coverage of every possible Google-related host.
- Existing hand-written GitHub Actions deployments must be updated separately
  to call the new manager before they receive its rollback safeguards.
- Future rollouts should have a reviewed, pinned candidate and an explicit
  workflow; **do not run unreviewed configuration transactions**.
