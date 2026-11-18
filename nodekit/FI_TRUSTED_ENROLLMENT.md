# FI Nodekit: private enrollment transport (not deployed)

New component: `nodekit/fi_enrollment_ssh.py`, a **FI-only OpenSSH forced-command target**. This is NOT a network listener and does not enable any VPN, CoreDNS, Nginx, SSH credentials or subscriptions.

## Trust chain

1. On a **separate trusted controller machine** keep the controller private Ed25519 signer in root-only storage, out of GitHub Actions, ChatGPT/agents and web workers. Independently approve SHA256 of the public 44-byte DER SPKI.
2. The Nodekit FI `controller-access.spki` file must contain precisely that **public** SPKI, be root-owned `0600` and independently approved. The FI node identity SHA256 remains `c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9` from reviewed `nodekit/fleet/fi.json`.
3. Create a **dedicated**, separately scoped SSH Ed25519 keypair for controller enrollment, distinct from operator/bootstrap and AWG delivery keys. Independently pin the FI sshd host public key (TOFU/accept-new is **not** acceptable). Ensure `/opt/mnebyvpn-nodekit/fi_enrollment_ssh.py` is root-owned, byte-for-byte reviewed, and cannot be modified by the SSH caller.
4. Install one restrictive `authorized_keys` entry, using the **independently approved real controller fingerprint** (not a placeholder), and no shell permission:

```text
restrict,command="/usr/bin/python3 /opt/mnebyvpn-nodekit/fi_enrollment_ssh.py --node-id fi-test-01 --expected-identity-sha256 c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9 --expected-controller-sha256 <APPROVED_64_CHAR_HEX>" ssh-ed25519 <VERIFIED_ENROLLMENT_SSH_PUBLIC_KEY> nodekit-fi-enrollment
```

5. **Separately** approve the actual FI node public SPKI (44 DER bytes) in the canonical PostgreSQL `vpn_node_enrollment_inventory`, status `approved`; no implicit approval from bootstrap or DNS. The trusted controller invokes `beginNodeEnrollment`, sends only a canonical controller-signed challenge on SSH stdin (`SSH_ORIGINAL_COMMAND=false`), validates the node-signed proof, and invokes `completeNodeEnrollment` to atomically consume the challenge.
6. Restrict the controller DB role to the enrollment inventory/challenge functions; isolate it from the public website. The registration remains status `enrolled` with **no subscriber publication**.

## Fail-closed behavior

- The handler rejects any non-FI node/host, a missing controller public key, mismatched independent SHA256, an expired challenge, an unsigned/tampered request, additional fields, incorrect root-only files, or any request not originating from the forced command with `SSH_ORIGINAL_COMMAND=false`.
- Controller and node identities are **different** Ed25519 keys. The node private key remains only in the root-owned FI identity directory; no private key is copied to GitHub, AI context, SSH stdout or PostgreSQL.
- A failed attempt does not mark the node enrolled; an unused challenge expires after five minutes. No automatic retry or silent re-approval is permitted.
- No public proxy, personal DoT, AWG peer, REALITY/VLESS profile or paid entitlement is opened by this enrollment step.

Node-side module and root ownership tests are offline only. Until separately pinned keys, a trusted controller host and production DB approval are provided, **do not run the enrollment**. See `nodekit/CONTROLLER_READINESS.md` and Mnebyvpn `docs/fi-controller-enrollment.md`.


## Security review 2026-11-18

The FI forced-command implementation now checks the private Nodekit stage root
and reads each sensitive file using a single `O_NOFOLLOW` file descriptor,
verifying its inode with `fstat` before reading. Symlink/fifo substitution
and unexpectedly large files are rejected. Duplicate keys in the incoming
signed JSON challenge are rejected rather than silently resolved by the JSON
parser. Tests cover a real Node.js↔Python canonical-message comparison as well
as Ed25519 challenge/proof signatures.

The script is **not** installed on the FI server by this review. Its
trusted-controller public key and the independent SSH host pin still require
operator-approved provisioning before real enrollment.
