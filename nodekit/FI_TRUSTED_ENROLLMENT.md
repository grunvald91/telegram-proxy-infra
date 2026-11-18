# FI Nodekit: private enrollment transport (not deployed)

New component: `nodekit/fi_enrollment_ssh.py`, a **FI-only OpenSSH forced-command target**. This is NOT a network listener and does not enable any VPN, CoreDNS, Nginx, SSH credentials or subscriptions.

## Trust chain

1. On the **existing MNEBYVPN central controller 188.120.254.223**, in a
   segregated root-only directory outside web/bot/worker permissions, keep the controller private Ed25519 signer in root-only storage, out of GitHub Actions, ChatGPT/agents and web workers. Independently approve SHA256 of the public 44-byte DER SPKI.
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


## Existing authority, not a new server

The controller is RU188 (`188.120.254.223`), not FI, DE89 or a newly
commissioned host. This Nodekit handler merely verifies a controller-signed
challenge and signs a one-time proof; it is not a Telegram proxy.
Telegram proxy means Telemt MTProto, and is an independently provisioned
per-customer component. See [CONTROLLER188_TELEGRAM_PROXY.md](CONTROLLER188_TELEGRAM_PROXY.md).

## Безручной SSH preflight для FI (18.11.2026)

Обновлённый `.github/workflows/fi-enrollment-trust-preflight-readonly.yml` автоматически получает и сохраняет первый Ed25519 SSH host key FI на **существующем RU188** посредством `nodekit/fleet_host_trust.py` по SSH-каналу, уже закреплённому для RU188. Никакого ручного ввода `NODEKIT_SSH_KNOWN_HOSTS` не требуется: если он заранее задан и проверен, его ключ дополнительно должен совпасть.

После сохранения pin CI использует `StrictHostKeyChecking=yes` для входа в FI, проверяет ожидаемый Nodekit Ed25519 public SPKI SHA-256 и manifest, выводит только публичные признаки готовности. Не создаёт `authorized_keys`, не вносит регистрацию в PostgreSQL, не запускает AWG delivery и не открывает клиентский доступ. Ошибка/недоступность FI приводит к провалу проверки; не трактовать это как успешное развёртывание.

**TOFU не является криптографическим подтверждением идентичности на первом соединении:** возможна первоначальная подмена SSH-хоста. Для production-замены VPS и выдачи клиентских подписок рекомендуется API attestation провайдера и подписание Nodekit challenge. Это автоматизируемые проверки, а не ручная процедура.

## Ревью автоматизации: контроль fail-closed

Если для FI задан независимо одобренный публичный host key, он валидируется **до** фиксации первого ключа на RU188; несовпадение не загрязняет хранилище доверия. Для тестового FI обязательны root-owned защищённые каталоги и файлы Nodekit, точный `fi-test-01` / `fi.mnebyvpn.site`, состояние `testing`, а также `registration_enabled=false` и `activation_enabled=false`. Любое отклонение завершает job ошибкой, а не успешным отчётом. Отсутствие `controller-access.spki` пока отражается как отдельная незавершённая стадия регистрации, не как доступ клиента.
