# FI217 Smart DNS — signed per-client admission, first data-plane stage

Status 2026-11-23: **pure code + offline tests; NOT installed/started on FI217,
NOT a public DNS service.** This stage directly addresses the missing
personal authorization confirmed by live read-only [FI audit
45222896888](https://github.com/grunvald91/telegram-proxy-infra/actions/runs/45222896888).
The FI Nodekit candidate currently contains **zero signed DNS/SNI routes**
and its TLS stage does not prove wildcard coverage.

## Components

- `fi_dns_signed_grants.py`: verifies an Ed25519-signed RU188 snapshot with
  independent pinned controller SPKI SHA-256. Snapshots are bound to
  `fi-test-01` + `FI`, ordered by monotonically increasing revision, fresh
  within 120 seconds, with entitlement UUID, credential revision, hashed
  country-bound 12-character SNI bearer, grant state and expiry. The digest is
  identical to `Mnebyvpn/packages/dns-policy/src/regional-personal-dot-identity.ts`:
  `SHA256("MNEBYVPN_COUNTRY_DNS_V1\\0FI\\0" + label)`. The raw bearer label
  **must never be exported from RU188** by the snapshot issuer.
- `fi_dns_guarded_ingress.py`: a separate **loopback-only** TCP/TLS
  passthrough candidate on `127.0.0.1:18853`. It parses bounded, fragmented
  ClientHello, requires exact `<12>.fi.dns.mnebyvpn.site` SNI and a fresh
  signed active grant before connecting to loopback `127.0.0.1:8853`
  CoreDNS. It does not terminate/decrypt TLS; transport remains end-to-end
  between Android and CoreDNS. Each connection stops at earliest grant or
  snapshot expiry, with bounds for concurrent sessions and handshake time.
  The service independently checks the CoreDNS origin has a valid trusted CA
  chain **and actual `*.fi.dns.mnebyvpn.site` wildcard SAN**, not merely the
  `fi.mnebyvpn.site` certificate. A malformed/missing snapshot fails closed.
- It opens **no public listener**, publishes no personal hostname, creates no
  DNS policy and does not touch AWG, DE89, RU188, VPN subscribers or payments.

### Controller signing transcript

Ed25519 over the UTF-8 compact JSON array, no extra whitespace:

```json
["MNEBYVPN_REGIONAL_DNS_SNAPSHOT_V1","fi-test-01","FI",revision,"issuedAt","validUntil",[["entitlementId",credentialRevision,"tokenSha256","expiresAt","ACTIVE|REVOKED"]]]
```

For more than one grant, rows are sorted by increasing token digest. The
snapshot envelope contains exactly
`schemaVersion,nodeId,countryCode,revision,issuedAt,validUntil,grants,signature`.
`issuedAt`, `validUntil` and `expiresAt` are canonical UTC milliseconds.
`signature` is canonical unpadded base64url Ed25519 (64 bytes).

This **wire format alone is not issuance**. The RU188 trusted grant issuer must
read canonical paid/trial entitlement state and latest revocation/rotation,
assemble the snapshot, sign it using the existing root-only controller key,
transmit it over independently pinned authenticated transport to FI, and
atomically replace a root-owned snapshot at increasing revision. No duplicate
controller or secrets in GitHub Actions. Fresh policy is required at most
every 60 seconds; a stale snapshot expires by 120 seconds.

### Hard release blockers

1. DNS-01 issuance of a **separate** CA-verified
   `*.fi.dns.mnebyvpn.site` certificate and matching scoped wildcard DNS A
   record pointed only to FI217; existing `*.dns.mnebyvpn.site` keys and
   certificates are not modified. Validate against two distinct labels.
2. A trusted RU188 signer/transport and durable monotonic rollback prevention
   on FI, with signed per-entitlement grants, rotation, refund/revoke, restart
   recovery and controller-loss behavior.
3. Production quota: the ingress currently checks **TCP connection admission,
   not each DNS query**. RU188's real query reservation/settlement and any
   cached reply counting MUST be implemented before subscriber publication.
4. A reviewed CoreDNS resolver, controller-signed SNI domain routing and
   verified Finnish egress for mapped destinations. Zero routes are not
   equivalent to working Smart DNS. No uncontrolled DNS redirect or open
   resolver.
5. Controlled per-service TCP/853 publication with rollback, external Android
   Private DNS CA/SNI/query tests, unknown/revoked/expired bearer denials,
   Google/YouTube sustained playback, long-lived connection expiry, renewal
   and failover tests on FI217.

**Do not run `--mode serve` as a production service**, expose
`127.0.0.1:8853` or `18853` publicly, or claim FI Smart DNS is ready
based on unit tests. Next is controller-bound signer + signed local grant
staging and TLS/DNS-01 preparation. Telegram Telemt remains a separate
unreleased FI priority after Smart DNS.


## Security review: signed policy freshness and live revocation

The initial signed ingress had three serious staging issues now corrected:

- Previously, an already admitted TLS socket was **not rechecked** after an
  RU188 snapshot revoke. A quiet connection could remain open until the
  original snapshot expiry. A single shared, short-lived signed-policy cache
  now revalidates every active socket at most every 3 seconds (plus up to
  1 second cache age); missing or invalid refreshed policy closes the stream.
  Policy renewal keeps the same authenticated Android TLS socket alive rather
  than forcing a disconnect every 120 seconds.
- A revision downgrade check existed only in process memory. A root-owned
  `dns-auth/snapshot-highwater.json` now persists the largest verified
  signed revision and its canonical transcript SHA-256 across restart. It
  rejects an older revision **or different data at the same revision**.
  The file is updated atomically with fsync before allowing new traffic.
  Its parent directory must already be root-owned and not group-accessible;
  the process never repairs unknown filesystem state by deleting the fence.
  Destruction of this root-only file by a compromised root user remains out
  of scope and should be monitored independently.
- FI DNS signature/file checks imported an AWG/VPN module unnecessarily.
  The DNS reader now independently verifies root ownership, permissions,
  symlink exclusion and file size; a broken AWG import cannot prevent
  DNS-specific verification.

With up to 2048 individual entitlement grants, the signed JSON may exceed
440 KB. The root-only snapshot size bound has been raised to 700 KB, with
the same 2048-entry, strict schema and signature validation.

This **does not** make FI217 Smart DNS ready. No production signed snapshot
writer, durable protected delivery, paid per-query reserve/settle, wildcard
certificate, published listener or Android external E2E is supplied by this
review. No systemd service or DNS port is installed by these changes.
