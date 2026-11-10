# MNEBYDNS: research domain inventory, 2026-11-10

This is an extraction from the user-supplied Russian-language study, **not a measured, independently verified blocklist**. The material mentions a 700k+ domestic-blocklist and a ~2,194-record foreign geoblock list but does not enumerate those complete lists. This extracted catalog has **523** valid-looking explicit domain literals, after removing **29** obvious merged-word artifacts / file names, and is not a claim that all 523 endpoints are currently blocked.

- `data/mnebydns-geoblock-research-20261110.tsv`: all 523 names with context and classification.
- `scripts/mnebydns-geoblock-research-queue-20261110.sql`: idempotent **506 PENDING research candidates**, preserving existing statuses and revisions. Other 17 include informational source domains, generic/wildcard geo-zones, shared apex hosts, per-URL-only cases, and the datacenter-IP-only Pinata note.
- `PENDING` **does not** configure DNS/proxy. Each exact host must pass the existing independent RU→DE / CoreDNS / TLS and rollback gate before the owner initiates canary and confirmation.
- The caller's intent is to eventually support these services; this import does not assert success. In particular do not bulk-wildcard `google.com`, `microsoft.com`, `amazon.com`, `bing.com`, `nvidia.com`; shared products/services need host-level proof.
- `rkn_or_mixed` marks domains also cited in the study's Russian domestic filter discussion. The remaining labels are **claims of the supplied document**, not confirmation of geopolicy, service availability, or current restrictions.

## Additional verification sources

- https://github.com/dartraiden/no-russia-hosts (foreign services' access restrictions; warns that split IPs inside one session can break web apps)
- https://github.com/itdoginfo/allow-domains (separates Russia-inside, geoblock and Russia-outside)
- https://github.com/Noktomezo/RussiaFancyLists (distinguishes state blacklist and foreign geoblock)

No external community list has been imported into the 523-entry user-research snapshot.
