# Nodekit: external AmneziaWG 3.1 E2E canary

Workflow: `.github/workflows/nodekit-fi-awg-external-e2e.yml` (run on reviewed main-branch workflow changes, or manual dispatch). Pull requests run offline checks only.

The temporary test is ONLY for the unpublished FI node fi.mnebyvpn.site (217.11.167.91). It does not touch current clients, other countries, or the existing Smart DNS ingress.

## Safeguards

- Build pinned official AmneziaWG v3.1 userspace client on an ephemeral GitHub-hosted runner.
- Generate the test client's private key only on that runner. Copy to server only the public key. Read server peer material via SSH into a mode 0600 temporary file, without logging it.
- Before touching the host network, arm a server-local systemd timer for independent TTL cleanup.
- Insert exact, comment-marked ephemeral iptables rules: UDP/51821 INPUT from the runner's SSH public IP; bidirectional forwarding between awg0 and eth0 ONLY for 10.73.91.2/32; IPv4 masquerade ONLY for that test IP.
- Do not alter permanent UFW settings, customer routes, or any default route. Restore original net.ipv4.ip_forward.
- Verify encrypted AWG handshake, the average tunnel ICMP round-trip time, bidirectional encrypted tunnel counters, and HTTPS egress returning 217.11.167.91; record HTTPS request time. Such a test does NOT validate mobile-provider reachability, congestion, or exit-country geolocation.
- On normal finish or error: remove runner AWG interface, temporary routes and remote server AWG; delete only our four exact firewall rules; clear temporary state. Assert the original IPv4 forwarding state is restored, the temporary AWG interface and timer are absent, and no marked firewall rules remain. The on-VPS timer remains a backup on cancellation.

## Rollout gates

No server is published or clients provisioned by this workflow. After successful FI E2E, review persistent and idempotent UFW/NAT configuration, independently check actual exit country, register the controller Ed25519 public key, test signed grant and revoke with lease watchdog, and only then allow subscription publication.

Security caveat: this temporary FI workflow still uses existing GitHub-managed SSH passwords, but it obtains an independently pinned FI host identity through pinned RU188 SSH and requires strict host-key checking (not TOFU). New-country workflows must use separately reviewed host identities, per-country secrets and inventory. No GitHub test runner receives the controller signing private key.

Upstreams: https://github.com/amnezia-vpn/amneziawg-go and https://github.com/amnezia-vpn/amneziawg-tools
