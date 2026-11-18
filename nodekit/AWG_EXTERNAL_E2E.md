# Nodekit: external AmneziaWG 3.1 E2E canary

Workflow: .github/workflows/nodekit-fi-awg-external-e2e.yml (manual dispatch).

The temporary test is ONLY for the unpublished FI node fi.mnebyvpn.site (217.11.167.91). It does not touch current clients, other countries, or the existing Smart DNS ingress.

## Safeguards

- Build pinned official AmneziaWG v3.1 userspace client on an ephemeral GitHub-hosted runner.
- Generate the test client's private key only on that runner. Copy to server only the public key. Read server peer material via SSH into a mode 0600 temporary file, without logging it.
- Before touching the host network, arm a server-local systemd timer for independent TTL cleanup.
- Insert exact, comment-marked ephemeral iptables rules: UDP/51821 INPUT from the runner's SSH public IP; bidirectional forwarding between awg0 and eth0 ONLY for 10.73.91.2/32; IPv4 masquerade ONLY for that test IP.
- Do not alter permanent UFW settings, customer routes, or any default route. Restore original net.ipv4.ip_forward.
- Verify encrypted AWG handshake, tunnel ICMP, and HTTPS egress returning 217.11.167.91. Such a test does NOT validate mobile-provider reachability, congestion, or exit-country geolocation.
- On normal finish or error: remove runner AWG interface, temporary routes and remote server AWG; delete only our four exact firewall rules; clear temporary state. The on-VPS timer remains a backup on cancellation.

## Rollout gates

No server is published or clients provisioned by this workflow. After successful FI E2E, review persistent and idempotent UFW/NAT configuration, independently check actual exit country, register the controller Ed25519 public key, test signed grant and revoke with lease watchdog, and only then allow subscription publication.

Security caveat: the current FI test workflow inherits the existing SSH password/accept-new (TOFU) exception. New-country workflows must use pinned host keys, per-country secrets and reviewed inventory. No GitHub test runner receives the controller signing private key.

Upstreams: https://github.com/amnezia-vpn/amneziawg-go and https://github.com/amnezia-vpn/amneziawg-tools
