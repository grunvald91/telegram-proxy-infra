# Nodekit AWG egress service (FI staged-only)

This stage makes the previously proven temporary Internet/NAT path reproducible without enabling customers or altering permanent UFW configuration.

Files: nodekit/awg_egress.py and /etc/systemd/system/mnebyvpn-nodekit-awg-egress@.service.

## Operating gates

- Fleet bootstrap installs the egress code and systemd unit, but NEVER enables or starts it.
- Systemd Requires/BindsTo the node's AWG signed-access watchdog. The watchdog itself Requires the AWG server and a pinned trusted controller Ed25519 public key. Without that key and a live watchdog there is no public activation.
- Current subnet 10.73.91.0/24, port UDP/51821 and outbound eth0 are restricted to the verified isolated fi-test-01; other countries require their own reviewed IPAM and automated tests.
- When activated after controlled E2E and entitlement release, the egress unit inserts exact comment-scoped INPUT, FORWARD and MASQUERADE rules. It records original IPv4 forwarding state and restores it on stop.
- The unit stops when the watchdog stops. ExecStop and ExecStopPost both remove only owned firewall rules and restore the original forwarding setting. If cleanup is incomplete, it retains the root-only state for operator review.
- It does not modify /etc/ufw, permanent sysctl configuration, the default route, the DNS sidecar, or production 89/188 nodes.

## Verification

Offline test: python3 -m unittest discover -s nodekit/tests -v

Actions inventory-approved bootstrap installs egress without activation. Inspect mode reports network_enabled=false. Never run the up mode directly via SSH or an AI agent: release must follow verified client E2E, controller enrollment, signed and monitored lease grants, and explicit owner approval.

FI external proof: https://github.com/grunvald91/telegram-proxy-infra/actions/runs/44255522426
