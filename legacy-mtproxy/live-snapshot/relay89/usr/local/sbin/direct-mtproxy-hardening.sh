#!/usr/bin/env bash
set -euo pipefail

for spec in "tcp 9443:9445" "tcp 9091:9093"; do
  proto=${spec%% *}
  ports=${spec#* }
  iptables -C INPUT -i eth0 -p "$proto" -m multiport --dports "$ports" -j DROP 2>/dev/null || \
    iptables -I INPUT 1 -i eth0 -p "$proto" -m multiport --dports "$ports" -j DROP
  ip6tables -C INPUT -i eth0 -p "$proto" -m multiport --dports "$ports" -j DROP 2>/dev/null || \
    ip6tables -I INPUT 1 -i eth0 -p "$proto" -m multiport --dports "$ports" -j DROP
done

# The two-hop MTProto endpoint is reachable only from the Russian ingress over WireGuard.
iptables -C INPUT -i tg-relay -s <REDACTED> -d 10.66.77.1/32 -p tcp --dport 9464 -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -i tg-relay -s <REDACTED> -d 10.66.77.1/32 -p tcp --dport 9464 -j ACCEPT
iptables -C INPUT -p tcp --dport 9464 -j DROP 2>/dev/null || \
  iptables -A INPUT -p tcp --dport 9464 -j DROP
ip6tables -C INPUT -p tcp --dport 9464 -j DROP 2>/dev/null || \
  ip6tables -A INPUT -p tcp --dport 9464 -j DROP

iptables -C INPUT -s <REDACTED> -p udp --dport 51820 -j ACCEPT 2>/dev/null || \
  iptables -I INPUT 1 -s <REDACTED> -p udp --dport 51820 -j ACCEPT
iptables -C INPUT -p udp --dport 51820 -j DROP 2>/dev/null || \
  iptables -A INPUT -p udp --dport 51820 -j DROP
ip6tables -C INPUT -p udp --dport 51820 -j DROP 2>/dev/null || \
  ip6tables -A INPUT -p udp --dport 51820 -j DROP
