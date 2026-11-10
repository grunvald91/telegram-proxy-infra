#!/usr/bin/env bash
# One-shot, source-IP-scoped RU TCP/18443 field reachability check.
# Script runs only via approved operator SSH. Never modifies public HTTPS/443.
set -Eeuo pipefail
[[ "$(id -u)" == 0 && $# -eq 2 ]] || { echo "usage: root script CLIENT_IPV4 RUN_ID" >&2; exit 2; }
CLIENT="$1"; RUN_ID="$2"; SERVER="188.120.254.223"; PORT=18443
[[ "$RUN_ID" =~ ^[0-9]{8,16}$ ]] || { echo "invalid run ID" >&2; exit 2; }
python3 - "$CLIENT" "$SERVER" <<'PY'
import ipaddress,sys
c,s=(ipaddress.IPv4Address(x) for x in sys.argv[1:])
if not c.is_global or not s.is_global or c==s:
    raise SystemExit("distinct global IPv4 required")
PY
for bin in iptables ss systemd-run systemctl python3 timeout; do command -v "$bin" >/dev/null; done
if ss -H -lnt "sport = :18443" | grep -q .; then echo "ru_ingress_port_occupied=true"; exit 3; fi
IPTABLES_BIN="$(type -P iptables)"
TAG="MNEBYDNS_IG_REACH_${RUN_ID}"
UNIT="mnebydns-ig-reach-${RUN_ID}"
RULE=(-s "$CLIENT/32" -d "$SERVER" -p tcp --dport "$PORT" -m comment --comment "$TAG" -j ACCEPT)
if iptables -w -C INPUT "${RULE[@]}" 2>/dev/null; then echo "ru_ingress_stale_rule=true"; exit 3; fi
if systemctl is-active --quiet "${UNIT}.timer"; then echo "ru_ingress_stale_timer=true"; exit 3; fi
cleanup() {
    iptables -w -D INPUT "${RULE[@]}" 2>/dev/null || true
}
trap cleanup EXIT
# Independent timer is installed before the temporary INPUT permission.
ROLLBACK="$IPTABLES_BIN -w -D INPUT -s $CLIENT/32 -d $SERVER -p tcp --dport $PORT -m comment --comment $TAG -j ACCEPT 2>/dev/null || true"
systemd-run --quiet --collect --unit "$UNIT" --on-active=70s /usr/bin/bash -c "$ROLLBACK"
iptables -w -I INPUT 1 "${RULE[@]}"
echo "ru_ingress_scope=runner_ipv4_only"
echo "ru_ingress_rollback_timer=armed"
# No application data is read, no connection details printed.
timeout 35s python3 -u - "$SERVER" "$PORT" <<'PY'
import socket,sys
host=sys.argv[1]
port=int(sys.argv[2])
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server:
    server.bind((host,port))
    server.listen(3)
    server.settimeout(29)
    print("ru_ingress_listener=READY",flush=True)
    conn,addr=server.accept()
    with conn:
        conn.settimeout(3)
        conn.sendall(b"MNEBYDNS_INGRESS_READY\n")
    print("ru_ingress_accepted_external_tcp=true",flush=True)
PY
echo "ru_ingress_probe=FINISHED"
