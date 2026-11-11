#!/usr/bin/env bash
# Owner-approved global IPv4 TCP443 SYNACK window experiment; independent rollback.
# Does not change DNS, Nginx, service processes or TLS payload.
set -Eeuo pipefail
TABLE="mneby_ig_w4_20261111"
UNIT="mneby-ig-w4-20261111"
DE="89.125.90.101"
[[ "$EUID" == 0 ]] || { echo 'de_global_abort=NOT_ROOT'; exit 2; }
[[ "$MNEBY_IG_GLOBAL_APPROVED" == YES ]] || { echo 'de_global_abort=NOT_APPROVED'; exit 2; }
for cmd in nft systemctl systemd-run ip ss; do command -v "$cmd" >/dev/null; done
for svc in nginx.service mnebydns-dot.service; do
    systemctl is-active --quiet "$svc" || { echo "de_global_abort=SERVICE_NOT_READY"; exit 1; }
done
ip -4 -o addr show | grep -F " $DE/" >/dev/null || { echo 'de_global_abort=WRONG_HOST'; exit 1; }
if nft list table inet "$TABLE" >/dev/null 2>&1; then
    echo 'de_global_abort=EXPERIMENT_TABLE_ALREADY_PRESENT'
    exit 1
fi
if systemctl is-active --quiet "$UNIT.timer"; then
    echo 'de_global_abort=PRIOR_TIMER_ACTIVE'
    exit 1
fi
if nft list ruleset | grep -Fq 'MNEBY_IG_GLOBAL_WIN4'; then
    echo 'de_global_abort=OTHER_TEST_ACTIVE'
    exit 1
fi
read -r -d '' RULES <<'NFT' || true
add table inet mneby_ig_w4_20261111
add chain inet mneby_ig_w4_20261111 output { type filter hook output priority mangle; policy accept; }
add rule inet mneby_ig_w4_20261111 output ip saddr 89.125.90.101 tcp sport 443 tcp flags & (syn | ack) == (syn | ack) counter tcp window set 4 comment "MNEBY_IG_GLOBAL_WIN4"
NFT
printf '%s\n' "$RULES" | nft --check -f -
echo 'de_global_nft_syntax_verified=true'
# Arm independent cleanup BEFORE any change to the running nft ruleset.
systemd-run --quiet --collect --unit "$UNIT" --on-active=90s \
    /usr/bin/python3 -c 'import subprocess; subprocess.run(["/usr/sbin/nft","delete","table","inet","mneby_ig_w4_20261111"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)'
systemctl is-active --quiet "$UNIT.timer" || { echo 'de_global_abort=NO_ROLLBACK_TIMER'; exit 1; }
echo 'de_global_independent_rollback_armed=true'
cleanup(){
    set +e
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
        nft delete table inet "$TABLE"
    fi
    if nft list table inet "$TABLE" >/dev/null 2>&1; then
        echo 'de_global_cleanup=FAIL'
        return 1
    fi
    echo 'de_global_cleanup=PASS'
}
trap cleanup EXIT
printf '%s\n' "$RULES" | nft -f -
nft -a list table inet "$TABLE" | grep -Fq 'MNEBY_IG_GLOBAL_WIN4'
echo 'de_global_tcp_window4=ACTIVE'
sleep 35
SNAPSHOT="$(nft -a list table inet "$TABLE")"
COUNT="$(printf '%s\n' "$SNAPSHOT" | sed -nE 's/.*counter packets ([0-9]+) bytes.*/\1/p' | head -n 1)"
if [[ -z "$COUNT" ]]; then COUNT=UNKNOWN; fi
echo "de_global_matched_synack_packets=$COUNT"
echo 'de_global_transport_only_no_android_e2e=true'
cleanup
trap - EXIT
systemctl is-active --quiet nginx.service
systemctl is-active --quiet mnebydns-dot.service
echo 'de_global_production_services_preserved=true'
