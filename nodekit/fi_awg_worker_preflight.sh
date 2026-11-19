#!/usr/bin/env bash
# RU188-only, READ-ONLY inventory of FI217 AWG delivery worker prerequisites.
# Deliberately never creates approval marker, starts services, writes files or
# touches customer subscriptions. Prints only bounded status labels.
set -Eeuo pipefail

ROOT=/root/mnebyvpn-controller
CURRENT=/opt/mnebyvpn-controller/current
UNIT=/etc/systemd/system/mnebyvpn-awg-delivery.service
CONTROLLER_SHA=e4c862bd0171e5be4ae64770a555029e090d3a8fcfa5ef2a82ffb0b798552844
NODE_SHA=c3689b687e8888d15e3ece8e45cf7d01672b9dadb77b1963a7871ffd8e967ed9
failed=0

check() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    printf 'FI_AWG_PREFLIGHT_%s=OK\n' "$label"
  else
    printf 'FI_AWG_PREFLIGHT_%s=BLOCKED\n' "$label"
    failed=$((failed + 1))
  fi
}
is_ru188() {
  [[ "$(id -u)" == 0 ]] &&
    hostname -I | tr ' ' '\n' | grep -Fxq 188.120.254.223
}
private_file() {
  local path="$1" mode
  [[ -f "$path" && ! -L "$path" ]] || return 1
  mode=$(stat -c '%u:%a' -- "$path") || return 1
  [[ "$mode" == 0:600 || "$mode" == 0:400 ]]
}
pinned_spki() {
  local path="$1" sha="$2" got
  private_file "$path" || return 1
  got=$(sha256sum -- "$path" | cut -d' ' -f1) || return 1
  [[ "$got" == "$sha" ]]
}
canonical_env() {
  local path="$ROOT/config/awg-delivery.env"
  private_file "$path" &&
    grep -Fxq 'MNEBYVPN_ENV=production' "$path" &&
    grep -Fxq 'MNEBYVPN_AWG_DELIVERY_WORKER=enabled' "$path" &&
    grep -Fxq "AWG_CONTROLLER_PUBLIC_SHA256=$CONTROLLER_SHA" "$path" &&
    grep -Fxq "AWG_CONTROLLER_SIGNING_KEY_FILE=$ROOT/controller-signing-key.pem" "$path" &&
    grep -Fxq "AWG_CONTROLLER_SSH_IDENTITY_FILE=$ROOT/awg-delivery-ssh" "$path" &&
    grep -Fxq "AWG_CONTROLLER_SSH_KNOWN_HOSTS_FILE=$ROOT/awg-delivery-known_hosts" "$path" &&
    grep -Eq '^DATABASE_URL=postgresql://mnebyvpn_awg_delivery:[a-f0-9]{64}@127\.0\.0\.1:55433/mnebyvpn_stage$' "$path"
}
signing_key_matches() {
  local key="$ROOT/controller-signing-key.pem" digest
  private_file "$key" || return 1
  digest=$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1) || return 1
  [[ "$digest" == "$CONTROLLER_SHA" ]]
}
ssh_delivery_ready() {
  private_file "$ROOT/awg-delivery-ssh" &&
    private_file "$ROOT/awg-delivery-known_hosts" &&
    private_file "$ROOT/fi-known_hosts" &&
    cmp -s -- "$ROOT/awg-delivery-known_hosts" "$ROOT/fi-known_hosts" &&
    [[ "$(wc -l < "$ROOT/awg-delivery-known_hosts")" -eq 1 ]] &&
    grep -Eq '^fi\.mnebyvpn\.site ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' "$ROOT/awg-delivery-known_hosts"
}
gateway_and_release_safe() {
  local actual
  actual=$(/usr/bin/docker exec -i mnebyvpn-stage-postgres \
    psql -X -q -At -v ON_ERROR_STOP=1 -U mnebyvpn_stage -d mnebyvpn_stage \
    -c "SELECT (SELECT status FROM public.vpn_node_enrollment_inventory WHERE node_id='fi-test-01'),(SELECT enabled::text FROM public.vpn_release_flags WHERE feature='vpn_awg_clients'),(to_regprocedure('public.awg_worker_lock_node(text)') IS NOT NULL)::text;" 2>/dev/null) || return 1
  [[ "$actual" == 'enrolled|false|true' ]]
}
worker_stopped() {
  local state
  state=$(systemctl show -p ActiveState --value mnebyvpn-awg-delivery.service) || return 1
  [[ "$state" == inactive ]]
}
worker_disabled() {
  local state
  state=$(systemctl is-enabled mnebyvpn-awg-delivery.service 2>/dev/null) || {
    [[ "$state" == disabled ]] && return 0
    return 1
  }
  [[ "$state" == disabled || "$state" == static ]]
}
approval_absent() {
  [[ ! -e "$ROOT/approvals/awg-delivery.enable" &&
     ! -L "$ROOT/approvals/awg-delivery.enable" ]]
}
worker_source_staged() {
  [[ -f "$CURRENT/apps/service/src/awg-controller-delivery-worker.ts" &&
     -f "$CURRENT/packages/provisioning/src/awg-trusted-ssh-delivery.ts" &&
     -f "$CURRENT/packages/provisioning/src/awg-offline-maintenance.ts" ]]
}
runtime_staged() {
  [[ -x "$CURRENT/bin/node" &&
     -f "$CURRENT/node_modules/pg/lib/index.js" ]]
}
unit_staged() {
  [[ -f "$UNIT" && ! -L "$UNIT" ]] &&
    grep -Fq 'ConditionPathExists=/root/mnebyvpn-controller/approvals/awg-delivery.enable' "$UNIT" &&
    grep -Fq 'ExecStart=/opt/mnebyvpn-controller/current/bin/node ' "$UNIT"
}

# Verify host before any access to protected controller assets.
if ! is_ru188; then
  echo 'FI_AWG_PREFLIGHT_HOST=BLOCKED'
  exit 2
fi
echo 'FI_AWG_PREFLIGHT_HOST=OK'

check CONTROLLER_IDENTITY pinned_spki "$ROOT/controller-public.spki" "$CONTROLLER_SHA"
check FI_NODE_IDENTITY pinned_spki "$ROOT/fi-node-public.spki" "$NODE_SHA"
check CANONICAL_WORKER_ENV canonical_env
check SIGNER_PRIVATE_KEY signing_key_matches
check FORCED_SSH_TRANSPORT ssh_delivery_ready
check POSTGRES_GATEWAY_AND_RELEASE gateway_and_release_safe
check SERVICE_UNIT unit_staged
check WORKER_SOURCE worker_source_staged
check WORKER_RUNTIME runtime_staged
check APPROVAL_NOT_PRESENT approval_absent
check WORKER_INACTIVE worker_stopped
check WORKER_NOT_ENABLED worker_disabled

if (( failed > 0 )); then
  printf 'FI_AWG_PREFLIGHT=BLOCKED;CHECKS_FAILED=%d;WORKER_STARTED=false;CUSTOMER_RELEASE=false\n' "$failed"
  exit 2
fi
echo 'FI_AWG_PREFLIGHT=PREACTIVATION_READY;WORKER_STARTED=false;CUSTOMER_RELEASE=false'
