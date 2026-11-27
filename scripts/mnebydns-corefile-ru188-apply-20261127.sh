#!/usr/bin/env bash
# Guarded cutover of DE89 CoreDNS Corefile synthetic A records from 89.125.90.101
# to RU188 (188.120.254.223), synchronized with mnebydns_dns_policy_guard.py,
# Apple .mobileconfig, and a fresh consistent /opt/mnebydns-stable-checkpoints/<epoch>.
set -Eeuo pipefail
umask 077

PHASE="${1:-status}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

STATE_DIR="${MNEBYDNS_CUTOVER_STATE_DIR:-/opt/mnebydns-corefile-ru188-20261127}"
SCRIPT="${MNEBYDNS_CUTOVER_SCRIPT:-$STATE_DIR/apply.sh}"
HELPER_STAGED="$STATE_DIR/cutover.py"
HELPER_SRC="${MNEBYDNS_CUTOVER_HELPER:-}"
COREDNS_BIN="${MNEBYDNS_CUTOVER_COREDNS_BIN:-/opt/mnebydns-dot/coredns}"
COREFILE="${MNEBYDNS_CUTOVER_COREFILE:-/opt/mnebydns-dot/Corefile}"
NGINX_CONF="${MNEBYDNS_CUTOVER_NGINX_CONF:-/etc/nginx/nginx.conf}"
PROXY_CONF="${MNEBYDNS_CUTOVER_PROXY_CONF:-/etc/mnebydns-googlepilot/nginx.conf}"
GUARD_LIVE="${MNEBYDNS_CUTOVER_GUARD_LIVE:-/opt/mnebydns-maintenance/mnebydns_dns_policy_guard.py}"
GUARD_STAGED_SRC="${MNEBYDNS_CUTOVER_GUARD_STAGED:-}"
MOBILECONFIG="${MNEBYDNS_CUTOVER_MOBILECONFIG:-/var/www/cdn-servgo/mnebyvpn-dns.mobileconfig}"
CHECKPOINT_ROOT="${MNEBYDNS_CUTOVER_CHECKPOINT_ROOT:-/opt/mnebydns-stable-checkpoints}"
POINTER="$CHECKPOINT_ROOT/current"
SAFE_DEPLOY="${MNEBYDNS_CUTOVER_SAFE_DEPLOY:-/opt/mnebydns-maintenance/mnebydns_safe_deploy.py}"
LOCK="${MNEBYDNS_CUTOVER_LOCK:-/run/lock/mnebyvpn-public-route.lock}"
UNIT="${MNEBYDNS_CUTOVER_UNIT:-mnebydns-corefile-ru188-revert-20261127}"
TIMER="${UNIT}.timer"
MIN_REWRITES="${MNEBYDNS_CUTOVER_MIN_REWRITES:-600}"
PREFLIGHT_PORT="${MNEBYDNS_CUTOVER_PREFLIGHT_PORT:-18553}"
DOT_PORT="${MNEBYDNS_CUTOVER_DOT_PORT:-853}"
DE_BIND_IP="${MNEBYDNS_CUTOVER_DE_BIND_IP:-89.125.90.101}"
DOT_PROBE_ADDR="${MNEBYDNS_CUTOVER_DOT_ADDR:-$DE_BIND_IP}"
RU_INGRESS_IP="${MNEBYDNS_CUTOVER_RU_INGRESS_IP:-188.120.254.223}"
HOT_RELOAD_WAIT_TRIES="${MNEBYDNS_CUTOVER_RELOAD_WAIT_TRIES:-15}"
HOT_RELOAD_WAIT_SLEEP="${MNEBYDNS_CUTOVER_RELOAD_WAIT_SLEEP:-1}"

log() { printf 'COREFILE_RU188_%s=%s\n' "$1" "$2"; }

resolve_first_file() {
  local p
  for p in "$@"; do
    if [[ -n "$p" && -s "$p" && ! -L "$p" ]]; then
      printf '%s\n' "$p"
      return 0
    fi
  done
  return 1
}

atomic_install_file() {
  local src="$1" dst="$2" ref="${3:-}" default_mode="${4:-0644}"
  local tmp
  tmp="$(mktemp "$(dirname "$dst")/.$(basename "$dst").ru188.XXXXXXXX")"
  cp -p "$src" "$tmp"
  if [[ -n "$ref" && -e "$ref" ]]; then
    chown --reference="$ref" "$tmp" >/dev/null 2>&1 || true
    chmod --reference="$ref" "$tmp"
  else
    chmod "$default_mode" "$tmp"
  fi
  mv -f "$tmp" "$dst"
}

active_helper() {
  if [[ -s "$HELPER_STAGED" ]]; then
    printf '%s\n' "$HELPER_STAGED"
    return 0
  fi
  resolve_first_file \
    "$HELPER_SRC" \
    "$SCRIPT_DIR/mnebydns-corefile-ru188-cutover-20261127.py" \
    "/tmp/mnebydns-corefile-ru188-cutover-20261127.py"
}

wait_coredns_hot_reload() {
  local expected_pid="$1" expected_ip="$2"
  local helper
  helper="$(active_helper)"
  local i current_pid
  for (( i = 1; i <= HOT_RELOAD_WAIT_TRIES; i++ )); do
    current_pid="$(systemctl show --value -p MainPID mnebydns-dot.service 2>/dev/null || true)"
    if [[ "$current_pid" != "$expected_pid" ]]; then
      echo "COREFILE_RU188_PID_CHANGED_DURING_RELOAD=true(old=$expected_pid,new=$current_pid)" >&2
      return 3
    fi
    if python3 "$helper" probe-dot \
      --address "$DOT_PROBE_ADDR" --port "$DOT_PORT" \
      --expected-ip "$expected_ip" --hosts www.youtube.com >/dev/null 2>&1; then
      return 0
    fi
    sleep "$HOT_RELOAD_WAIT_SLEEP"
  done
  return 4
}

do_revert() {
  local backup_dir="$STATE_DIR/backup"
  test -s "$backup_dir/Corefile.before" || { echo "COREFILE_RU188_REVERT_MISSING_BACKUP=true" >&2; return 3; }

  if ! cmp -s "$backup_dir/Corefile.before" "$COREFILE"; then
    if [[ -s "$STATE_DIR/Corefile.candidate" ]] && ! cmp -s "$STATE_DIR/Corefile.candidate" "$COREFILE"; then
      echo "COREFILE_RU188_REVERT_DRIFT_REFUSED=true" >&2
      return 4
    fi
    atomic_install_file "$backup_dir/Corefile.before" "$COREFILE" "$backup_dir/Corefile.before" 0640
    if systemctl is-active --quiet mnebydns-dot.service; then
      local cur_pid
      cur_pid="$(systemctl show --value -p MainPID mnebydns-dot.service 2>/dev/null || true)"
      if [[ "$cur_pid" =~ ^[1-9][0-9]*$ ]]; then
        wait_coredns_hot_reload "$cur_pid" "$DE_BIND_IP" || systemctl restart mnebydns-dot.service
      else
        systemctl restart mnebydns-dot.service
      fi
    else
      systemctl restart mnebydns-dot.service
    fi
  fi

  if [[ -s "$backup_dir/mnebydns_dns_policy_guard.py.before" ]]; then
    atomic_install_file "$backup_dir/mnebydns_dns_policy_guard.py.before" "$GUARD_LIVE" \
      "$backup_dir/mnebydns_dns_policy_guard.py.before" 0644
  fi
  if [[ -s "$backup_dir/mnebyvpn-dns.mobileconfig.before" ]]; then
    atomic_install_file "$backup_dir/mnebyvpn-dns.mobileconfig.before" "$MOBILECONFIG" \
      "$backup_dir/mnebyvpn-dns.mobileconfig.before" 0644
  fi

  rm -f "$STATE_DIR/confirmed"
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  cmp -s "$backup_dir/Corefile.before" "$COREFILE"
  log REVERTED PASS
}

do_stage() {
  local helper guard_src
  helper="$(resolve_first_file \
    "$HELPER_SRC" \
    "$SCRIPT_DIR/mnebydns-corefile-ru188-cutover-20261127.py" \
    "/tmp/mnebydns-corefile-ru188-cutover-20261127.py")" || {
    echo "COREFILE_RU188_MISSING_CUTOVER_HELPER=true" >&2
    exit 3
  }
  guard_src="$(resolve_first_file \
    "$GUARD_STAGED_SRC" \
    "$SCRIPT_DIR/mnebydns_dns_policy_guard.py" \
    "/tmp/mnebydns_dns_policy_guard.py")" || {
    echo "COREFILE_RU188_MISSING_STAGED_GUARD=true" >&2
    exit 3
  }

  test -x "$COREDNS_BIN"
  test -f "$COREFILE" && test ! -L "$COREFILE"
  test -s "$NGINX_CONF"
  test -s "$PROXY_CONF"
  test -s "$MOBILECONFIG"
  systemctl is-active --quiet mnebydns-dot.service
  systemctl is-active --quiet nginx.service
  "$COREDNS_BIN" -plugins 2>&1 | grep -Eq '(^|[[:space:].])reload([[:space:]]|$)'
  python3 "$helper" validate-guard --path "$guard_src" >/dev/null

  if [[ -e "$STATE_DIR" ]]; then
    if [[ -e "$STATE_DIR/confirmed" ]] || [[ -e "$STATE_DIR/backup" ]] || systemctl is-active --quiet "$TIMER"; then
      echo "COREFILE_RU188_ACTIVE_OR_CONFIRMED_REFUSE_RESTAGE=true" >&2
      exit 3
    fi
    rm -rf -- "$STATE_DIR"
  fi

  install -d -m 0700 "$STATE_DIR"
  local self_real target_real
  self_real="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  target_real="$(readlink -f "$SCRIPT" 2>/dev/null || printf '%s' "$SCRIPT")"
  if [[ "$self_real" != "$target_real" ]]; then
    install -m 0700 "$0" "$SCRIPT"
  else
    chmod 0700 "$SCRIPT"
  fi
  install -m 0700 "$helper" "$HELPER_STAGED"
  install -m 0644 "$guard_src" "$STATE_DIR/guard.candidate.py"

  python3 "$HELPER_STAGED" rewrite \
    --input "$COREFILE" \
    --output "$STATE_DIR/Corefile.candidate" \
    --min-rewrites "$MIN_REWRITES"
  chown --reference="$COREFILE" "$STATE_DIR/Corefile.candidate" >/dev/null 2>&1 || true
  chmod --reference="$COREFILE" "$STATE_DIR/Corefile.candidate"
  sha256sum "$COREFILE" | awk '{print $1}' > "$STATE_DIR/Corefile.staged_base.sha256"

  python3 "$HELPER_STAGED" preflight \
    --input "$STATE_DIR/Corefile.candidate" \
    --output "$STATE_DIR/Corefile.preflight" \
    --port "$PREFLIGHT_PORT" \
    --bind 127.0.0.1

  python3 "$HELPER_STAGED" mobileconfig \
    --input "$MOBILECONFIG" \
    --output "$STATE_DIR/mobileconfig.candidate"
  chmod --reference="$MOBILECONFIG" "$STATE_DIR/mobileconfig.candidate"

  test -z "$(ss -H -lnt "sport = :${PREFLIGHT_PORT}")"
  local preflight_pid=""
  cleanup_preflight() {
    if [[ -n "${preflight_pid:-}" ]]; then
      kill "$preflight_pid" >/dev/null 2>&1 || true
      wait "$preflight_pid" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_preflight EXIT
  "$COREDNS_BIN" -conf "$STATE_DIR/Corefile.preflight" >"$STATE_DIR/preflight.log" 2>&1 &
  preflight_pid=$!

  local attempt ready=0
  for (( attempt = 1; attempt <= 50; attempt++ )); do
    if ! kill -0 "$preflight_pid" 2>/dev/null; then
      echo "COREFILE_RU188_PREFLIGHT_START_FAILED=true" >&2
      exit 3
    fi
    if ss -H -lnt "sport = :${PREFLIGHT_PORT}" | grep -Fq "127.0.0.1:${PREFLIGHT_PORT}"; then
      ready=1
      break
    fi
    sleep 0.2
  done
  if (( ! ready )); then
    echo "COREFILE_RU188_PREFLIGHT_LISTENER_TIMEOUT=true" >&2
    exit 3
  fi

  python3 "$HELPER_STAGED" probe-preflight --address 127.0.0.1 --port "$PREFLIGHT_PORT"
  cleanup_preflight
  preflight_pid=""
  trap - EXIT
  log STAGED PASS
}

do_apply() {
  test -s "$STATE_DIR/Corefile.candidate"
  test -s "$STATE_DIR/guard.candidate.py"
  test -s "$STATE_DIR/mobileconfig.candidate"
  test -s "$STATE_DIR/Corefile.staged_base.sha256"
  test -s "$HELPER_STAGED"
  test -x "$SCRIPT"
  test ! -e "$STATE_DIR/confirmed"
  test ! -e "$STATE_DIR/backup"

  test -f "$COREFILE" && test ! -L "$COREFILE"
  test "$(stat -c '%a' "$COREFILE")" = "640"
  local live_sha staged_sha
  live_sha="$(sha256sum "$COREFILE" | awk '{print $1}')"
  staged_sha="$(cat "$STATE_DIR/Corefile.staged_base.sha256")"
  if [[ "$live_sha" != "$staged_sha" ]]; then
    echo "COREFILE_RU188_LIVE_DRIFT_SINCE_STAGE=true" >&2
    exit 3
  fi

  systemctl is-active --quiet mnebydns-dot.service
  systemctl is-active --quiet nginx.service
  local old_pid
  old_pid="$(systemctl show --value -p MainPID mnebydns-dot.service)"
  [[ "$old_pid" =~ ^[1-9][0-9]*$ ]] || { echo "COREFILE_RU188_INVALID_MAINPID=$old_pid" >&2; exit 3; }

  python3 "$HELPER_STAGED" validate-guard --path "$STATE_DIR/guard.candidate.py" >/dev/null

  local backup_dir="$STATE_DIR/backup"
  install -d -m 0700 "$backup_dir"
  cp -p "$COREFILE" "$backup_dir/Corefile.before"
  chown --reference="$COREFILE" "$backup_dir/Corefile.before" >/dev/null 2>&1 || true
  chmod --reference="$COREFILE" "$backup_dir/Corefile.before"

  if [[ -f "$GUARD_LIVE" ]]; then
    cp -p "$GUARD_LIVE" "$backup_dir/mnebydns_dns_policy_guard.py.before"
    chown --reference="$GUARD_LIVE" "$backup_dir/mnebydns_dns_policy_guard.py.before" >/dev/null 2>&1 || true
    chmod --reference="$GUARD_LIVE" "$backup_dir/mnebydns_dns_policy_guard.py.before"
  fi
  cp -p "$MOBILECONFIG" "$backup_dir/mnebyvpn-dns.mobileconfig.before"
  chown --reference="$MOBILECONFIG" "$backup_dir/mnebyvpn-dns.mobileconfig.before" >/dev/null 2>&1 || true
  chmod --reference="$MOBILECONFIG" "$backup_dir/mnebyvpn-dns.mobileconfig.before"

  systemd-run --quiet --unit="$UNIT" --on-active=5m --collect /bin/bash "$SCRIPT" revert
  systemctl is-active --quiet "$TIMER"
  log AUTO_REVERT ARMED_5M

  trap 'do_revert || true' ERR

  local ref_meta
  ref_meta="$(stat -c '%a:%u:%g' "$backup_dir/Corefile.before")"
  atomic_install_file "$STATE_DIR/Corefile.candidate" "$COREFILE" "$backup_dir/Corefile.before" 0640
  test "$(stat -c '%a:%u:%g' "$COREFILE")" = "$ref_meta"

  wait_coredns_hot_reload "$old_pid" "$RU_INGRESS_IP"
  test "$(systemctl show --value -p MainPID mnebydns-dot.service)" = "$old_pid"

  atomic_install_file "$STATE_DIR/guard.candidate.py" "$GUARD_LIVE" \
    "$backup_dir/mnebydns_dns_policy_guard.py.before" 0644
  python3 - "$GUARD_LIVE" <<'PY'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("mnebydns_dns_policy_guard", sys.argv[1])
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(json.dumps(mod.smoke_check(), sort_keys=True))
PY

  atomic_install_file "$STATE_DIR/mobileconfig.candidate" "$MOBILECONFIG" \
    "$backup_dir/mnebyvpn-dns.mobileconfig.before" 0644

  python3 "$HELPER_STAGED" probe-dot \
    --address "$DOT_PROBE_ADDR" --port "$DOT_PORT" \
    --expected-ip "$RU_INGRESS_IP" \
    --hosts www.youtube.com claude.ai www.google.com

  trap - ERR
  log APPLIED PENDING_FINALIZE
}

do_finalize() {
  test -s "$STATE_DIR/backup/Corefile.before"
  cmp -s "$STATE_DIR/Corefile.candidate" "$COREFILE"
  cmp -s "$STATE_DIR/guard.candidate.py" "$GUARD_LIVE"
  cmp -s "$STATE_DIR/mobileconfig.candidate" "$MOBILECONFIG"
  test -s "$NGINX_CONF"
  test -s "$PROXY_CONF"
  test -s "$SAFE_DEPLOY"
  systemctl is-active --quiet mnebydns-dot.service
  systemctl is-active --quiet nginx.service
  nginx -t >/dev/null 2>&1

  python3 "$HELPER_STAGED" probe-dot \
    --address "$DOT_PROBE_ADDR" --port "$DOT_PORT" \
    --expected-ip "$RU_INGRESS_IP" \
    --hosts www.youtube.com claude.ai www.google.com

  mkdir -p -m 0700 "$CHECKPOINT_ROOT"
  local now target="" add candidate
  now="$(date -u +%s)"
  for add in 0 1 2 3; do
    candidate="$CHECKPOINT_ROOT/$((now + add))"
    if [[ ! -e "$candidate" ]]; then
      target="$candidate"
      break
    fi
  done
  test -n "$target"
  mkdir -m 0700 "$target"
  cp -p "$COREFILE" "$target/dns.stable"
  cp -p "$NGINX_CONF" "$target/nginx.stable"
  cp -p "$PROXY_CONF" "$target/proxy.stable"
  (cd "$target" && sha256sum nginx.stable dns.stable proxy.stable > stable-manifest.sha256)
  (cd "$target" && sha256sum -c stable-manifest.sha256 >/dev/null)
  cmp -s "$target/dns.stable" "$COREFILE"
  cmp -s "$target/nginx.stable" "$NGINX_CONF"
  cmp -s "$target/proxy.stable" "$PROXY_CONF"

  local tmp_ptr
  tmp_ptr="$(mktemp "$CHECKPOINT_ROOT/current.ru188.XXXXXXXX")"
  printf '%s\n' "$target" > "$tmp_ptr"
  if [[ -e "$POINTER" && ! -L "$POINTER" ]]; then
    chmod --reference="$POINTER" "$tmp_ptr"
  else
    chmod 0644 "$tmp_ptr"
  fi
  mv -Tf "$tmp_ptr" "$POINTER"
  test "$(cat "$POINTER")" = "$target"

  local sd_out
  sd_out="$(python3 "$SAFE_DEPLOY" status)"
  python3 - "$sd_out" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
if not isinstance(data, dict):
    raise SystemExit("safe_deploy status output must be a JSON object")
if data.get("done") is False:
    raise SystemExit(f"safe_deploy status failed: {data.get('error')}: {data.get('reason')}")
if data.get("read_only") is not True or data.get("dns_reader_group_verified") is not True:
    raise SystemExit("safe_deploy status missing read_only or dns_reader_group_verified")
services = data.get("services")
if services is not None:
    if not isinstance(services, dict) or not services:
        raise SystemExit("safe_deploy status services field invalid")
    for svc_name, svc_info in services.items():
        if not isinstance(svc_info, dict) or not all(v is True for v in svc_info.values()):
            raise SystemExit(f"safe_deploy status unhealthy service {svc_name}: {svc_info!r}")
PY
  : > "$STATE_DIR/confirmed"
  chmod 0600 "$STATE_DIR/confirmed"
  systemctl stop "$TIMER" >/dev/null 2>&1 || true
  log CHECKPOINT "$target"
  log FINALIZED PASS
}

do_status() {
  local ru_a de_a de_bind
  ru_a="$(grep -Ec "^[[:space:]]*answer[[:space:]]+\"\\{\\{[[:space:]]*\\.Name[[:space:]]*\\}\\}[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+A[[:space:]]+${RU_INGRESS_IP//./\\.}\"" "$COREFILE" || true)"
  de_a="$(grep -Ec "^[[:space:]]*answer[[:space:]]+\"\\{\\{[[:space:]]*\\.Name[[:space:]]*\\}\\}[[:space:]]+[0-9]+[[:space:]]+IN[[:space:]]+A[[:space:]]+${DE_BIND_IP//./\\.}\"" "$COREFILE" || true)"
  de_bind="$(grep -Ec "^[[:space:]]*bind[[:space:]]+${DE_BIND_IP//./\\.}([[:space:]]|$)" "$COREFILE" || true)"
  log RU_A_ANSWERS "$ru_a"
  log DE_A_ANSWERS "$de_a"
  log DE_BINDS "$de_bind"
  log COREFILE_META "$(stat -c '%a:%u:%g' "$COREFILE" 2>/dev/null || echo MISSING)"
  if [[ -f "$POINTER" && ! -L "$POINTER" ]]; then
    log CHECKPOINT_CURRENT "$(cat "$POINTER")"
  else
    log CHECKPOINT_CURRENT MISSING
  fi
  log DOT_SERVICE "$(systemctl is-active mnebydns-dot.service 2>/dev/null || true)"
  log REVERT_TIMER "$(systemctl is-active "$TIMER" 2>/dev/null || true)"
}

if [[ "$PHASE" == "--self-test" ]]; then
  helper_self="$(active_helper)"
  python3 "$helper_self" --self-test
  exit 0
fi

[[ "$(id -u)" == "0" ]] || exit 2

case "$PHASE" in
  stage|apply|revert|finalize)
    mkdir -p "$(dirname "$LOCK")"
    exec 9>"$LOCK"
    flock -w 50 9 || { echo "COREFILE_RU188_LOCK_BUSY=true" >&2; exit 3; }
    ;;
esac

case "$PHASE" in
  stage) do_stage ;;
  apply) do_apply ;;
  revert) do_revert ;;
  finalize) do_finalize ;;
  status) do_status ;;
  *) echo "usage: $0 stage|apply|revert|finalize|status|--self-test" >&2; exit 2 ;;
esac
