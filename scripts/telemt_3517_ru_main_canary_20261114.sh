#!/usr/bin/env bash
# Isolated Telemt 3.5.17 upgrade on RU telemt.service only.
# Keeps /usr/bin/telemt and every other unit unchanged.
# Independent six-minute rollback is armed before any systemd override.
set -Eeuo pipefail
umask 077
ACTION="$1"
RUNID="$2"
[[ "$RUNID" =~ ^[0-9]{8,20}$ ]] || { echo BAD_RUNID >&2; exit 2; }
UNIT=telemt.service
BIN=/opt/telemt-3.5.17/telemt
UPLOADED=/tmp/telemt-3.5.17-canary-"$RUNID"
SUM="${3:-}"
DROPINDIR=/etc/systemd/system/telemt.service.d
DROPIN="$DROPINDIR/90-telemt3517-canary.conf"
FOLDER=/root/proxy-backups/telemt3517-ru-main-"$RUNID"
TIMER=telemt3517-ru-main-rollback-"$RUNID"
service_ready() {
    systemctl is-active --quiet "$UNIT"
    local pid
    pid="$(systemctl show "$UNIT" -p MainPID --value)"
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    [[ -r "/proc/$pid/exe" ]] || return 1
}
rollback() {
    if [[ -e "$FOLDER/confirmed" ]]; then
        echo TELEMT_ROLLBACK_ALREADY_CONFIRMED=true
        return 0
    fi
    if [[ -f "$DROPIN" ]]; then
        [[ -f "$FOLDER/desired-dropin.conf" ]] || { echo MISSING_DESIRED_DROPIN >&2; return 1; }
        if ! cmp -s "$DROPIN" "$FOLDER/desired-dropin.conf"; then
            echo TELEMT_ROLLBACK_DRIFT_NO_OVERWRITE=true >&2
            return 1
        fi
        rm -f "$DROPIN"
        systemctl daemon-reload
        systemctl restart "$UNIT"
        service_ready
        echo TELEMT_ROLLBACK_RESTORED_BASELINE=true
    else
        echo TELEMT_ROLLBACK_NOT_NEEDED=true
    fi
}
stage() {
    [[ $EUID -eq 0 ]] || { echo ROOT_REQUIRED >&2; exit 1; }
    [[ ! -e "$FOLDER" && ! -e "$DROPIN" ]] || { echo STAGE_ALREADY_EXISTS >&2; exit 1; }
    systemctl is-active --quiet "$UNIT"
    [[ -f /etc/telemt/telemt.toml ]] || { echo EXPECTED_CONFIG_MISSING >&2; exit 1; }
    local original_exec
    original_exec="$(systemctl show "$UNIT" -p ExecStart --value)"
    [[ "$original_exec" == *"/usr/bin/telemt"* && "$original_exec" == *"/etc/telemt/telemt.toml"* ]] || {
        echo BASELINE_EXECSTART_DRIFT >&2; exit 1;
    }
    [[ "$SUM" =~ ^[0-9a-f]{64}$ ]] || { echo INVALID_TRUSTED_BINARY_DIGEST >&2; exit 1; }
    [[ -f "$UPLOADED" && ! -L "$UPLOADED" ]] || { echo UPLOAD_MISSING >&2; exit 1; }
    printf '%s  %s\n' "$SUM" "$UPLOADED" | sha256sum --check --status || { echo RELEASE_SHA_MISMATCH >&2; exit 1; }
    install -d -m 0755 /opt/telemt-3.5.17
    if [[ -f "$BIN" ]]; then
        printf '%s  %s\n' "$SUM" "$BIN" | sha256sum --check --status || { echo EXISTING_BINARY_MISMATCH >&2; exit 1; }
    else
        install -m 0755 -o root -g root "$UPLOADED" "$BIN"
    fi
    [[ "$("$BIN" --version 2>&1)" == *"3.5.17"* ]] || { echo RELEASE_VERSION_MISMATCH >&2; exit 1; }
    mkdir -m 0700 "$FOLDER"
    install -m 0700 "$0" "$FOLDER/rollback.sh"
    systemctl cat "$UNIT" > "$FOLDER/unit-before.txt"
    chmod 0600 "$FOLDER/unit-before.txt"
    cat > "$FOLDER/desired-dropin.conf" <<'EOF'
[Service]
ExecStart=
ExecStart=/opt/telemt-3.5.17/telemt /etc/telemt/telemt.toml
EOF
    chmod 0600 "$FOLDER/desired-dropin.conf"
    systemd-run --quiet --unit="$TIMER" --on-active=6min "$FOLDER/rollback.sh" rollback "$RUNID"
    systemctl is-active --quiet "$TIMER.timer" || { echo ROLLBACK_TIMER_MISSING >&2; exit 1; }
    echo TELEMT_INDEPENDENT_ROLLBACK_ARMED=true
    install -d -m 0755 "$DROPINDIR"
    install -m 0644 "$FOLDER/desired-dropin.conf" "$DROPIN"
    systemctl daemon-reload
    if ! systemctl restart "$UNIT"; then rollback; exit 1; fi
    if ! service_ready; then rollback; exit 1; fi
    local pid exe
    pid="$(systemctl show "$UNIT" -p MainPID --value)"
    exe="$(readlink -f "/proc/$pid/exe" || true)"
    if [[ "$exe" != "$BIN" ]]; then rollback; echo EXECUTABLE_MISMATCH >&2; exit 1; fi
    echo TELEMT_RU_MAIN_CANARY_RUNNING_3517=true
}
commit() {
    [[ -f "$FOLDER/desired-dropin.conf" ]] || { echo MISSING_CANARY_STATE >&2; exit 1; }
    cmp -s "$DROPIN" "$FOLDER/desired-dropin.conf"
    service_ready
    local pid
    pid="$(systemctl show "$UNIT" -p MainPID --value)"
    [[ "$(readlink -f "/proc/$pid/exe")" == "$BIN" ]] || { echo EXE_DRIFT >&2; exit 1; }
    systemctl is-active --quiet "$TIMER.timer" || { echo TIMER_NOT_ARMED >&2; exit 1; }
    touch "$FOLDER/confirmed"
    systemctl stop "$TIMER.timer"
    echo TELEMT_3517_RU_MAIN_COMMITTED=true
}
case "$ACTION" in
    stage) stage;;
    commit) commit;;
    rollback) rollback;;
    *) echo 'usage: stage|commit|rollback RUNID' >&2; exit 2;;
esac
