#!/bin/bash
set -euo pipefail

CONFIG_FILE="/etc/auto_xdp/auto_xdp.env"
RUN_STATE_DIR="/run/auto_xdp"
RUNTIME_COMMON_SCRIPT="/usr/local/lib/auto_xdp/auto_xdp_runtime_common.sh"

[[ -f "$CONFIG_FILE" ]] || {
    echo "[auto_xdp] missing config: $CONFIG_FILE" >&2
    exit 1
}

# shellcheck disable=SC1091
source "$CONFIG_FILE"

export PYTHONPATH="${PYTHONPATH:-}"

[[ -f "$RUNTIME_COMMON_SCRIPT" ]] || {
    echo "[auto_xdp] missing runtime library: $RUNTIME_COMMON_SCRIPT" >&2
    exit 1
}

auto_xdp_shared_info() {
    echo "[auto_xdp] $*" >&2
}

auto_xdp_shared_warn() {
    echo "[auto_xdp] warning: $*" >&2
}

# shellcheck disable=SC1091
source "$RUNTIME_COMMON_SCRIPT"

# Normalize _IFACES array — supports both new IFACES= and legacy IFACE= configs.
IFS=' ' read -ra _IFACES <<< "${IFACES:-${IFACE:-}}"
[[ ${#_IFACES[@]} -gt 0 ]] || {
    echo "[auto_xdp] no interfaces configured (IFACES or IFACE missing from config)" >&2
    exit 1
}

sync_script_supports_log_level() {
    "$PYTHON3_BIN" "$SYNC_SCRIPT" --help 2>/dev/null | grep -q -- "--log-level"
}

run_sync_script() {
    local mode="$1"
    shift || true

    if sync_script_supports_log_level; then
        if [[ "$mode" == "watch" ]]; then
            exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --log-level "$LOG_LEVEL" --watch --interval "$SYNC_INTERVAL" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
        fi
        exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --log-level "$LOG_LEVEL" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
    fi

    echo "[auto_xdp] warning: installed xdp_port_sync.py does not support --log-level; running without it" >&2
    if [[ "$mode" == "watch" ]]; then
        exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --watch --interval "$SYNC_INTERVAL" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
    fi
    exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
}

ensure_xdp_loaded() {
    command -v bpftool &>/dev/null || return 1
    [[ -f "$XDP_OBJ_PATH" ]] || return 1

    ensure_bpffs

    cleanup_failed_load() {
        cleanup_tc_egress_filter
        local _iface
        for _iface in "${_IFACES[@]}"; do
            ip link set dev "$_iface" xdp off 2>/dev/null || true
        done
        rm -rf "$BPF_PIN_DIR"
    }

    # If the prog is already pinned and maps are intact, just re-attach any
    # interface that has lost its XDP program (e.g. after a link bounce).
    if [[ -f "$BPF_PIN_DIR/prog" ]] && xdp_maps_ready; then
        local _iface _any_missing=0
        for _iface in "${_IFACES[@]}"; do
            if ! ip link show "$_iface" 2>/dev/null | grep -q "xdp"; then
                _any_missing=1
                ip link set dev "$_iface" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null \
                || ip link set dev "$_iface" xdp generic pinned "$BPF_PIN_DIR/prog" 2>/dev/null \
                || echo "[auto_xdp] warning: could not re-attach XDP to $_iface" >&2
            fi
        done
        [[ $_any_missing -eq 1 ]] && echo "[auto_xdp] re-attached XDP to missing interfaces" >&2
        echo "existing" > "${RUN_STATE_DIR}/xdp_mode"
        return 0
    fi

    [[ -f "$BPF_PIN_DIR/prog" ]] && echo "[auto_xdp] existing XDP maps incomplete; reloading runtime objects" >&2

    rm -rf "$BPF_PIN_DIR"
    mkdir -p "$BPF_PIN_DIR"

    bpftool prog load "$XDP_OBJ_PATH" "$BPF_PIN_DIR/prog" type xdp \
        pinmaps "$BPF_PIN_DIR" >/dev/null 2>&1 || return 1
    xdp_maps_ready || {
        echo "[auto_xdp] pinned XDP maps incomplete after pinning; fallback to nftables" >&2
        cleanup_failed_load
        return 1
    }
    seed_existing_tcp_conntrack
    load_tc_egress_program || true
    load_slot_handlers || true

    local _iface _attached=0 _xdp_mode="native"
    for _iface in "${_IFACES[@]}"; do
        if ip link set dev "$_iface" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
            echo "[auto_xdp] attached XDP (native) on $_iface" >&2
            _attached=$((_attached + 1))
        elif ip link set dev "$_iface" xdp generic pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
            echo "[auto_xdp] attached XDP (generic) on $_iface" >&2
            _xdp_mode="generic"
            _attached=$((_attached + 1))
        else
            echo "[auto_xdp] warning: could not attach XDP to $_iface; skipping" >&2
        fi
    done

    [[ $_attached -gt 0 ]] || { cleanup_failed_load; return 1; }
    echo "$_xdp_mode" > "${RUN_STATE_DIR}/xdp_mode"
    return 0
}

select_backend() {
    mkdir -p "$RUN_STATE_DIR"

    if [[ "${PREFERRED_BACKEND}" != "nftables" ]] && ensure_xdp_loaded; then
        echo "xdp" > "${RUN_STATE_DIR}/backend"
        if command -v nft &>/dev/null && nft list table inet auto_xdp &>/dev/null 2>&1; then
            if nft delete table inet auto_xdp 2>/dev/null; then
                echo "[auto_xdp] nftables inet auto_xdp table removed (replaced by XDP)"
            fi
        fi
        return 0
    fi

    command -v nft &>/dev/null || {
        echo "[auto_xdp] nft not found and XDP unavailable" >&2
        exit 1
    }
    echo "nftables" > "${RUN_STATE_DIR}/backend"
}

if [[ "${1:-}" == "--sync-once" ]]; then
    shift
    select_backend
    run_sync_script once "$@"
fi

select_backend
run_sync_script watch
