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

resolve_preferred_backend() {
    local preferred="${PREFERRED_BACKEND:-auto}"

    [[ -f "${TOML_CONFIG:-}" ]] || {
        printf '%s\n' "$preferred"
        return 0
    }

    preferred=$("$PYTHON3_BIN" - "$TOML_CONFIG" "$preferred" <<'PY'
import os
import sys

path, default = sys.argv[1], sys.argv[2]

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        print(default)
        raise SystemExit(0)

if not os.path.exists(path):
    print(default)
    raise SystemExit(0)

try:
    with open(path, "rb") as f:
        cfg = tomllib.load(f)
except Exception:
    print(default)
    raise SystemExit(0)

preferred = str(cfg.get("daemon", {}).get("preferred_backend", default)).lower()
if preferred not in {"auto", "xdp", "nftables"}:
    preferred = default
print(preferred)
PY
) || preferred="${PREFERRED_BACKEND:-auto}"

    printf '%s\n' "$preferred"
}

run_sync_script() {
    local mode="$1"
    shift || true
    local backend
    backend=$(cat "${RUN_STATE_DIR}/backend")

    if [[ "$mode" == "watch" ]]; then
        exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --watch --backend "$backend" "$@"
    fi
    exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --backend "$backend" "$@"
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

    local _iface _attached=0 _xdp_mode="native" _native_err _generic_err
    for _iface in "${_IFACES[@]}"; do
        ethtool -K "$_iface" lro off 2>/dev/null || true
        if _native_err=$(ip link set dev "$_iface" xdp pinned "$BPF_PIN_DIR/prog" 2>&1); then
            echo "[auto_xdp] attached XDP (native) on $_iface" >&2
            _attached=$((_attached + 1))
        elif _generic_err=$(ip link set dev "$_iface" xdp generic pinned "$BPF_PIN_DIR/prog" 2>&1); then
            echo "[auto_xdp] attached XDP (generic) on $_iface" >&2
            _xdp_mode="generic"
            _attached=$((_attached + 1))
        else
            echo "[auto_xdp] warning: could not attach XDP to $_iface; skipping" >&2
            [[ -n "$_native_err" ]] && echo "[auto_xdp]   ↳ native:  $_native_err" >&2
            [[ -n "$_generic_err" ]] && echo "[auto_xdp]   ↳ generic: $_generic_err" >&2
        fi
    done

    [[ $_attached -gt 0 ]] || { cleanup_failed_load; return 1; }
    echo "$_xdp_mode" > "${RUN_STATE_DIR}/xdp_mode"
    return 0
}

select_backend() {
    mkdir -p "$RUN_STATE_DIR"
    local preferred_backend
    preferred_backend=$(resolve_preferred_backend)

    if [[ "$preferred_backend" != "nftables" ]] && ensure_xdp_loaded; then
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
