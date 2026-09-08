#!/bin/bash
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/auto_xdp/auto_xdp.env}"
RUN_STATE_DIR="${RUN_STATE_DIR:-/run/auto_xdp}"
AUTO_XDP_LAUNCHER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
RUNTIME_COMMON_SCRIPT="${RUNTIME_COMMON_SCRIPT:-${AUTO_XDP_LAUNCHER_DIR}/auto_xdp_runtime_common.sh}"

recover_interrupted_release_switch() {
    local install_root="${AUTO_XDP_INSTALL_ROOT:-/usr/local/lib/auto_xdp}"
    local current_link="${AUTO_XDP_CURRENT_LINK:-${install_root}/current}"
    local transaction_file="${INSTALL_TRANSACTION_FILE:-/etc/auto_xdp/install-transaction.json}"
    [[ -f "$transaction_file" ]] || return 0
    local phase previous fields script_dir
    local -a _recovery_fields=()
    fields=$(python3 - "$transaction_file" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as handle:
        value = json.load(handle)
except Exception:
    raise SystemExit(0)
if value.get("status") != "active":
    raise SystemExit(0)
print(value.get("phase", ""))
print(value.get("previous", ""))
PY
) || return 0
    mapfile -t _recovery_fields <<<"$fields"
    phase="${_recovery_fields[0]:-}"
    previous="${_recovery_fields[1]:-}"
    [[ "$phase" == "switching" && -n "$previous" \
        && -d "${install_root}/${previous}" ]] || return 0

    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
    echo "[auto_xdp] interrupted install switch detected; restoring ${previous}" >&2
    PYTHONPATH="${script_dir}/python" python3 -m auto_xdp.install_state link \
        --target "$previous" --link "$current_link" || return 1
    PYTHONPATH="${script_dir}/python" python3 -m auto_xdp.install_state transition \
        --path "$transaction_file" --status recovered --phase rolled_back || return 1
    exec "${current_link}/auto_xdp_start.sh" "$@"
}

append_pythonpath_once() {
    local path="$1"

    [[ -n "$path" ]] || return 0
    case ":${PYTHONPATH:-}:" in
        *":${path}:"*)
            return 0
            ;;
    esac
    PYTHONPATH="${path}${PYTHONPATH:+:${PYTHONPATH}}"
}

discover_python_lib_dir() {
    local candidate
    local -a candidates=()

    if [[ -n "${PYTHON_LIB_DIR:-}" ]]; then
        candidates+=("${PYTHON_LIB_DIR}")
    fi
    candidates+=(
        "${AUTO_XDP_LAUNCHER_DIR}/python"
        "$(cd "${AUTO_XDP_LAUNCHER_DIR}/.." && pwd)"
    )

    for candidate in "${candidates[@]}"; do
        [[ -f "${candidate}/auto_xdp/__init__.py" ]] || continue
        printf '%s\n' "$candidate"
        return 0
    done

    if [[ -n "${PYTHON_LIB_DIR:-}" ]]; then
        printf '%s\n' "${PYTHON_LIB_DIR}"
    else
        printf '%s\n' "${AUTO_XDP_LAUNCHER_DIR}/python"
    fi
}

auto_xdp_shared_info() {
    echo "[auto_xdp] $*" >&2
}

auto_xdp_shared_warn() {
    echo "[auto_xdp] warning: $*" >&2
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    recover_interrupted_release_switch "$@"
    [[ -f "$CONFIG_FILE" ]] || {
        echo "[auto_xdp] missing config: $CONFIG_FILE" >&2
        exit 1
    }
    # shellcheck disable=SC1091
    source "$CONFIG_FILE"

    PYTHON_LIB_DIR="$(discover_python_lib_dir)"
    export PYTHON_LIB_DIR
    append_pythonpath_once "${PYTHON_LIB_DIR}"
    export PYTHONPATH="${PYTHONPATH:-}"

    [[ -f "$RUNTIME_COMMON_SCRIPT" ]] || {
        echo "[auto_xdp] missing runtime library: $RUNTIME_COMMON_SCRIPT" >&2
        exit 1
    }
    # shellcheck disable=SC1091
    source "$RUNTIME_COMMON_SCRIPT"

    IFS=' ' read -ra _IFACES <<< "${IFACES:-}"
    [[ ${#_IFACES[@]} -gt 0 ]] || {
        echo "[auto_xdp] no interfaces configured (IFACES missing from config)" >&2
        exit 1
    }
fi

resolve_preferred_backend() {
    _auto_xdp_resolve_preferred_backend "${TOML_CONFIG:-}" "${PREFERRED_BACKEND:-auto}"
}

resolve_policy_mode() {
    "$PYTHON3_BIN" -c '
from auto_xdp.config import load_toml_config
import sys
print(str(load_toml_config(sys.argv[1]).get("policy", {}).get("mode", "audit")).lower())
' "${TOML_CONFIG:-/etc/auto_xdp/config.toml}"
}

resolve_committed_backend() {
    local state_path="${RUNTIME_STATE:-/etc/auto_xdp/runtime-state.json}"
    [[ -f "$state_path" ]] || return 1
    "$PYTHON3_BIN" - "$state_path" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as handle:
        state = json.load(handle)
    value = state.get("active_backend") if state.get("healthy") else None
except Exception:
    value = None
if value not in {"xdp", "nftables"}:
    raise SystemExit(1)
print(value)
PY
}

run_sync_script() {
    local mode="$1"
    shift || true
    local backend
    backend=$(cat "${RUN_STATE_DIR}/backend" 2>/dev/null || resolve_preferred_backend)

    if [[ "$mode" == "watch" ]]; then
        exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --watch --backend "$backend" "$@"
    fi
    exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --backend "$backend" "$@"
}

ensure_xdp_loaded() {
    if declare -F _auto_xdp_resolve_bpftool >/dev/null 2>&1; then
        _auto_xdp_resolve_bpftool || return 1
    else
        # Keep this helper usable when runtime_common is intentionally mocked
        # out by component tests.
        command -v bpftool &>/dev/null || return 1
    fi
    [[ -f "$XDP_OBJ_PATH" ]] || return 1

    ensure_bpffs

    # A killed loader can leave a staged or rollback generation behind. Resume
    # it when possible. If the staged generation is no longer usable, verify
    # and restore the last committed generation before accepting the healthy
    # fast path below.
    if [[ -e "${BPF_PIN_DIR}_next" || -e "${BPF_PIN_DIR}_rollback" ]]; then
        if ! _auto_xdp_finish_interrupted_reload; then
            _auto_xdp_warn "Interrupted candidate could not be committed; restoring the last committed generation."
            _auto_xdp_restore_interrupted_reload || return 1
        fi
    fi

    # If the prog is already pinned and maps are intact, just re-attach any
    # interface that has lost its XDP program (e.g. after a link bounce).
    if [[ -f "$BPF_PIN_DIR/prog" ]] && xdp_maps_ready; then
        local _iface _any_missing=0 _xdp_mode="native"
        for _iface in "${_IFACES[@]}"; do
            if ! _auto_xdp_verify_iface_program "$_iface" "$BPF_PIN_DIR/prog"; then
                _any_missing=1
                if _auto_xdp_attach_candidate "$_iface" "$BPF_PIN_DIR/prog" \
                        && _auto_xdp_verify_iface_program "$_iface" "$BPF_PIN_DIR/prog"; then
                    echo "[auto_xdp] re-attached XDP (${AUTO_XDP_LAST_ATTACH_MODE}) on $_iface" >&2
                    [[ "$AUTO_XDP_LAST_ATTACH_MODE" == "generic" ]] && _xdp_mode="generic"
                else
                    echo "[auto_xdp] warning: could not re-attach XDP to $_iface" >&2
                    return 1
                fi
            elif ip -d link show dev "$_iface" 2>/dev/null | grep -q "xdpgeneric"; then
                _xdp_mode="generic"
            fi
        done
        [[ -f "$BPF_PIN_DIR/sock_state_link" ]] || load_sock_state_tracker || true
        load_port_handlers || true
        auto_tune_interface_parallelism || true
        [[ $_any_missing -eq 1 ]] && echo "[auto_xdp] re-attached XDP to missing interfaces" >&2
        echo "$_xdp_mode" > "${RUN_STATE_DIR}/xdp_mode"
        _auto_xdp_record_xdp_state "$BPF_PIN_DIR/prog" || {
            echo "[auto_xdp] warning: could not persist verified per-interface XDP state" >&2
            return 1
        }
        return 0
    fi

    [[ -f "$BPF_PIN_DIR/prog" ]] && echo "[auto_xdp] existing XDP maps incomplete; reloading runtime objects" >&2

    # Build a candidate map generation while the current XDP program remains
    # attached. The shared switch helper restores every interface if any
    # replace operation fails.
    if ! transactional_reload_xdp; then
        echo "[auto_xdp] transactional XDP reload failed; previous protection preserved or restored" >&2
        if _auto_xdp_any_target_has_xdp; then
            echo "[auto_xdp] refusing nftables fallback while XDP remains attached" >&2
            return 2
        fi
        return 1
    fi

    load_sock_state_tracker || true
    auto_tune_interface_parallelism || true
    echo "$AUTO_XDP_SWITCH_MODE" > "${RUN_STATE_DIR}/xdp_mode"
    return 0
}

activate_nftables_backend() {
    command -v nft &>/dev/null || {
        echo "[auto_xdp] nft not found and nftables backend was selected" >&2
        return 1
    }

    local needs_cutover=0 iface mode index detached=0 rollback_ok=1 table_dump=""
    local nft_family="${NFT_FAMILY:-inet}" nft_table="${NFT_TABLE:-auto_xdp}"
    local -a old_modes=()
    _auto_xdp_any_target_has_xdp && needs_cutover=1
    table_dump=$(nft list table "$nft_family" "$nft_table" 2>/dev/null || true)
    if [[ $needs_cutover -eq 0 && "$table_dump" == *"set tcp_ports"* \
            && "$table_dump" == *"chain input"* ]]; then
        echo "nftables" > "${RUN_STATE_DIR}/backend"
        _auto_xdp_record_nft_state
        return
    fi

    # Build and validate the full nftables policy while XDP still protects the
    # interfaces. nft commits the generated table atomically.
    if ! PYTHONPATH="${PYTHON_LIB_DIR}${PYTHONPATH:+:$PYTHONPATH}" \
            "$PYTHON3_BIN" "$SYNC_SCRIPT" \
            --config "$TOML_CONFIG" --backend nftables; then
        echo "[auto_xdp] nftables candidate sync failed; retaining current XDP backend" >&2
        return 1
    fi
    table_dump=$(nft list table "$nft_family" "$nft_table" 2>/dev/null || true)
    if [[ "$table_dump" != *"set tcp_ports"* \
            || "$table_dump" != *"chain input"* ]]; then
        echo "[auto_xdp] nftables candidate schema verification failed; retaining current XDP backend" >&2
        return 1
    fi

    if [[ $needs_cutover -eq 1 ]]; then
        for iface in "${_IFACES[@]}"; do
            old_modes+=("$(_auto_xdp_iface_xdp_mode "$iface")")
        done
        for iface in "${_IFACES[@]}"; do
            _auto_xdp_detach_mode "$iface" native
            _auto_xdp_detach_mode "$iface" generic
            if [[ "$(_auto_xdp_iface_xdp_mode "$iface")" != "none" ]]; then
                echo "[auto_xdp] failed to remove XDP from $iface after nftables verification" >&2
                for ((index = 0; index < detached; index++)); do
                    _auto_xdp_attach_mode "${_IFACES[$index]}" "$BPF_PIN_DIR/prog" \
                        "${old_modes[$index]}" >/dev/null 2>&1 \
                        && _auto_xdp_verify_iface_program "${_IFACES[$index]}" "$BPF_PIN_DIR/prog" \
                        || rollback_ok=0
                done
                [[ $rollback_ok -eq 1 ]] \
                    || echo "[auto_xdp] warning: XDP rollback was incomplete; retaining all pin generations" >&2
                return 1
            fi
            detached=$((detached + 1))
        done
    fi

    echo "nftables" > "${RUN_STATE_DIR}/backend"
    _auto_xdp_record_nft_state
}

_auto_xdp_record_nft_state() {
    local python_root="${PYTHON_LIB_DIR:-${AUTO_XDP_RUNTIME_COMMON_DIR}/..}"
    local generation
    generation=$(_auto_xdp_runtime_generation)
    PYTHONPATH="$python_root${PYTHONPATH:+:$PYTHONPATH}" \
        "$PYTHON3_BIN" -m auto_xdp.install_state record \
        --machine-state "${MACHINE_STATE:-/etc/auto_xdp/machine-state.json}" \
        --runtime-state "${RUNTIME_STATE:-/etc/auto_xdp/runtime-state.json}" \
        --requested-backend "${preferred_backend:-nftables}" \
        --active-backend nftables \
        --generation "$generation" >/dev/null
}

select_backend() {
    mkdir -p "$RUN_STATE_DIR"
    local preferred_backend committed_backend="" xdp_status=1
    preferred_backend=$(resolve_preferred_backend)
    if [[ "$preferred_backend" == "auto" ]]; then
        committed_backend=$(resolve_committed_backend 2>/dev/null || true)
    fi

    if [[ "$preferred_backend" != "nftables" && "$committed_backend" != "nftables" ]]; then
        if ensure_xdp_loaded; then
            xdp_status=0
        else
            xdp_status=$?
        fi
        if [[ $xdp_status -eq 0 ]]; then
            echo "xdp" > "${RUN_STATE_DIR}/backend"
            if command -v nft &>/dev/null \
                    && nft list table "${NFT_FAMILY:-inet}" "${NFT_TABLE:-auto_xdp}" \
                        &>/dev/null 2>&1; then
                if nft delete table "${NFT_FAMILY:-inet}" "${NFT_TABLE:-auto_xdp}" \
                        2>/dev/null; then
                    echo "[auto_xdp] nftables ${NFT_FAMILY:-inet} ${NFT_TABLE:-auto_xdp} table removed (replaced by XDP)"
                fi
            fi
            return 0
        fi
        if [[ $xdp_status -eq 2 ]]; then
            echo "[auto_xdp] XDP reload failed with an attachment still active; backend selection aborted" >&2
            return 1
        fi
    fi

    activate_nftables_backend
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ "${1:-}" == "--sync-once" ]]; then
        shift
        if [[ "$(resolve_policy_mode)" != "enforce" ]]; then
            run_sync_script once "$@"
        fi
        select_backend
        run_sync_script once "$@"
    fi

    if [[ "$(resolve_policy_mode)" != "enforce" ]]; then
        rm -f "${RUN_STATE_DIR}/backend" "${RUN_STATE_DIR}/xdp_mode"
        run_sync_script watch
    fi

    select_backend
    run_sync_script watch
fi
