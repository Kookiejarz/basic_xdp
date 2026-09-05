#!/bin/bash

# Versioned runtime releases and installer transaction management.
# The active runtime is selected only by INSTALL_ROOT/current. The sole public
# facade is /usr/local/bin/axdp; daemons execute directly from current.

_release_python() {
    local python_root="${SOURCE_ROOT:-.}"
    as_root env "PYTHONPATH=${python_root}${PYTHONPATH:+:$PYTHONPATH}" \
        "${PYTHON3_BIN:-python3}" -m auto_xdp.install_state "$@"
}

_set_payload_context() {
    INSTALL_DIR="$1"
    PYTHON_LIB_DIR="${INSTALL_DIR}/python"
    AUTO_XDP_PACKAGE_DIR="${PYTHON_LIB_DIR}/auto_xdp"
}

_restore_stable_payload_context() {
    INSTALL_DIR="$CURRENT_LINK"
    PYTHON_LIB_DIR="${INSTALL_DIR}/python"
    AUTO_XDP_PACKAGE_DIR="${PYTHON_LIB_DIR}/auto_xdp"
}

_transition_update() {
    local -a args=(transition --path "$INSTALL_TRANSACTION_FILE")
    [[ -z "${INSTALL_TRANSACTION_ID:-}" ]] || args+=(--transaction-id "$INSTALL_TRANSACTION_ID")
    while [[ $# -gt 0 ]]; do
        args+=("$1" "$2")
        shift 2
    done
    _release_python "${args[@]}" >/dev/null
}

_atomic_runtime_link() {
    _release_python link --target "$1" --link "$2"
}

acquire_install_lock() {
    local lock_parent owner_pid=""
    lock_parent=$(dirname "$INSTALL_LOCK_DIR")
    as_root mkdir -p "$lock_parent"
    if ! as_root mkdir "$INSTALL_LOCK_DIR" 2>/dev/null; then
        owner_pid=$(as_root sed -n '1p' "${INSTALL_LOCK_DIR}/pid" 2>/dev/null || true)
        if [[ "$owner_pid" =~ ^[0-9]+$ ]] && as_root kill -0 "$owner_pid" 2>/dev/null; then
            return 1
        fi
        as_root rm -rf "$INSTALL_LOCK_DIR"
        as_root mkdir "$INSTALL_LOCK_DIR" || return 1
    fi
    printf '%s\n' "$$" | as_root tee "${INSTALL_LOCK_DIR}/pid" >/dev/null
    INSTALL_LOCK_HELD=1
}

acquire_install_lock_step() {
    step_begin "Acquiring installer transaction lock"
    if acquire_install_lock; then
        step_ok
    else
        die "Another Auto XDP installation is active (${INSTALL_LOCK_DIR})."
    fi
}

release_install_lock() {
    [[ ${INSTALL_LOCK_HELD:-0} -eq 1 ]] || return 0
    as_root rm -f "${INSTALL_LOCK_DIR}/pid" 2>/dev/null || true
    as_root rmdir "$INSTALL_LOCK_DIR" 2>/dev/null || true
    INSTALL_LOCK_HELD=0
}

recover_interrupted_install() {
    [[ -f "$INSTALL_TRANSACTION_FILE" ]] || return 0
    local fields status phase previous candidate
    local -a _tx_fields=()
    fields=$("${PYTHON3_BIN:-python3}" - "$INSTALL_TRANSACTION_FILE" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as handle:
        value = json.load(handle)
except Exception:
    raise SystemExit(0)
print(value.get("status", ""))
print(value.get("phase", ""))
print(value.get("previous", ""))
print(value.get("candidate", ""))
PY
) || return 0
    mapfile -t _tx_fields <<<"$fields"
    status="${_tx_fields[0]:-}"
    phase="${_tx_fields[1]:-}"
    previous="${_tx_fields[2]:-}"
    candidate="${_tx_fields[3]:-}"
    [[ "$status" == "active" ]] || return 0

    if [[ "$phase" == "switching" && -n "$previous" \
            && -d "${INSTALL_ROOT}/${previous}" ]]; then
        warn "Recovering an interrupted release switch; restoring ${previous}."
        _atomic_runtime_link "$previous" "$CURRENT_LINK"
        _transition_update --status recovered --phase rolled_back
    else
        # Once config preparation finished, current is a coherent
        # complete release. Runtime startup can safely repair backend state.
        warn "Adopting coherent release after interrupted ${phase:-unknown} phase: ${candidate:-current}."
        _transition_update --status recovered --phase adopted
    fi
}

recover_interrupted_install_step() {
    step_begin "Recovering interrupted installation state"
    recover_interrupted_install
    step_ok
}

_write_release_metadata() {
    local release_dir="$1" release_name="$2"
    local metadata
    metadata=$(mktemp)
    _SETUP_TMPFILES+=("$metadata")
    "${PYTHON3_BIN:-python3}" - "$metadata" "$release_name" \
        "${SOURCE_REVISION:-local}" "${AUTO_XDP_SOURCE_REF:-local}" <<'PY'
import json, sys
from datetime import datetime, timezone
path, name, revision, source_ref = sys.argv[1:]
with open(path, "w") as handle:
    json.dump({
        "schema": 1,
        "release": name,
        "revision": revision,
        "source_ref": source_ref,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
    place_file "$metadata" "${release_dir}/release.json"
}

validate_runtime_release() {
    local release_dir="$1" required
    local required_paths=(
        python/auto_xdp/__init__.py python/auto_xdp/install_state.py
        python/auto_xdp/default_config.toml
        handlers xdp_required_maps.txt xdp_map_abi.txt auto_xdp_runtime_common.sh
        auto_xdp_bpf_helpers.py xdp_port_sync.py pkt_relay.py axdp
        auto_xdp_start.sh release.json
    )
    for required in "${required_paths[@]}"; do
        [[ -e "${release_dir}/${required}" ]] || {
            warn "Release validation failed: ${required} missing."
            return 1
        }
    done
    bash -n "${release_dir}/auto_xdp_start.sh" \
        "${release_dir}/auto_xdp_runtime_common.sh" \
        "${release_dir}/axdp" || return 1
    PYTHONPATH="${release_dir}/python" "${PYTHON3_BIN:-python3}" - <<'PY'
from auto_xdp import admin_cli, install_state
parser = admin_cli.build_parser()
assert parser is not None and install_state.STATE_SCHEMA >= 1
PY
}

stage_runtime_release() {
    local stamp revision_tag final_dir rc=0
    stamp=$(date -u +%Y%m%d-%H%M%S)
    revision_tag="${SOURCE_VERSION:-${SOURCE_REVISION:-local}}"
    revision_tag=$(printf '%s' "$revision_tag" | tr -c 'A-Za-z0-9._-' '-')
    RELEASE_NAME="${revision_tag:-local}-${stamp}-${BASHPID:-$$}"
    RELEASE_CANDIDATE_DIR="${RELEASES_DIR}/.staging-${RELEASE_NAME}"
    final_dir="${RELEASES_DIR}/${RELEASE_NAME}"
    priv_mkdir "$RELEASES_DIR"
    as_root mkdir "$RELEASE_CANDIDATE_DIR" || return 1

    _set_payload_context "$RELEASE_CANDIDATE_DIR"
    build_release_payload || rc=1
    [[ $rc -ne 0 ]] || restore_compiled_slot_handlers || rc=1
    [[ $rc -ne 0 ]] || _write_release_metadata "$RELEASE_CANDIDATE_DIR" "$RELEASE_NAME" || rc=1
    [[ $rc -ne 0 ]] || validate_runtime_release "$RELEASE_CANDIDATE_DIR" || rc=1
    _restore_stable_payload_context
    if [[ $rc -ne 0 ]]; then
        as_root rm -rf "$RELEASE_CANDIDATE_DIR"
        RELEASE_CANDIDATE_DIR=""
        return 1
    fi
    as_root chmod -R go-w "$RELEASE_CANDIDATE_DIR"
    as_root mv "$RELEASE_CANDIDATE_DIR" "$final_dir" || return 1
    RELEASE_CANDIDATE_DIR="$final_dir"
}

stage_runtime_release_step() {
    step_begin "Building and validating immutable runtime release"
    if stage_runtime_release; then
        step_ok "$RELEASE_NAME"
    else
        die "Runtime release validation failed. The active installation was not changed."
    fi
}

_resolve_previous_release() {
    local current_target
    PREVIOUS_RELEASE=""
    if [[ -L "$CURRENT_LINK" ]]; then
        current_target=$(readlink "$CURRENT_LINK")
        case "$current_target" in
            releases/*)
                [[ -d "${INSTALL_ROOT}/${current_target}" ]] && {
                    PREVIOUS_RELEASE="$current_target"
                    return
                }
                ;;
            "${RELEASES_DIR}"/*)
                [[ -d "$current_target" ]] && {
                    PREVIOUS_RELEASE="releases/${current_target##*/}"
                    return
                }
                ;;
        esac
    fi
}

begin_install_transaction() {
    _resolve_previous_release
    PREVIOUS_ENV_CONFIG=""
    if [[ -n "$PREVIOUS_RELEASE" && -f "$CONFIG_FILE" ]]; then
        PREVIOUS_ENV_CONFIG=$(mktemp)
        _SETUP_TMPFILES+=("$PREVIOUS_ENV_CONFIG")
        as_root cp "$CONFIG_FILE" "$PREVIOUS_ENV_CONFIG" || return 1
    fi
    INSTALL_TRANSACTION_ID="${RELEASE_NAME}"
    INSTALL_TRANSACTION_ACTIVE=1
    INSTALL_TRANSACTION_COMMITTED=0
    _transition_update \
        --status active --phase switching \
        --previous "$PREVIOUS_RELEASE" \
        --candidate "releases/${RELEASE_NAME}" \
        --release "$RELEASE_NAME"
}

begin_install_transaction_step() {
    step_begin "Opening reversible install transaction"
    begin_install_transaction
    step_ok "previous=${PREVIOUS_RELEASE:-none}"
}

_remove_obsolete_install_layout() {
    local path bin_dir
    local -a obsolete_root=(
        python handlers xdp_required_maps.txt xdp_map_abi.txt xdp_firewall.o
        sock_state_track.o auto_xdp_runtime_common.sh auto_xdp_bpf_helpers.py
        xdp_port_sync.py pkt_relay.py axdp auto_xdp_start.sh release.json
    )
    for path in "${obsolete_root[@]}"; do
        as_root rm -rf "${INSTALL_ROOT}/${path}"
    done
    bin_dir=$(dirname "$AXDP_CMD")
    as_root rm -f \
        "${bin_dir}/xdp_port_sync.py" \
        "${bin_dir}/pkt_relay.py" \
        "${bin_dir}/auto_xdp_start.sh"
}

_install_axdp_entrypoint() {
    _atomic_runtime_link "${CURRENT_LINK}/axdp" "$AXDP_CMD"
}

activate_candidate_release() {
    _atomic_runtime_link "releases/${RELEASE_NAME}" "$CURRENT_LINK" || return 1
    _remove_obsolete_install_layout || return 1
    _install_axdp_entrypoint || return 1
    install_toml_config || return 1
    install_machine_state || return 1
    write_config || return 1
    _transition_update --phase backend
}

activate_candidate_release_step() {
    step_begin "Atomically activating runtime release"
    if activate_candidate_release; then
        step_ok "$RELEASE_NAME"
    else
        die "Could not activate release ${RELEASE_NAME}; rollback will restore the previous generation."
    fi
}

_restart_previous_service() {
    case "$INIT_SYSTEM" in
        systemd)
            as_root systemctl daemon-reload 2>/dev/null || true
            as_root systemctl restart "$SERVICE_NAME" 2>/dev/null || true
            as_root systemctl restart "$RELAY_SERVICE_NAME" 2>/dev/null || true
            ;;
        openrc)
            as_root rc-service "$SERVICE_NAME" restart 2>/dev/null || true
            as_root rc-service "$RELAY_SERVICE_NAME" restart 2>/dev/null || true
            ;;
    esac
}

rollback_install_transaction() {
    [[ ${INSTALL_TRANSACTION_ACTIVE:-0} -eq 1 ]] || return 0
    if [[ -n "${PREVIOUS_RELEASE:-}" && -d "${INSTALL_ROOT}/${PREVIOUS_RELEASE}" ]]; then
        warn "Installation failed; atomically restoring ${PREVIOUS_RELEASE}."
        _atomic_runtime_link "$PREVIOUS_RELEASE" "$CURRENT_LINK" || return 1
        if [[ -n "${PREVIOUS_ENV_CONFIG:-}" && -f "$PREVIOUS_ENV_CONFIG" ]]; then
            place_file "$PREVIOUS_ENV_CONFIG" "$CONFIG_FILE" || return 1
        fi
        _transition_update --status rolled_back --phase rolled_back || true
        _restart_previous_service
    else
        # A fresh candidate is the only coherent runtime. Retain it for
        # diagnostics/protection instead of detaching a successfully loaded
        # firewall and leaving broken entry points behind.
        warn "Fresh installation failed after activation; retaining coherent release ${RELEASE_NAME} for recovery."
        _transition_update --status failed --phase retained_fresh || true
    fi
    INSTALL_TRANSACTION_ACTIVE=0
}

commit_install_transaction() {
    _transition_update --status committed --phase committed
    INSTALL_TRANSACTION_COMMITTED=1
    INSTALL_TRANSACTION_ACTIVE=0
}

commit_install_transaction_step() {
    step_begin "Committing install transaction"
    commit_install_transaction
    step_ok "$RELEASE_NAME"
}
