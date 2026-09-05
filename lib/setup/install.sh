#!/bin/bash

# lib/setup/install.sh — runtime file installation and system service setup
# Sourced by setup_xdp.sh after backend_xdp.sh and backend_nft.sh.

RELAY_GROUP="${RELAY_GROUP:-auto-xdp}"

ensure_relay_group() {
    if getent group "$RELAY_GROUP" >/dev/null 2>&1; then
        return 0
    fi
    if command -v groupadd >/dev/null 2>&1; then
        as_root groupadd --system "$RELAY_GROUP"
    elif command -v addgroup >/dev/null 2>&1; then
        as_root addgroup -S "$RELAY_GROUP"
    else
        die "groupadd or addgroup is required to create the ${RELAY_GROUP} service group"
    fi
    priv_mkdir "$CONFIG_DIR"
    as_root install -m 0600 /dev/null "${CONFIG_DIR}/.relay-group-created"
}

stop_existing_service() {
    case "$INIT_SYSTEM" in
        systemd)
            as_root systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            as_root systemctl stop "${RELAY_SERVICE_NAME:-auto-xdp-relay}" 2>/dev/null || true
            ;;
        openrc)
            as_root rc-service "$SERVICE_NAME" stop 2>/dev/null || true
            as_root rc-service "${RELAY_SERVICE_NAME:-auto-xdp-relay}" stop 2>/dev/null || true
            ;;
    esac

    as_root pkill -f "auto_xdp_start.sh" 2>/dev/null || true
    as_root pkill -f "xdp_port_sync.py" 2>/dev/null || true
    as_root pkill -f "pkt_relay.py" 2>/dev/null || true
}

existing_install_detected() {
    local runtime_paths=(
        "$CONFIG_FILE"
        "$AXDP_CMD"
        "$CURRENT_LINK"
        "${CONFIG_DIR}/config.toml"
    )
    local path=""

    for path in "${runtime_paths[@]}"; do
        [[ -e "$path" ]] && return 0
    done

    case "$INIT_SYSTEM" in
        systemd)
            [[ -e "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" ]] && return 0
            [[ -e "${SYSTEMD_UNIT_DIR}/${RELAY_SERVICE_NAME:-auto-xdp-relay}.service" ]] && return 0
            ;;
        openrc)
            [[ -e "${OPENRC_INIT_DIR}/${SERVICE_NAME}" ]] && return 0
            [[ -e "${OPENRC_INIT_DIR}/${RELAY_SERVICE_NAME:-auto-xdp-relay}" ]] && return 0
            ;;
    esac

    return 1
}

prepare_candidate_config() {
    local source_config="${CONFIG_DIR}/config.toml"
    if [[ ! -f "$source_config" ]]; then
        source_config="${SOURCE_ROOT}/config.toml"
    fi
    [[ -f "$source_config" ]] || return 1
    local candidate
    candidate=$(mktemp)
    _SETUP_TMPFILES+=("$candidate")
    cp "$source_config" "$candidate" || return 1
    "${PYTHON3_BIN:-python3}" - "$candidate" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
with open(sys.argv[1], "rb") as handle:
    value = tomllib.load(handle)
backend = str(value.get("daemon", {}).get("preferred_backend", "auto")).lower()
if backend not in {"auto", "xdp", "nftables"}:
    raise SystemExit(f"invalid daemon.preferred_backend: {backend}")
interfaces = value.get("interfaces", {})
mode = str(interfaces.get("mode", "auto"))
if mode not in {"auto", "explicit"}:
    raise SystemExit(f"invalid interfaces.mode: {mode}")
if mode == "explicit" and not interfaces.get("include", []):
    raise SystemExit("interfaces.mode=explicit requires a non-empty interfaces.include")
xdp_mode = str(interfaces.get("xdp_mode", "auto"))
if xdp_mode not in {"auto", "native", "generic"}:
    raise SystemExit(f"invalid interfaces.xdp_mode: {xdp_mode}")
PY
    CANDIDATE_TOML_CONFIG="$candidate"
}

prepare_candidate_config_step() {
    step_begin "Validating candidate configuration"
    if prepare_candidate_config; then
        step_ok "local config preserved"
    else
        die "Candidate config validation failed. Current installation was not changed."
    fi
}

# The complete candidate release is already staged and validated when this
# runs. Stop old processes only for the short atomic current-link transaction.
replace_existing_install_step() {
    if existing_install_detected; then
        step_begin "Replacing existing installation"
        stop_existing_service
        step_ok "services stopped; candidate release is ready"
    else
        step_begin "Checking existing installation"
        stop_existing_service
        step_ok "none found"
    fi
}

write_config() {
    REQUESTED_BACKEND=$(_auto_xdp_resolve_preferred_backend "$TOML_CONFIG" "auto")
    priv_mkdir "$CONFIG_DIR"
    write_file "$CONFIG_FILE" <<EOF_CFG
IFACES="${IFACES[*]}"
SYNC_SCRIPT="${CURRENT_LINK}/xdp_port_sync.py"
PYTHON3_BIN="${PYTHON3_BIN}"
BPF_PIN_DIR="${BPF_PIN_DIR}"
XDP_OBJ_PATH="${CURRENT_LINK}/${XDP_OBJ}"
SOCK_STATE_OBJ_PATH="${CURRENT_LINK}/${SOCK_STATE_OBJ}"
BPFTOOL_BIN="${BPFTOOL_BIN:-}"
PREFERRED_BACKEND="${REQUESTED_BACKEND}"
MACHINE_STATE="${MACHINE_STATE}"
RUNTIME_STATE="${RUNTIME_STATE}"
INSTALL_TRANSACTION_FILE="${INSTALL_TRANSACTION_FILE}"
RUNTIME_GENERATION="${RELEASE_NAME:-unknown}"
AUTO_TUNE_QUEUES="1"
BPF_HELPER_SCRIPT="${CURRENT_LINK}/auto_xdp_bpf_helpers.py"
TOML_CONFIG="${CONFIG_DIR}/config.toml"
INSTALL_DIR="${CURRENT_LINK}"
HANDLERS_DIR="${CONFIG_DIR}/handlers"
PYTHON_LIB_DIR="${CURRENT_LINK}/python"
PYTHONPATH="${CURRENT_LINK}/python"
export BPF_PIN_DIR
EOF_CFG
}

install_machine_state() {
    [[ -n "${MACHINE_STATE_CANDIDATE:-}" && -f "$MACHINE_STATE_CANDIDATE" ]] || return 0
    place_file "$MACHINE_STATE_CANDIDATE" "$MACHINE_STATE"
    as_root chmod 0644 "$MACHINE_STATE"
}

install_python_support_package() {
    local pkg_root="${AUTO_XDP_PACKAGE_DIR}"
    local files rel target

    priv_mkdir "$pkg_root"

    if [[ -n "${SOURCE_ROOT:-}" && -d "${SOURCE_ROOT}/auto_xdp" ]]; then
        mapfile -t files < <(
            find "${SOURCE_ROOT}/auto_xdp" -name "*.py" -type f \
                | sed "s|^${SOURCE_ROOT}/||" \
                | sort
        )
    elif [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        local api_url
        api_url="$(sed \
            -e 's|https://raw\.githubusercontent\.com/|https://api.github.com/repos/|' \
            -e 's|/\([^/]*\)$|/git/trees/\1?recursive=1|' \
            <<< "$RAW_URL")"
        mapfile -t files < <(
            curl -fsSL "$api_url" \
            | python3 -c "
import json, sys
try:
    tree = json.load(sys.stdin).get('tree', [])
except Exception:
    raise SystemExit(1)
for e in tree:
    p = e['path']
    if p.startswith('auto_xdp/') and p.endswith('.py'):
        print(p)
" | sort
        )
        if [[ ${#files[@]} -eq 0 ]]; then
            warn "GitHub API returned no auto_xdp Python files (rate limited or network error); aborting Python package install"
            return 1
        fi
    else
        mapfile -t files < <(find auto_xdp -name "*.py" -type f | sort)
    fi

    for rel in "${files[@]}"; do
        target="${pkg_root}/${rel#auto_xdp/}"
        priv_mkdir "$(dirname "$target")"
        fetch_local_or_remote "$rel" "$rel" "$target" || return 1
    done

    fetch_local_or_remote \
        "auto_xdp/xdp_required_maps.txt" \
        "auto_xdp/xdp_required_maps.txt" \
        "${pkg_root}/xdp_required_maps.txt" || return 1

    fetch_local_or_remote \
        "auto_xdp/default_config.toml" \
        "auto_xdp/default_config.toml" \
        "${pkg_root}/default_config.toml" || return 1
}

install_runner_script() {
    local target="${INSTALL_DIR}/auto_xdp_start.sh"
    if ! fetch_local_or_remote "$RUNNER_SRC" "$RUNNER_SRC" "$target"; then
        die "Failed to install ${RUNNER_SRC}"
    fi
    as_root chmod +x "$target"
}

install_xdp_required_maps() {
    priv_mkdir "$INSTALL_DIR"
    if ! fetch_local_or_remote \
            "auto_xdp/xdp_required_maps.txt" \
            "auto_xdp/xdp_required_maps.txt" \
            "${INSTALL_DIR}/xdp_required_maps.txt"; then
        die "Failed to install auto_xdp/xdp_required_maps.txt"
    fi
}

install_xdp_map_abi() {
    local target="${INSTALL_DIR}/xdp_map_abi.txt"
    priv_mkdir "$INSTALL_DIR"
    if [[ -f "${BUILD_STAGING_DIR:-}/xdp_map_abi.txt" ]]; then
        place_file "${BUILD_STAGING_DIR}/xdp_map_abi.txt" "$target"
    elif ! fetch_local_or_remote \
            "auto_xdp/xdp_map_abi.txt" \
            "auto_xdp/xdp_map_abi.txt" \
            "$target"; then
        die "Failed to install auto_xdp/xdp_map_abi.txt"
    fi
}

install_runtime_common_script() {
    local target="${INSTALL_DIR}/auto_xdp_runtime_common.sh"
    if ! fetch_local_or_remote "$RUNTIME_COMMON_SRC" "$RUNTIME_COMMON_SRC" "$target"; then
        die "Failed to install ${RUNTIME_COMMON_SRC}"
    fi
    as_root chmod +x "$target"
}

install_sync_script() {
    local target="${INSTALL_DIR}/xdp_port_sync.py"
    if ! fetch_local_or_remote "xdp_port_sync.py" "xdp_port_sync.py" "$target"; then
        die "Failed to install xdp_port_sync.py"
    fi
    as_root chmod +x "$target"
}

install_relay_script() {
    local target="${INSTALL_DIR}/pkt_relay.py"
    if ! fetch_local_or_remote "pkt_relay.py" "pkt_relay.py" "$target"; then
        die "Failed to install pkt_relay.py"
    fi
    as_root chmod +x "$target"
}

install_bpf_helper() {
    local target="${INSTALL_DIR}/auto_xdp_bpf_helpers.py"
    if ! fetch_local_or_remote "$BPF_HELPER_SRC" "$BPF_HELPER_SRC" "$target"; then
        die "Failed to install ${BPF_HELPER_SRC}"
    fi
    as_root chmod +x "$target"
}

install_axdp_command() {
    local target="${INSTALL_DIR}/axdp"
    if ! fetch_local_or_remote "axdp" "axdp" "$target"; then
        die "Failed to install axdp"
    fi
    as_root chmod +x "$target"
}

validate_installed_python_support_package() {
    PYTHONPATH="${PYTHON_LIB_DIR}" "${PYTHON3_BIN:-python3}" - <<'PY'
import sys

try:
    import auto_xdp.tui  # noqa: F401
    from auto_xdp import admin_cli
    from importlib import resources
except Exception as exc:
    raise SystemExit(f"failed to import installed auto_xdp TUI modules: {exc}")

if not resources.files("auto_xdp").joinpath("default_config.toml").is_file():
    raise SystemExit("installed auto_xdp package is missing default_config.toml")

parser = admin_cli.build_parser()
required_options = {"--run-state-dir", "--nft-family", "--nft-table", "--iface"}
missing_options = sorted(required_options - set(parser._option_string_actions))
if missing_options:
    raise SystemExit(
        "installed auto_xdp.admin_cli is missing required wrapper options: "
        + ", ".join(missing_options)
    )
command_action = next(
    (action for action in parser._actions if getattr(action, "dest", None) == "command"),
    None,
)
choices = set(getattr(command_action, "choices", {}) or {})
if "tui" not in choices:
    raise SystemExit("installed auto_xdp.admin_cli does not expose the tui command")
PY
}

install_slot_handler_sdk() {
    local handlers_root="${INSTALL_DIR}/handlers"
    local -a handler_files=()
    local rel=""

    priv_mkdir "$handlers_root"

    if [[ -n "${BUILD_STAGING_DIR:-}" && -d "${BUILD_STAGING_DIR}/handlers" ]]; then
        local _staged=()
        mapfile -t -d '' _staged < <(find "${BUILD_STAGING_DIR}/handlers" -maxdepth 1 \
            -type f \( -name 'Makefile' -o -name '*.c' -o -name '*.h' \) -print0)
        if [[ ${#_staged[@]} -gt 0 ]]; then
            local _sf
            for _sf in "${_staged[@]}"; do
                place_file "$_sf" "${handlers_root}/$(basename "$_sf")"
            done
            return 0
        fi
    fi

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        local api_url
        api_url="$(sed \
            -e 's|https://raw\.githubusercontent\.com/|https://api.github.com/repos/|' \
            -e 's|/\([^/]*\)$|/git/trees/\1?recursive=1|' \
            <<< "$RAW_URL")"
        mapfile -t handler_files < <(
            curl -fsSL "$api_url" \
            | python3 -c "
import json, sys
for e in json.load(sys.stdin).get('tree', []):
    p = e['path']
    if not p.startswith('handlers/'):
        continue
    tail = p.split('/')[-1]
    if tail == 'Makefile' or p.endswith('.c') or p.endswith('.h'):
        print(p)
" | sort
        )
    else
        local handler_root="${SOURCE_ROOT:-${BOOTSTRAP_LOCAL_ROOT:-.}}/handlers"
        mapfile -t handler_files < <(
            find "$handler_root" -maxdepth 1 -type f \
                \( -name 'Makefile' -o -name '*.c' -o -name '*.h' \) \
                | sort
        )
    fi

    if [[ ${#handler_files[@]} -eq 0 ]]; then
        warn "Handler SDK files not found (GitHub API unavailable or repo empty); continuing without optional handlers"
        return 0
    fi

    for rel in "${handler_files[@]}"; do
        if ! fetch_local_or_remote "$rel" "$rel" "${handlers_root}/${rel#handlers/}"; then
            die "Failed to install ${rel}"
        fi
    done
}

install_toml_config() {
    local toml_target="${CONFIG_DIR}/config.toml"
    priv_mkdir "$CONFIG_DIR"
    priv_mkdir "${CONFIG_DIR}/handlers"
    as_root chmod 0755 "${CONFIG_DIR}/handlers"

    if [[ -f "$toml_target" ]]; then
        local backup_dir="${CONFIG_DIR}/backups"
        local stamp
        stamp=$(date -u +%Y%m%d-%H%M%S)
        priv_mkdir "$backup_dir"
        place_file "$toml_target" "${backup_dir}/config.toml.${stamp}"
        as_root chmod 0700 "$backup_dir"
        info "Preserving existing config.toml (backup: ${backup_dir}/config.toml.${stamp})"
        return 0
    fi

    if [[ -n "${CANDIDATE_TOML_CONFIG:-}" && -f "$CANDIDATE_TOML_CONFIG" ]]; then
        place_file "$CANDIDATE_TOML_CONFIG" "$toml_target"
    elif ! fetch_local_or_remote "config.toml" "config.toml" "$toml_target"; then
        die "Failed to install config.toml"
    fi
}

build_release_payload() {
    priv_mkdir "$INSTALL_DIR"

    install_compiled_bpf_objects() {
        local object source
        for object in "$XDP_OBJ" "$SOCK_STATE_OBJ"; do
            source="${BUILD_STAGING_DIR}/${object}"
            [[ -f "$source" ]] || continue
            place_file "$source" "${INSTALL_DIR}/${object}" || return 1
        done
        return 0
    }

    local rc=0
    substep_run "Installing staged BPF objects" install_compiled_bpf_objects || rc=1
    substep_run "Installing XDP required maps list" install_xdp_required_maps || rc=1
    substep_run "Installing XDP map ABI manifest" install_xdp_map_abi || rc=1
    substep_run "Installing sync daemon" install_sync_script || rc=1
    substep_run "Installing Python support package" install_python_support_package || rc=1
    substep_run "Installing relay helper" install_relay_script || rc=1
    substep_run "Installing BPF helper script" install_bpf_helper || rc=1
    substep_run "Installing axdp command" install_axdp_command || rc=1
    substep_run "Validating Python support package" validate_installed_python_support_package || rc=1
    substep_run "Installing slot handler SDK" install_slot_handler_sdk || rc=1
    substep_run "Installing shared runtime library" install_runtime_common_script || rc=1
    substep_run "Installing launcher script" install_runner_script || rc=1

    unset -f install_compiled_bpf_objects
    return "$rc"
}

load_configured_slot_handlers_step() {
    [[ "${ACTIVE_BACKEND:-nftables}" == "xdp" ]] || return 0
    [[ ${AUTO_XDP_HANDLERS_PRELOADED:-0} -eq 0 ]] || return 0

    step_begin "Loading configured slot handlers"
    if load_slot_handlers; then
        step_ok
    else
        step_warn "slot handlers unavailable"
    fi
}

load_configured_port_handlers_step() {
    [[ "${ACTIVE_BACKEND:-nftables}" == "xdp" ]] || return 0
    [[ ${AUTO_XDP_HANDLERS_PRELOADED:-0} -eq 0 ]] || return 0

    step_begin "Loading configured per-port handlers"
    if load_port_handlers; then
        step_ok
    else
        step_warn "per-port handlers unavailable"
    fi
}

install_systemd_service() {
    ensure_relay_group
    as_root install -d -m 0750 -o root -g "$RELAY_GROUP" /run/auto_xdp
    write_file "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" <<EOF_UNIT
[Unit]
Description=Auto XDP Loader + Port Whitelist Auto-Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${CURRENT_LINK}/auto_xdp_start.sh
Restart=on-failure
RestartSec=5
User=root
Group=${RELAY_GROUP}
RuntimeDirectory=auto_xdp
RuntimeDirectoryMode=0750

[Install]
WantedBy=multi-user.target
EOF_UNIT

    write_file "${SYSTEMD_UNIT_DIR}/${RELAY_SERVICE_NAME}.service" <<EOF_RELAY_UNIT
[Unit]
Description=Auto XDP packet event relay
After=${SERVICE_NAME}.service
Wants=${SERVICE_NAME}.service
PartOf=${SERVICE_NAME}.service

[Service]
Type=simple
Environment=PYTHONPATH=${CURRENT_LINK}/python
ExecStart=${CURRENT_LINK}/pkt_relay.py --config ${TOML_CONFIG} --pin-path ${BPF_PIN_DIR}/pkt_ringbuf --wait-for-ringbuf
Restart=on-failure
RestartSec=2
User=root
Group=${RELAY_GROUP}
UMask=0007

[Install]
WantedBy=multi-user.target
EOF_RELAY_UNIT

    as_root systemctl daemon-reload
    as_root systemctl enable "$SERVICE_NAME"
    as_root systemctl enable "$RELAY_SERVICE_NAME"
    as_root systemctl restart "$SERVICE_NAME"
    as_root systemctl restart "$RELAY_SERVICE_NAME"
}

install_openrc_service() {
    ensure_relay_group
    as_root install -d -m 0750 -o root -g "$RELAY_GROUP" /run/auto_xdp
    write_file "${OPENRC_INIT_DIR}/${SERVICE_NAME}" <<EOF_OPENRC
#!/sbin/openrc-run
description="Auto XDP loader + port whitelist auto-sync"
command="${CURRENT_LINK}/auto_xdp_start.sh"
command_background=true
command_user="root:${RELAY_GROUP}"
pidfile="/run/\${RC_SVCNAME}.pid"

start_pre() {
    install -d -m 0750 -o root -g ${RELAY_GROUP} /run/auto_xdp
}

depend() {
    need net
}
EOF_OPENRC

    write_file "${OPENRC_INIT_DIR}/${RELAY_SERVICE_NAME}" <<EOF_RELAY_OPENRC
#!/sbin/openrc-run
description="Auto XDP packet event relay"
command="${CURRENT_LINK}/pkt_relay.py"
command_args="--config ${TOML_CONFIG} --pin-path ${BPF_PIN_DIR}/pkt_ringbuf --wait-for-ringbuf"
command_background=true
command_user="root:${RELAY_GROUP}"
pidfile="/run/\${RC_SVCNAME}.pid"

start_pre() {
    install -d -m 0750 -o root -g ${RELAY_GROUP} /run/auto_xdp
}

depend() {
    need net
    after ${SERVICE_NAME}
}
EOF_RELAY_OPENRC

    as_root chmod +x "${OPENRC_INIT_DIR}/${SERVICE_NAME}"
    as_root chmod +x "${OPENRC_INIT_DIR}/${RELAY_SERVICE_NAME}"
    as_root rc-update add "$SERVICE_NAME" default >/dev/null 2>&1 || true
    as_root rc-update add "$RELAY_SERVICE_NAME" default >/dev/null 2>&1 || true
    as_root rc-service "$SERVICE_NAME" restart
    as_root rc-service "$RELAY_SERVICE_NAME" restart
}

run_initial_sync() {
    info "Running initial sync..."
    as_root env \
        "PYTHONPATH=${PYTHON_LIB_DIR}" \
        "$PYTHON3_BIN" "$SYNC_SCRIPT" \
        --config "$TOML_CONFIG" \
        --backend "$ACTIVE_BACKEND"
}

run_initial_sync_step() {
    step_begin "Applying and verifying initial policy"
    local sync_log
    sync_log=$(mktemp)
    _SETUP_TMPFILES+=("$sync_log")
    if ! run_initial_sync >"$sync_log" 2>&1; then
        warn_from_log_file "$sync_log" "initial sync: " 20
        if [[ "${REQUESTED_BACKEND:-auto}" == "auto" && "$ACTIVE_BACKEND" == "xdp" ]]; then
            warn "XDP initial policy verification failed; attempting nftables fallback."
            if ! ensure_nftables_available; then
                step_fail "initial policy sync failed and nftables is unavailable"
                return 1
            fi
            ACTIVE_BACKEND="nftables"
            ACTIVE_XDP_MODE="none"
            PENDING_NFT_CUTOVER=1
            XDP_FALLBACK_REASON="XDP initial policy sync failed"
            : >"$sync_log"
            if ! run_initial_sync >"$sync_log" 2>&1; then
                warn_from_log_file "$sync_log" "nftables sync: " 20
                step_fail "both XDP and nftables initial policy sync failed"
                return 1
            fi
        else
            step_fail "initial policy sync failed; refusing to report a healthy installation"
            return 1
        fi
    fi
    if [[ ${PENDING_NFT_CUTOVER:-0} -eq 1 ]]; then
        if ! finalize_nftables_cutover; then
            step_fail "nftables candidate loaded, but XDP cutover could not be verified"
            return 1
        fi
    fi
    step_ok "$ACTIVE_BACKEND policy verified"
}

install_runtime_service_step() {
    step_begin "Installing and enabling system service"
    case "$INIT_SYSTEM" in
        systemd)
            install_systemd_service
            if ! as_root systemctl is-active --quiet "$SERVICE_NAME"; then
                step_fail "systemd service did not remain active after restart"
                return 1
            fi
            step_ok "systemd: $SERVICE_NAME"
            ;;
        openrc)
            install_openrc_service
            if ! as_root rc-service "$SERVICE_NAME" status >/dev/null 2>&1; then
                step_fail "OpenRC service did not remain active after restart"
                return 1
            fi
            step_ok "openrc: $SERVICE_NAME"
            ;;
        *)
            step_warn "no init system detected — start manually: $RUNNER_SCRIPT"
            ;;
    esac
}
