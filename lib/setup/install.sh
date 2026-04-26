#!/bin/bash

# lib/setup/install.sh — runtime file installation and system service setup
# Sourced by setup_xdp.sh after backend_xdp.sh and backend_nft.sh.

stop_existing_service() {
    case "$INIT_SYSTEM" in
        systemd)
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            ;;
        openrc)
            rc-service "$SERVICE_NAME" stop 2>/dev/null || true
            ;;
    esac

    pkill -f "auto_xdp_start.sh" 2>/dev/null || true
    pkill -f "xdp_port_sync.py" 2>/dev/null || true
}

existing_install_detected() {
    local runtime_paths=(
        "$CONFIG_FILE"
        "$SYNC_SCRIPT"
        "$AXDP_CMD"
        "$RUNNER_SCRIPT"
        "$BPF_RUNTIME_COMMON_INSTALLED"
        "$BPF_HELPER_INSTALLED"
        "$XDP_OBJ_INSTALLED"
        "$TC_OBJ_INSTALLED"
        "${INSTALL_DIR}/handlers"
        "${CONFIG_DIR}/config.toml"
    )
    local path=""

    for path in "${runtime_paths[@]}"; do
        [[ -e "$path" ]] && return 0
    done

    case "$INIT_SYSTEM" in
        systemd)
            [[ -e "/etc/systemd/system/${SERVICE_NAME}.service" ]] && return 0
            ;;
        openrc)
            [[ -e "/etc/init.d/${SERVICE_NAME}" ]] && return 0
            ;;
    esac

    return 1
}

confirm_existing_install_step() {
    if ! existing_install_detected; then
        return 0
    fi

    step_begin "Checking existing installation"
    if confirm_yes_no "Existing Auto XDP installation detected. Replace installed runtime files and restart the service? [y/N] " "abort"; then
        step_ok "confirmed"
        return 0
    fi

    step_warn "aborted"
    die "Installation aborted; existing deployment left untouched."
}

stop_existing_service_step() {
    step_begin "Stopping existing service"
    stop_existing_service
    step_ok
}

write_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<EOF_CFG
IFACES="${IFACES[*]}"
IFACE="${IFACES[0]}"
SYNC_SCRIPT="${SYNC_SCRIPT}"
PYTHON3_BIN="${PYTHON3_BIN}"
BPF_PIN_DIR="${BPF_PIN_DIR}"
XDP_OBJ_PATH="${XDP_OBJ_INSTALLED}"
TC_OBJ_PATH="${TC_OBJ_INSTALLED}"
PREFERRED_BACKEND="auto"
BPF_HELPER_SCRIPT="${BPF_HELPER_INSTALLED}"
TOML_CONFIG="${CONFIG_DIR}/config.toml"
HANDLERS_DIR="${INSTALL_DIR}/handlers"
PYTHONPATH="${PYTHON_LIB_DIR}"
export BPF_PIN_DIR
EOF_CFG
}

install_python_support_package() {
    local pkg_root="${AUTO_XDP_PACKAGE_DIR}"
    local files rel target

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        local api_url
        api_url="$(sed \
            -e 's|https://raw\.githubusercontent\.com/|https://api.github.com/repos/|' \
            -e 's|/\([^/]*\)$|/git/trees/\1?recursive=1|' \
            <<< "$RAW_URL")"
        mapfile -t files < <(
            curl -fsSL "$api_url" \
            | python3 -c "
import json, sys
for e in json.load(sys.stdin).get('tree', []):
    p = e['path']
    if p.startswith('auto_xdp/') and p.endswith('.py'):
        print(p)
" | sort
        )
    else
        mapfile -t files < <(find auto_xdp -name "*.py" -type f | sort)
    fi

    for rel in "${files[@]}"; do
        target="${pkg_root}/${rel#auto_xdp/}"
        mkdir -p "$(dirname "$target")"
        fetch_local_or_remote "$rel" "$rel" "$target" || return 1
    done
}

install_runner_script() {
    if ! fetch_local_or_remote "$RUNNER_SRC" "$RUNNER_SRC" "$RUNNER_SCRIPT"; then
        die "Failed to install ${RUNNER_SRC}"
    fi
    chmod +x "$RUNNER_SCRIPT"
}

install_runtime_common_script() {
    if ! fetch_local_or_remote "$RUNTIME_COMMON_SRC" "$RUNTIME_COMMON_SRC" "$BPF_RUNTIME_COMMON_INSTALLED"; then
        die "Failed to install ${RUNTIME_COMMON_SRC}"
    fi
    chmod +x "$BPF_RUNTIME_COMMON_INSTALLED"
}

install_sync_script() {
    if ! fetch_local_or_remote "xdp_port_sync.py" "xdp_port_sync.py" "$SYNC_SCRIPT"; then
        die "Failed to install xdp_port_sync.py"
    fi
    chmod +x "$SYNC_SCRIPT"
}

install_relay_script() {
    if ! fetch_local_or_remote "pkt_relay.py" "pkt_relay.py" "$RELAY_SCRIPT"; then
        die "Failed to install pkt_relay.py"
    fi
    chmod +x "$RELAY_SCRIPT"
}

install_bpf_helper() {
    if ! fetch_local_or_remote "$BPF_HELPER_SRC" "$BPF_HELPER_SRC" "$BPF_HELPER_INSTALLED"; then
        die "Failed to install ${BPF_HELPER_SRC}"
    fi
    chmod +x "$BPF_HELPER_INSTALLED"
}

install_axdp_command() {
    if ! fetch_local_or_remote "axdp" "axdp" "$AXDP_CMD"; then
        die "Failed to install axdp"
    fi
    chmod +x "$AXDP_CMD"
}

install_slot_handler_sdk() {
    local handlers_root="${INSTALL_DIR}/handlers"
    mkdir -p "$handlers_root"
    if ! fetch_local_or_remote "handlers/xdp_slot_ctx.h" "handlers/xdp_slot_ctx.h" "${handlers_root}/xdp_slot_ctx.h"; then
        die "Failed to install handlers/xdp_slot_ctx.h"
    fi
}

install_toml_config() {
    local toml_target="${CONFIG_DIR}/config.toml"
    mkdir -p "$CONFIG_DIR"

    if [[ -f "$toml_target" ]]; then
        if ! confirm_yes_no "config.toml already exists at ${toml_target}. Replace with repo default? [y/N] "; then
            return 0
        fi
    fi

    if ! fetch_local_or_remote "config.toml" "config.toml" "$toml_target"; then
        die "Failed to install config.toml"
    fi
}

install_runtime_files() {
    mkdir -p "$INSTALL_DIR"

    _install_runtime_common_assets() {
        install_runtime_common_script
        write_config
    }

    substep_run "Installing sync daemon" install_sync_script
    substep_run "Installing Python support package" install_python_support_package
    substep_run "Installing relay helper" install_relay_script
    substep_run "Installing BPF helper script" install_bpf_helper
    substep_run "Installing axdp command" install_axdp_command
    substep_run "Installing slot handler SDK" install_slot_handler_sdk
    substep_run "Installing shared runtime library" _install_runtime_common_assets
    substep_run "Installing default TOML config" install_toml_config
    substep_run "Installing launcher script" install_runner_script

    unset -f _install_runtime_common_assets
}

install_runtime_files_step() {
    step_begin "Installing runtime files"
    install_runtime_files
    IN_STEP=0; _STEP_NEWLINED=0
}

load_configured_slot_handlers_step() {
    [[ "${ACTIVE_BACKEND:-nftables}" == "xdp" ]] || return 0

    step_begin "Loading configured slot handlers"
    if load_slot_handlers; then
        step_ok
    else
        step_warn "slot handlers unavailable"
    fi
}

install_systemd_service() {
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF_UNIT
[Unit]
Description=Auto XDP Loader + Port Whitelist Auto-Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${RUNNER_SCRIPT}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF_UNIT

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
}

install_openrc_service() {
    cat > "/etc/init.d/${SERVICE_NAME}" <<EOF_OPENRC
#!/sbin/openrc-run
description="Auto XDP loader + port whitelist auto-sync"
command="${RUNNER_SCRIPT}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
    need net
}
EOF_OPENRC

    chmod +x "/etc/init.d/${SERVICE_NAME}"
    rc-update add "$SERVICE_NAME" default >/dev/null 2>&1 || true
    rc-service "$SERVICE_NAME" restart
}

run_initial_sync() {
    info "Running initial sync..."
    "$RUNNER_SCRIPT" --sync-once
}

run_initial_sync_step() {
    step_begin "Pre-seeding IPv4/IPv6 established TCP sessions"
    run_initial_sync >/dev/null 2>&1 || true
    step_ok
}

install_runtime_service_step() {
    step_begin "Installing and enabling system service"
    case "$INIT_SYSTEM" in
        systemd)
            install_systemd_service
            step_ok "systemd: $SERVICE_NAME"
            ;;
        openrc)
            install_openrc_service
            step_ok "openrc: $SERVICE_NAME"
            ;;
        *)
            step_warn "no init system detected — start manually: $RUNNER_SCRIPT"
            ;;
    esac
}
