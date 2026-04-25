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

write_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<EOF_CFG
IFACES="${IFACES[*]}"
IFACE="${IFACES[0]}"
SYNC_INTERVAL="${SYNC_INTERVAL}"
LOG_LEVEL="${LOG_LEVEL}"
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
    local bpf_root="${pkg_root}/bpf"

    mkdir -p "$bpf_root"

    fetch_local_or_remote "auto_xdp/__init__.py" "auto_xdp/__init__.py" "${pkg_root}/__init__.py" || return 1
    fetch_local_or_remote "auto_xdp/config.py" "auto_xdp/config.py" "${pkg_root}/config.py" || return 1
    fetch_local_or_remote "auto_xdp/bpf/__init__.py" "auto_xdp/bpf/__init__.py" "${bpf_root}/__init__.py" || return 1
    fetch_local_or_remote "auto_xdp/bpf/maps.py" "auto_xdp/bpf/maps.py" "${bpf_root}/maps.py" || return 1
    fetch_local_or_remote "auto_xdp/bpf/syscall.py" "auto_xdp/bpf/syscall.py" "${bpf_root}/syscall.py" || return 1
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

install_toml_config() {
    local toml_target="${CONFIG_DIR}/config.toml"
    mkdir -p "$CONFIG_DIR"

    if [[ -f "$toml_target" ]]; then
        if confirm_yes_no "config.toml already exists at ${toml_target}. Replace with repo default? [y/N] "; then
            info "Replacing config.toml with repo default."
        else
            info "Keeping existing config.toml."
            return 0
        fi
    fi

    if ! fetch_local_or_remote "config.toml" "config.toml" "$toml_target"; then
        die "Failed to install config.toml"
    fi
}

install_runtime_files() {
    info "Installing runtime files..."
    mkdir -p "$INSTALL_DIR"
    install_sync_script
    install_python_support_package
    install_relay_script
    install_bpf_helper
    install_axdp_command
    install_runtime_common_script
    write_config
    install_toml_config
    install_runner_script
    ok "Runtime installed under $INSTALL_DIR and $CONFIG_DIR"
}

install_systemd_service() {
    info "Creating systemd service: $SERVICE_NAME..."
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
    ok "Service started and enabled: $SERVICE_NAME"
}

install_openrc_service() {
    info "Creating OpenRC service: $SERVICE_NAME..."
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
    ok "OpenRC service started and enabled: $SERVICE_NAME"
}

run_initial_sync() {
    info "Running initial sync..."
    "$RUNNER_SCRIPT" --sync-once
}
