# lib/setup/backend_xdp.sh — XDP attach/detach backend helpers
# Sourced by setup_xdp.sh after build.sh and runtime_common.

cleanup_existing_xdp() {
    cleanup_tc_egress_filter

    local iface any_xdp=0
    for iface in "${IFACES[@]}"; do
        if ip -d link show dev "$iface" 2>/dev/null | grep -Eq 'xdp|xdpgeneric|xdpoffload'; then
            any_xdp=1
            break
        fi
    done

    if [[ $any_xdp -eq 1 ]]; then
        local iface_list="${IFACES[*]}"
        warn "Existing XDP program detected on one or more interfaces: $iface_list"
        if confirm_yes_no "Unload the existing XDP program from all interfaces and continue? [y/N] " "abort"; then
            :
        else
            confirm_rc=$?
            case "$confirm_rc" in
                2)
                    die "Cannot confirm unloading because no interactive TTY is available. Re-run with --force."
                    ;;
                *)
                    die "Aborted before unloading the existing XDP program."
                    ;;
            esac
        fi

        for iface in "${IFACES[@]}"; do
            ip link set dev "$iface" xdp off 2>/dev/null || true
            ip link set dev "$iface" xdp generic off 2>/dev/null || true
        done

        for iface in "${IFACES[@]}"; do
            if ip -d link show dev "$iface" 2>/dev/null | grep -Eq 'xdp|xdpgeneric|xdpoffload'; then
                die "Failed to clear the existing XDP program from $iface. Detach it manually and rerun."
            fi
        done
    fi

    if [[ -d "$BPF_PIN_DIR" ]]; then
        warn "Removing old BPF pin directory $BPF_PIN_DIR..."
        rm -rf "$BPF_PIN_DIR"
    fi
    mkdir -p "$BPF_PIN_DIR"
}

deploy_xdp_backend() {
    if [[ ! -f "$XDP_OBJ_INSTALLED" ]]; then
        warn "Compiled XDP object not found; skipping XDP backend."
        return 1
    fi

    ensure_bpffs
    cleanup_existing_xdp

    if ! bpftool prog load "$XDP_OBJ_INSTALLED" "$BPF_PIN_DIR/prog" type xdp \
            pinmaps "$BPF_PIN_DIR"; then
        warn "bpftool prog load failed; falling back from XDP."
        rm -rf "$BPF_PIN_DIR"
        return 1
    fi

    if ! xdp_maps_ready; then
        warn "Pinned XDP maps are incomplete after pinning; falling back from XDP."
        rm -rf "$BPF_PIN_DIR"
        return 1
    fi

    seed_existing_tcp_conntrack
    load_tc_egress_program || true

    local iface attached=0 _native_err _generic_err
    ACTIVE_XDP_MODE="native"
    for iface in "${IFACES[@]}"; do
        ethtool -K "$iface" lro off 2>/dev/null || true
        if _native_err=$(ip link set dev "$iface" xdp pinned "$BPF_PIN_DIR/prog" 2>&1); then
            attached=$((attached + 1))
        elif _generic_err=$(ip link set dev "$iface" xdp generic pinned "$BPF_PIN_DIR/prog" 2>&1); then
            ACTIVE_XDP_MODE="generic"
            attached=$((attached + 1))
        else
            warn "Failed to attach XDP to $iface (skipping this interface)"
            [[ -n "$_native_err" ]] && warn "  ↳ native:  $_native_err"
            [[ -n "$_generic_err" ]] && warn "  ↳ generic: $_generic_err"
        fi
    done

    if [[ $attached -gt 0 ]]; then
        ACTIVE_BACKEND="xdp"
        return 0
    fi

    warn "XDP could not be attached to any interface — using nftables fallback."
    cleanup_tc_egress_filter
    for iface in "${IFACES[@]}"; do
        ip link set dev "$iface" xdp off 2>/dev/null || true
    done
    rm -rf "$BPF_PIN_DIR"
    return 1
}

deploy_backend_step() {
    step_begin "Loading backend on ${IFACES[*]}"
    if deploy_xdp_backend; then
        cleanup_existing_nftables
        step_ok "XDP $ACTIVE_XDP_MODE mode"
    else
        ACTIVE_BACKEND="nftables"
        ACTIVE_XDP_MODE="none"
        if ensure_nftables_available; then
            step_ok "nftables fallback"
        else
            die "Neither XDP nor nftables backend is available."
        fi
    fi
}
