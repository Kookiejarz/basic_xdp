# lib/setup/backend_xdp.sh — XDP attach/detach backend helpers
# Sourced by setup_xdp.sh after build.sh and runtime_common.

cleanup_existing_xdp() {
    # Scan ALL system interfaces, not just IFACES: a previous install may have
    # attached XDP to different interfaces. Discovery and confirmation happen
    # before staging, but the programs remain attached until the candidate XDP
    # program has committed successfully.
    local iface any_xdp=0
    XDP_PREVIOUS_IFACES=()
    for iface in $(ls /sys/class/net/ 2>/dev/null); do
        if ip -d link show dev "$iface" 2>/dev/null \
                | grep -Eq '(^|[[:space:]])prog/xdp([[:space:]]|$)|(^|[[:space:]])xdpgeneric([[:space:]]|$)|(^|[[:space:]])xdpoffload([[:space:]]|$)'; then
            XDP_PREVIOUS_IFACES+=("$iface")
            any_xdp=1
        fi
    done

    if [[ $any_xdp -eq 1 ]]; then
        local iface_list="${XDP_PREVIOUS_IFACES[*]}"
        info "Existing XDP program detected on: $iface_list — transactional replacement planned"
        # A detected reinstall (EXISTING_INSTALL=1) means this is our own prior
        # attach; same no-prompt precedent as replace_existing_install_step.
        # Only prompt when some other XDP program is present on a fresh install.
        if [[ ${EXISTING_INSTALL:-0} -eq 1 ]]; then
            :
        elif confirm_yes_no "Unload the existing XDP program from all interfaces and continue? [y/N] " "abort"; then
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

    fi
}

deploy_xdp_backend() {
    XDP_FALLBACK_BLOCKED=0
    if [[ ! -f "$XDP_OBJ_INSTALLED" ]]; then
        XDP_FALLBACK_REASON="compiled XDP object not found"
        warn "XDP unavailable: compiled object not found; continuing with nftables backend."
        return 1
    fi

    ensure_bpffs
    cleanup_existing_xdp

    if ! transactional_reload_xdp; then
        XDP_FALLBACK_REASON="transactional XDP switch failed; previous attachment was preserved or restored"
        warn "XDP upgrade failed transactionally; previous protection was preserved or restored."
        if _auto_xdp_any_target_has_xdp; then
            XDP_FALLBACK_BLOCKED=1
            warn "Refusing nftables fallback while XDP remains attached."
        fi
        return 1
    fi

    ACTIVE_XDP_MODE="$AUTO_XDP_SWITCH_MODE"
    load_sock_state_tracker || true

    # Old attachments on interfaces removed from IFACES are detached only after
    # the target interfaces have committed successfully.
    local old_iface target keep
    for old_iface in "${XDP_PREVIOUS_IFACES[@]}"; do
        keep=0
        for target in "${IFACES[@]}"; do
            [[ "$old_iface" == "$target" ]] && keep=1
        done
        if [[ $keep -eq 0 ]]; then
            ip link set dev "$old_iface" xdp off 2>/dev/null || true
            ip link set dev "$old_iface" xdpgeneric off 2>/dev/null || true
            ip link set dev "$old_iface" xdpoffload off 2>/dev/null || true
        fi
    done

    auto_tune_interface_parallelism || true
    ACTIVE_BACKEND="xdp"
    return 0
}

deploy_backend_step() {
    REQUESTED_BACKEND=$(_auto_xdp_resolve_preferred_backend "$TOML_CONFIG" "auto")
    step_begin "Loading backend on ${IFACES[*]}"
    if [[ "$REQUESTED_BACKEND" == "nftables" ]]; then
        ACTIVE_BACKEND="nftables"
        ACTIVE_XDP_MODE="none"
        XDP_FALLBACK_REASON="explicitly selected by daemon.preferred_backend"
        if ensure_nftables_available; then
            PENDING_NFT_CUTOVER=1
            step_ok "nftables candidate; XDP removal follows policy verification"
            return 0
        fi
        step_fail "nftables was explicitly requested but is unavailable"
        return 1
    fi

    if deploy_xdp_backend; then
        cleanup_existing_nftables
        XDP_FALLBACK_REASON=""
        step_ok "XDP $ACTIVE_XDP_MODE mode"
    else
        if [[ "$REQUESTED_BACKEND" == "xdp" ]]; then
            step_fail "XDP was explicitly requested and transactional loading failed; fallback disabled"
            return 1
        fi
        if [[ ${XDP_FALLBACK_BLOCKED:-0} -eq 1 ]]; then
            step_fail "XDP reload failed while an XDP attachment remains active; nftables fallback was not started."
            return 1
        fi
        ACTIVE_BACKEND="nftables"
        ACTIVE_XDP_MODE="none"
        if ensure_nftables_available; then
            PENDING_NFT_CUTOVER=1
            step_ok "nftables fallback"
        else
            die "Neither XDP nor nftables backend is available."
        fi
    fi
}
