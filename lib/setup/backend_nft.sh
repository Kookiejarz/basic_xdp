# lib/setup/backend_nft.sh — nftables fallback backend helpers
# Sourced by setup_xdp.sh after build.sh.

ensure_nftables_available() {
    if command -v nft &>/dev/null; then
        return 0
    fi

    warn "nft not found — attempting to install nftables..."
    pkg_install_optional nftables
    command -v nft &>/dev/null
}

cleanup_existing_nftables() {
    command -v nft &>/dev/null || return 0
    local family="${NFT_FAMILY:-inet}" table="${NFT_TABLE:-auto_xdp}"
    nft list table "$family" "$table" &>/dev/null || return 0
    if nft delete table "$family" "$table" 2>/dev/null; then
        info "nftables $family $table table removed (replaced by XDP)"
    else
        warn "Could not remove $family $table table; remove manually if needed."
    fi
}

verify_nftables_policy() {
    command -v nft &>/dev/null || return 1
    local body
    body=$(nft list table "${NFT_FAMILY:-inet}" "${NFT_TABLE:-auto_xdp}" 2>/dev/null) || return 1
    printf '%s' "$body" | grep -Fq 'set tcp_ports' || return 1
    printf '%s' "$body" | grep -Fq 'chain input'
}

finalize_nftables_cutover() {
    verify_nftables_policy || return 1
    local iface mode prog_id pin index detached=0 rollback_ok=1 have_xdp=0
    local rollback_dir="${BPF_PIN_DIR}_nft_cutover_${BASHPID:-$$}"
    local -a old_modes=() rollback_pins=()

    # Pin every currently attached program before removing any of them. This
    # also makes an explicit nftables cutover reversible when the old XDP
    # program was not loaded from auto_xdp's normal live pin directory.
    for iface in "${IFACES[@]}"; do
        mode=$(_auto_xdp_iface_xdp_mode "$iface")
        old_modes+=("$mode")
        rollback_pins+=("")
        [[ "$mode" == "none" ]] || have_xdp=1
    done
    if [[ $have_xdp -eq 1 ]]; then
        mkdir "$rollback_dir" || return 1
        for index in "${!IFACES[@]}"; do
            [[ "${old_modes[$index]}" == "none" ]] && continue
            prog_id=$(_auto_xdp_iface_prog_id "${IFACES[$index]}") || {
                for pin in "${rollback_pins[@]}"; do [[ -z "$pin" ]] || rm -f "$pin"; done
                rmdir "$rollback_dir" 2>/dev/null || true
                return 1
            }
            pin="${rollback_dir}/prog_${index}"
            rollback_pins[$index]="$pin"
            bpftool prog pin id "$prog_id" "$pin" || {
                for pin in "${rollback_pins[@]}"; do [[ -z "$pin" ]] || rm -f "$pin"; done
                rmdir "$rollback_dir" 2>/dev/null || true
                return 1
            }
        done
    fi

    for index in "${!IFACES[@]}"; do
        iface="${IFACES[$index]}"
        mode="${old_modes[$index]}"
        [[ "$mode" == "none" ]] || _auto_xdp_detach_mode "$iface" "$mode"
        if [[ "$(_auto_xdp_iface_xdp_mode "$iface")" != "none" ]]; then
            warn "Failed to remove XDP from $iface after nftables verification; restoring previous attachments."
            for ((index = 0; index < detached; index++)); do
                [[ "${old_modes[$index]}" == "none" ]] && continue
                _auto_xdp_attach_mode "${IFACES[$index]}" "${rollback_pins[$index]}" \
                    "${old_modes[$index]}" >/dev/null 2>&1 \
                    && _auto_xdp_verify_iface_program \
                        "${IFACES[$index]}" "${rollback_pins[$index]}" \
                    || rollback_ok=0
            done
            if [[ $rollback_ok -eq 1 ]]; then
                for pin in "${rollback_pins[@]}"; do [[ -z "$pin" ]] || rm -f "$pin"; done
                [[ $have_xdp -eq 0 ]] || rmdir "$rollback_dir" 2>/dev/null || true
            else
                warn "XDP rollback was incomplete; retained recovery pins in $rollback_dir."
            fi
            return 1
        fi
        detached=$((detached + 1))
    done
    for pin in "${rollback_pins[@]}"; do [[ -z "$pin" ]] || rm -f "$pin"; done
    [[ $have_xdp -eq 0 ]] || rmdir "$rollback_dir" 2>/dev/null || true

    for iface in "${IFACES[@]}"; do
        [[ "$(_auto_xdp_iface_xdp_mode "$iface")" == "none" ]] || return 1
    done
    PENDING_NFT_CUTOVER=0
    ACTIVE_XDP_MODE="none"
    local python_root="${PYTHON_LIB_DIR:-${SOURCE_ROOT:-.}}"
    local generation
    generation=$(_auto_xdp_runtime_generation)
    local -a reason_args=()
    [[ -n "${XDP_FALLBACK_REASON:-}" ]] && reason_args=(--fallback-reason "$XDP_FALLBACK_REASON")
    PYTHONPATH="$python_root${PYTHONPATH:+:$PYTHONPATH}" \
        "${PYTHON3_BIN:-python3}" -m auto_xdp.install_state record \
        --machine-state "$MACHINE_STATE" \
        --runtime-state "$RUNTIME_STATE" \
        --requested-backend "${REQUESTED_BACKEND:-auto}" \
        --active-backend nftables \
        --generation "$generation" \
        "${reason_args[@]}" >/dev/null || return 1
    return 0
}
