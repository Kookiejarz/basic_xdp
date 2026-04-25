usage() {
    cat <<'EOF'
Usage: sudo bash setup_xdp.sh [--check-update] [--force] [--all-interfaces] [interface...]

Options:
  --check-update     Compare local files with GitHub by SHA-256 and ask before pulling
  --force            Skip confirmations and apply update/replace actions automatically
  --check-env        Print detected package manager and init system, then exit
  --dry-run          Report planned actions without changing the system
  --all-interfaces   Deploy to all active non-loopback interfaces automatically
  -h, --help         Show this help

Examples:
  sudo bash setup_xdp.sh                    # auto-detect default route interface
  sudo bash setup_xdp.sh --all-interfaces   # deploy to all active interfaces
  sudo bash setup_xdp.sh eth0 eth1          # deploy to specific interfaces
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check-update)
                CHECK_UPDATES=1
                shift
                ;;
            --force)
                FORCE=1
                shift
                ;;
            --check-env)
                CHECK_ENV=1
                shift
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --all-interfaces|-a)
                ALL_IFACES=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            --)
                shift
                break
                ;;
            -*)
                die "Unknown option: $1"
                ;;
            *)
                IFACES+=("$1")
                shift
                ;;
        esac
    done

    if [[ $# -gt 0 ]]; then
        die "Unexpected argument: $1"
    fi
}

get_active_interfaces() {
    ip -o link show up 2>/dev/null \
        | awk -F': ' '{print $2}' \
        | awk '{print $1}' \
        | grep -v '^lo$' \
        | grep -v '@' \
        | grep -v '^dummy' \
        | grep -v '^virbr' \
        | grep -v '^docker' \
        | grep -v '^veth' \
        | grep -v '^br-' \
        || true
}

dry_run_report() {
    detect_pkg_manager || die "No supported package manager found."
    detect_init_system

    local detected_ifaces=""
    if [[ $ALL_IFACES -eq 1 ]]; then
        detected_ifaces=$(get_active_interfaces | tr '\n' ' ' | sed 's/[[:space:]]*$//')
    elif [[ ${#IFACES[@]} -gt 0 ]]; then
        detected_ifaces="${IFACES[*]}"
    else
        detected_ifaces=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)
    fi

    echo "mode=dry-run"
    echo "distro_id=$DISTRO_ID"
    echo "distro_name=$DISTRO_NAME"
    echo "distro_family=$DISTRO_FAMILY"
    echo "package_manager=$PKG_MANAGER"
    echo "init_system=$INIT_SYSTEM"
    echo "interfaces=${detected_ifaces:-undetected}"
    echo "missing_commands=$(for cmd in clang bpftool python3 curl ip tc nft; do command -v "$cmd" >/dev/null 2>&1 || printf '%s ' "$cmd"; done | sed 's/[[:space:]]*$//')"
    echo "planned_packages=$(package_list_for_manager; optional_package_list_for_manager; printf ' python3-psutil')"
    echo "planned_actions=check-dependencies,compile-xdp,deploy-backend,install-runtime,initial-sync,install-service"
    echo "note=dry-run performs no installs, no downloads, and no system changes"
}
