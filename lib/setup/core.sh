_step_tag() {
    case "${1:-INFO}" in
        COMPILE) printf "${YELLOW}[COMPILING]${NC}" ;;
        *)       printf "${CYAN}[INFO]${NC}     " ;;
    esac
}

step_begin() {
    IN_STEP=1
    _STEP_NEWLINED=0
    _PENDING_NL=0
    _step_tag "${2:-INFO}"
    printf " %-60s" "$1 …"
}

step_ok() {
    local nl=$_STEP_NEWLINED
    local pending=$_PENDING_NL
    IN_STEP=0
    _STEP_NEWLINED=0
    _PENDING_NL=0
    if [[ $pending -eq 1 ]]; then
        printf " ${GREEN}✓${NC}%s\n" "${1:+  ($1)}"
    elif [[ $nl -eq 1 ]]; then
        printf "${_STEP_INDENT}${GREEN}✓${NC}%s\n" "${1:+  ($1)}"
    else
        [[ -n "${1:-}" ]] && printf "${GREEN}($1)${NC} ${GREEN}✓${NC}\n" || printf " ${GREEN}✓${NC}\n"
    fi
}

step_fail() {
    local nl=$_STEP_NEWLINED
    IN_STEP=0
    _STEP_NEWLINED=0
    if [[ $_PENDING_NL -eq 1 ]]; then
        printf "\n"
        _PENDING_NL=0
    elif [[ $nl -eq 0 ]]; then
        printf " ${RED}✗${NC}\n"
    fi
    printf "${_STEP_INDENT}${RED}[ERROR]${NC}  %s\n" "${1:-Failed}" >&2
}

step_warn() {
    local nl=$_STEP_NEWLINED
    local pending=$_PENDING_NL
    IN_STEP=0
    _STEP_NEWLINED=0
    _PENDING_NL=0
    if [[ $pending -eq 1 ]]; then
        printf " ${YELLOW}⚠${NC}%s\n" "${1:+  ($1)}"
    elif [[ $nl -eq 1 ]]; then
        printf "${_STEP_INDENT}${YELLOW}⚠${NC}%s\n" "${1:+  ($1)}"
    else
        printf " ${YELLOW}⚠${NC}%s\n" "${1:+  ($1)}"
    fi
}

substep_run() {
    local label="$1"
    shift

    if [[ $IN_STEP -eq 1 && $_STEP_NEWLINED -eq 0 ]]; then
        printf "\n"
        _STEP_NEWLINED=1
    fi

    if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi

    printf "${_STEP_INDENT}${CYAN}↳ [INFO]${NC}  %-46s" "${label} …"
    _STEP_NEWLINED=0

    if "$@"; then
        if [[ $_PENDING_NL -eq 1 ]]; then
            printf " ${GREEN}✓${NC}\n"
            _PENDING_NL=0
        else
            printf " ${GREEN}✓${NC}\n"
        fi
        _STEP_NEWLINED=1
        return 0
    else
        local status=$?
        if [[ $_PENDING_NL -eq 1 ]]; then
            printf " ${RED}✗${NC}\n"
            _PENDING_NL=0
        else
            printf " ${RED}✗${NC}\n"
        fi
        _STEP_NEWLINED=1
        return "$status"
    fi
}

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

print_installer_banner() {
    echo -e "\n${BOLD}${CYAN}  ╔═══════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}  ║      Auto XDP Installer           ║${NC}"
    echo -e "${BOLD}${CYAN}  ╚═══════════════════════════════════╝${NC}\n"
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

resolve_target_interfaces_step() {
    step_begin "Detecting network interfaces"
    if [[ $ALL_IFACES -eq 1 ]]; then
        mapfile -t IFACES < <(get_active_interfaces)
        [[ ${#IFACES[@]} -gt 0 ]] || die "No active non-loopback interfaces found."
    elif [[ ${#IFACES[@]} -eq 0 ]]; then
        local _default_iface
        _default_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
        [[ -n "$_default_iface" ]] || die "Cannot detect default interface. Specify manually: sudo bash $0 eth0"
        IFACES=("$_default_iface")
    fi

    local _iface
    for _iface in "${IFACES[@]}"; do
        ip link show "$_iface" &>/dev/null || die "Interface '$_iface' does not exist."
    done

    IFACE="${IFACES[0]}"
    step_ok "Found: ${IFACES[*]}"
}

check_root_privileges() {
    step_begin "Checking root privileges"
    [[ $EUID -eq 0 ]] || die "Please run this script with sudo."
    step_ok
}

print_deployment_summary() {
    echo ""
    cat <<'EOF'
      █████████   █████  █████ ███████████    ███████       █████ █████ ██████████   ███████████
     ███▒▒▒▒▒███ ▒▒███  ▒▒███ ▒█▒▒▒███▒▒▒█  ███▒▒▒▒▒███    ▒▒███ ▒▒███ ▒▒███▒▒▒▒███ ▒▒███▒▒▒▒▒███
    ▒███    ▒███  ▒███   ▒███ ▒   ▒███  ▒  ███     ▒▒███    ▒▒███ ███   ▒███   ▒▒███ ▒███    ▒███
    ▒███████████  ▒███   ▒███     ▒███    ▒███      ▒███     ▒▒█████    ▒███    ▒███ ▒██████████
    ▒███▒▒▒▒▒███  ▒███   ▒███     ▒███    ▒███      ▒███      ███▒███   ▒███    ▒███ ▒███▒▒▒▒▒▒
    ▒███    ▒███  ▒███   ▒███     ▒███    ▒▒███     ███      ███ ▒▒███  ▒███    ███  ▒███
    █████   █████ ▒▒████████      █████    ▒▒▒███████▒      █████ █████ ██████████   █████
    ▒▒▒▒▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒▒      ▒▒▒▒▒       ▒▒▒▒▒▒▒       ▒▒▒▒▒ ▒▒▒▒▒ ▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒
EOF
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Deployment Complete!                  ${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo ""
    if [[ ${#IFACES[@]} -eq 1 ]]; then
        echo "  Interface      : ${IFACES[0]}"
    else
        echo "  Interfaces     : ${IFACES[*]}"
    fi
    echo "  Active backend : $ACTIVE_BACKEND"
    if [[ "$ACTIVE_BACKEND" == "xdp" ]]; then
        echo "  XDP mode       : $ACTIVE_XDP_MODE"
        echo "  BPF maps       : $BPF_PIN_DIR/"
        echo "  TC egress obj  : $TC_OBJ_INSTALLED"
    else
        echo "  nftables table : inet auto_xdp"
    fi
    echo "  Init system    : $INIT_SYSTEM"
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        echo "  Service        : systemctl status $SERVICE_NAME"
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        echo "  Service        : rc-service $SERVICE_NAME status"
    else
        echo "  Service        : not installed"
    fi
    echo "  Launcher       : $RUNNER_SCRIPT"
    echo "  Command        : $AXDP_CMD"
    echo ""
    echo "  Next Commands"
    echo "  axdp           : sudo axdp"
    echo "  axdp watch     : sudo axdp watch"
    echo "  axdp rates     : sudo axdp stats --rates"
    echo "  axdp live      : sudo axdp stats --watch --rates --interval 2"
    echo "  axdp sync      : sudo axdp sync"
    echo "  axdp ports      : sudo axdp ports"
    if [[ "$INIT_SYSTEM" == "systemd" || "$INIT_SYSTEM" == "openrc" ]]; then
        echo "  service status : sudo axdp status"
        echo "  service restart: sudo axdp restart"
    fi
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
