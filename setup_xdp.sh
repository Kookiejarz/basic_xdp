#!/bin/bash

# setup_xdp.sh — Auto XDP installer / loader / fallback bootstrap
# Usage: sudo bash setup_xdp.sh [--check-update] [--force] [--check-env] [--dry-run] [interface]
# Supports Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

IN_STEP=0
_STEP_NEWLINED=0
# Prefix used to indent sub-lines inside a step (aligns with label text).
_STEP_INDENT="             "

info()  { if [[ $IN_STEP -eq 0 ]]; then echo -e "${CYAN}[INFO]${NC}  $*"; fi; }
ok()    { if [[ $IN_STEP -eq 0 ]]; then echo -e "${GREEN}[ OK ]${NC}  $*"; fi; }
warn()  {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then printf "\n"; _STEP_NEWLINED=1; fi
        printf "${_STEP_INDENT}${YELLOW}↳ [WARN]${NC}  %s\n" "$*"
    else
        echo -e "${YELLOW}[WARN]${NC}  $*"
    fi
}
die()   {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then
            printf " ${RED}✗${NC}\n"
        else
            printf "${_STEP_INDENT}${RED}✗${NC}\n"
        fi
        IN_STEP=0; _STEP_NEWLINED=0
    fi
    echo -e "${RED}[ERR ]${NC}  $*" >&2
    exit 1
}

_step_tag() {
    case "${1:-INFO}" in
        COMPILE) printf "${YELLOW}[COMPILING]${NC}" ;;
        *)       printf "${CYAN}[INFO]${NC}     " ;;
    esac
}
step_begin() {
    IN_STEP=1; _STEP_NEWLINED=0
    _step_tag "${2:-INFO}"
    printf " %-60s" "$1 …"
}
step_ok() {
    local nl=$_STEP_NEWLINED
    IN_STEP=0; _STEP_NEWLINED=0
    if [[ $nl -eq 1 ]]; then
        printf "${_STEP_INDENT}${GREEN}✓${NC}%s\n" "${1:+  ($1)}"
    else
        [[ -n "${1:-}" ]] && printf "${GREEN}($1)${NC} ${GREEN}✓${NC}\n" || printf " ${GREEN}✓${NC}\n"
    fi
}
step_fail() {
    local nl=$_STEP_NEWLINED
    IN_STEP=0; _STEP_NEWLINED=0
    if [[ $nl -eq 0 ]]; then printf " ${RED}✗${NC}\n"; fi
    printf "${_STEP_INDENT}${RED}[ERROR]${NC}  %s\n" "${1:-Failed}" >&2
}
step_warn() {
    local nl=$_STEP_NEWLINED
    IN_STEP=0; _STEP_NEWLINED=0
    if [[ $nl -eq 1 ]]; then
        printf "${_STEP_INDENT}${YELLOW}⚠${NC}%s\n" "${1:+  ($1)}"
    else
        printf " ${YELLOW}⚠${NC}%s\n" "${1:+  ($1)}"
    fi
}

IFACE=""
IFACES=()
ALL_IFACES=0
XDP_SRC="xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
TC_SRC="tc_flow_track.c"
TC_OBJ="tc_flow_track.o"
SYNC_INTERVAL=30

INSTALL_DIR="/usr/local/lib/auto_xdp"
PYTHON_LIB_DIR="${INSTALL_DIR}/python"
AUTO_XDP_PACKAGE_DIR="${PYTHON_LIB_DIR}/auto_xdp"
CONFIG_DIR="/etc/auto_xdp"
CONFIG_FILE="${CONFIG_DIR}/auto_xdp.env"
TOML_CONFIG="${CONFIG_DIR}/config.toml"
SYNC_SCRIPT="/usr/local/bin/xdp_port_sync.py"
RELAY_SCRIPT="/usr/local/bin/pkt_relay.py"
AXDP_CMD="/usr/local/bin/axdp"
RUNNER_SCRIPT="/usr/local/bin/auto_xdp_start.sh"
RUNNER_SRC="runtime/auto_xdp_start.sh"
RUNTIME_COMMON_SRC="runtime/auto_xdp_runtime_common.sh"
XDP_OBJ_INSTALLED="${INSTALL_DIR}/xdp_firewall.o"
TC_OBJ_INSTALLED="${INSTALL_DIR}/tc_flow_track.o"
BPF_RUNTIME_COMMON_INSTALLED="${INSTALL_DIR}/auto_xdp_runtime_common.sh"
BPF_HELPER_SRC="auto_xdp_bpf_helpers.py"
BPF_HELPER_INSTALLED="${INSTALL_DIR}/auto_xdp_bpf_helpers.py"
BPF_HELPER_BOOTSTRAP=""

export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SERVICE_NAME="xdp-port-sync"
RAW_URL="https://raw.githubusercontent.com/Kookiejarz/auto_xdp/main"
TC_FILTER_PREF=49152
PREFER_REMOTE_SOURCES=0
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"
SYSTEMD_RUN_DIR="${SYSTEMD_RUN_DIR:-/run/systemd/system}"

case "${BASH_SOURCE[0]:-}" in
    stdin|/dev/stdin|/dev/fd/*|/proc/self/fd/*)
        # curl | bash should use the matching GitHub sources instead of stale
        # files from the caller's working directory.
        PREFER_REMOTE_SOURCES=1
        ;;
esac
if [[ $PREFER_REMOTE_SOURCES -eq 0 ]]; then
    # Some shells expose stdin execution as "bash" instead of /dev/fd/*.
    # Also prefer remote sources when the script path is not a readable file.
    if [[ "${BASH_SOURCE[0]:-}" == "bash" || ! -r "${BASH_SOURCE[0]:-}" ]]; then
        PREFER_REMOTE_SOURCES=1
    fi
fi

PKG_MANAGER=""
INIT_SYSTEM="none"
SYSTEMD_AVAILABLE=0
OPENRC_AVAILABLE=0
ACTIVE_BACKEND="nftables"
ACTIVE_XDP_MODE="none"
PYTHON3_BIN=""
LOG_LEVEL="info"
CHECK_UPDATES=0
FORCE=0
CHECK_ENV=0
DRY_RUN=0
DISTRO_ID="unknown"
DISTRO_NAME="unknown"
DISTRO_LIKE=""
DISTRO_FAMILY="unknown"

source_setup_lib() {
    local relative_path="$1"
    local source_path="$relative_path"
    if [[ $PREFER_REMOTE_SOURCES -eq 1 || ! -r "$source_path" ]]; then
        source_path=$(mktemp)
        curl -fsSL "${RAW_URL}/${relative_path}" -o "$source_path" \
            || die "Failed to load ${relative_path}"
    fi
    # shellcheck disable=SC1090
    source "$source_path"
}

source_setup_lib "lib/setup/core.sh"
source_setup_lib "lib/setup/detect.sh"
source_setup_lib "lib/setup/packages.sh"
source_setup_lib "lib/setup/fetch.sh"
source_setup_lib "lib/setup/build.sh"
source_setup_lib "lib/setup/backend_xdp.sh"
source_setup_lib "lib/setup/backend_nft.sh"

auto_xdp_shared_info() {
    info "$@"
}

auto_xdp_shared_warn() {
    warn "$@"
}

load_runtime_common_lib() {
    local lib_path="$RUNTIME_COMMON_SRC"
    if [[ $PREFER_REMOTE_SOURCES -eq 1 || ! -r "$lib_path" ]]; then
        lib_path=$(mktemp)
        if ! fetch_local_or_remote "$RUNTIME_COMMON_SRC" "$RUNTIME_COMMON_SRC" "$lib_path"; then
            die "Failed to load ${RUNTIME_COMMON_SRC}"
        fi
    fi
    # shellcheck disable=SC1090
    source "$lib_path"
}

load_runtime_common_lib
source_setup_lib "lib/setup/install.sh"

main() {
    parse_args "$@"

    if [[ $CHECK_ENV -eq 1 ]]; then
        detect_os_release
        detect_pkg_manager || die "No supported package manager found."
        detect_init_system
        echo "distro_id=$DISTRO_ID"
        echo "distro_name=$DISTRO_NAME"
        echo "distro_family=$DISTRO_FAMILY"
        echo "package_manager=$PKG_MANAGER"
        echo "init_system=$INIT_SYSTEM"
        exit 0
    fi

    if [[ $DRY_RUN -eq 1 ]]; then
        dry_run_report
        exit 0
    fi

    echo -e "\n${BOLD}${CYAN}  ╔═══════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYAN}  ║      Auto XDP Installer           ║${NC}"
    echo -e "${BOLD}${CYAN}  ╚═══════════════════════════════════╝${NC}\n"

    # 1. Root check
    step_begin "Checking root privileges"
    [[ $EUID -eq 0 ]] || die "Please run this script with sudo."
    step_ok

    # 2. Interface detection
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

    # 3. Package manager
    step_begin "Detecting default package manager"
    detect_pkg_manager || die "No supported package manager found."
    detect_init_system
    step_ok "Found: $PKG_MANAGER"

    # 4. Dependencies
    step_begin "Checking required tools"
    MISSING=()
    for cmd in clang bpftool python3 curl ip tc nft; do
        command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
    done
    if [[ ${#MISSING[@]} -gt 0 ]]; then
        step_warn "Missing: ${MISSING[*]} — installing via $PKG_MANAGER"
        step_begin "Installing missing packages via $PKG_MANAGER"
        install_packages || die "Package installation failed."
        step_ok
        step_begin "Verifying installed tools"
    fi
    command -v python3 &>/dev/null || die "python3 not found after installation."
    command -v curl    &>/dev/null || die "curl not found after installation."
    command -v ip      &>/dev/null || die "ip command not found after installation."
    ensure_psutil
    PYTHON3_BIN=$(command -v python3)
    step_ok

    # 5. BPF helper
    step_begin "Fetching BPF helper script"
    if ensure_bpf_helper_bootstrap; then
        step_ok
    else
        step_warn "map operations limited"
    fi

    if ! command -v bpftool &>/dev/null || ! command -v clang &>/dev/null; then
        echo -e "  ${YELLOW}[WARN]${NC}  bpftool or clang still missing — XDP backend may be unavailable."
    fi

    # 6. Stop existing runtime
    step_begin "Stopping existing service"
    stop_existing_service
    step_ok

    # 7. Compile BPF objects
    step_begin "Compiling XDP and tc BPF objects" COMPILE
    if compile_xdp_program; then
        step_ok
    else
        step_warn "compile failed — nftables fallback will be used"
    fi

    # 8. Deploy backend
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

    # 9. Install runtime files
    step_begin "Installing runtime files"
    install_runtime_files
    step_ok

    # 10. Initial sync — pre-seeds existing TCP sessions into conntrack map
    step_begin "Pre-seeding IPv4/IPv6 established TCP sessions"
    run_initial_sync >/dev/null 2>&1 || true
    step_ok

    # 11. Install system service
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

    # 12. Cleanup build artifacts
    step_begin "Cleaning up build artifacts"
    local _cleaned=()
    for _f in "$XDP_OBJ" "$TC_OBJ"; do
        if [[ -f "$_f" ]]; then
            rm -f "$_f" && _cleaned+=("$_f")
        fi
    done
    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        for _f in "$XDP_SRC" "$TC_SRC"; do
            if [[ -f "$_f" ]]; then
                rm -f "$_f" && _cleaned+=("$_f")
            fi
        done
    fi
    if [[ -n "$BPF_HELPER_BOOTSTRAP" && "$BPF_HELPER_BOOTSTRAP" != "$BPF_HELPER_SRC" && -f "$BPF_HELPER_BOOTSTRAP" ]]; then
        rm -f "$BPF_HELPER_BOOTSTRAP" && _cleaned+=("$BPF_HELPER_BOOTSTRAP")
    fi
    if [[ ${#_cleaned[@]} -gt 0 ]]; then
        step_ok "Removed: ${_cleaned[*]}"
    else
        step_ok "Nothing to remove"
    fi

    # Summary
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

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
