#!/bin/bash

# setup_xdp.sh — Auto XDP installer / loader / fallback bootstrap
# Usage: sudo bash setup_xdp.sh [--check-update] [--force] [--check-env] [--dry-run] [interface]
# Supports Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

IN_STEP=0
_STEP_NEWLINED=0
_PENDING_NL=0
# Prefix used to indent sub-lines inside a step (aligns with label text).
_STEP_INDENT="             "

info()  {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then printf "\n"; _STEP_NEWLINED=1; fi
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; fi
        printf "${_STEP_INDENT}${CYAN}↳ [INFO]${NC}  %s" "$*"
        _PENDING_NL=1
    else
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        echo -e "${CYAN}[INFO]${NC}  $*"
    fi
}
ok()    { if [[ $IN_STEP -eq 0 ]]; then echo -e "${GREEN}[ OK ]${NC}  $*"; fi; }
warn()  {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then printf "\n"; _STEP_NEWLINED=1; fi
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        printf "${_STEP_INDENT}${YELLOW}↳ [WARN]${NC}  %s\n" "$*"
    else
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        echo -e "${YELLOW}[WARN]${NC}  $*"
    fi
}
die()   {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then
            printf " ${RED}✗${NC}\n"
        else
            if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; fi
            printf "${_STEP_INDENT}${RED}✗${NC}\n"
        fi
        IN_STEP=0; _STEP_NEWLINED=0; _PENDING_NL=0
    fi
    echo -e "${RED}[ERR ]${NC}  $*" >&2
    exit 1
}

IFACE=""
IFACES=()
ALL_IFACES=0
XDP_SRC="bpf/xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
TC_SRC="tc_flow_track.c"
TC_OBJ="tc_flow_track.o"

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

    print_installer_banner
    check_root_privileges
    resolve_target_interfaces_step
    detect_environment_step
    check_required_tools_step
    bootstrap_bpf_helper_step
    stop_existing_service_step
    compile_bpf_objects_step
    deploy_backend_step
    install_runtime_files_step
    load_configured_slot_handlers_step
    run_initial_sync_step
    install_runtime_service_step
    cleanup_build_artifacts_step
    print_deployment_summary
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
