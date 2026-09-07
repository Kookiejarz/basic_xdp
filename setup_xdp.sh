#!/bin/bash

# setup_xdp.sh — Auto XDP installer / loader / fallback bootstrap
# Usage: bash setup_xdp.sh [--check-update] [--force] [--check-env] [--dry-run] [interface]
# Runs as an ordinary user and escalates with sudo only for the steps that need
# it; running the whole script with sudo still works.
# Supports Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.

set -euo pipefail

# Keep errors raised before setup libraries are loaded readable.  The shared
# helper below replaces these with TTY-aware values once it is available.
C_GREEN=''; C_RED=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_BOLD=''; C_RESET=''
GREEN=''; RED=''; YELLOW=''; CYAN=''; BOLD=''; NC=''

IN_STEP=0
_STEP_NEWLINED=0
_PENDING_NL=0
# Prefix used to indent sub-lines inside a step (aligns with label text).
_STEP_INDENT="             "
OK_MARK='✓'
WARN_MARK='!'
FAIL_MARK='✗'

if [[ -r "${BASH_SOURCE[0]:-}" ]]; then
    _early_setup_root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    if [[ -r "$_early_setup_root/lib/setup/log.sh" ]]; then
        # shellcheck disable=SC1090
        source "$_early_setup_root/lib/setup/log.sh"
    fi
fi
if ! declare -F log_printf >/dev/null 2>&1; then
    log_printf() {
        local rendered format="$1"
        shift
        printf -v rendered "$format" "$@"
        printf '%b' "$rendered"
    }
    log_eprintf() {
        local rendered format="$1"
        shift
        printf -v rendered "$format" "$@"
        printf '%b' "$rendered" >&2
    }
fi
if declare -F log_init_colors >/dev/null 2>&1; then
    log_init_colors
fi

info()  {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then printf "\n"; _STEP_NEWLINED=1; fi
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; fi
        printf "${_STEP_INDENT}${CYAN}[INFO]${NC}  %s" "$*"
        _PENDING_NL=1
    else
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        log_printf '%b\n' "${CYAN}[INFO]${NC}  $*"
    fi
}
warn()  {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then printf "\n"; _STEP_NEWLINED=1; fi
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        printf "${_STEP_INDENT}${YELLOW}[WARN]${NC}  %s\n" "$*"
    else
        if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; _PENDING_NL=0; fi
        log_printf '%b\n' "${YELLOW}[WARN]${NC}  $*"
    fi
}
die()   {
    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then
            printf " ${FAIL_MARK}\n"
        else
            if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; fi
            printf "${_STEP_INDENT}${FAIL_MARK}\n"
        fi
        IN_STEP=0; _STEP_NEWLINED=0; _PENDING_NL=0
    fi
    log_eprintf '%b\n' "${RED}[ERR ]${NC}  $*"
    exit 1
}

die_with_next() {
    local message="$1"
    local next_step="$2"

    if [[ $IN_STEP -eq 1 ]]; then
        if [[ $_STEP_NEWLINED -eq 0 ]]; then
            printf " ${FAIL_MARK}\n"
        else
            if [[ $_PENDING_NL -eq 1 ]]; then printf "\n"; fi
            printf "${_STEP_INDENT}${FAIL_MARK}\n"
        fi
        IN_STEP=0; _STEP_NEWLINED=0; _PENDING_NL=0
    fi
    log_eprintf '%b\n' "${RED}[ERR ]${NC}  $message"
    echo "       Next: $next_step" >&2
    exit 1
}

IFACE=""
IFACES=()
ALL_IFACES=0
XDP_SRC="bpf/xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"

INSTALL_ROOT="/usr/local/lib/auto_xdp"
RELEASES_DIR="${INSTALL_ROOT}/releases"
CURRENT_LINK="${INSTALL_ROOT}/current"
INSTALL_DIR="$CURRENT_LINK"
INSTALL_LOCK_DIR="/run/auto_xdp/install.lock"
RELEASE_NAME="${AUTO_XDP_RELEASE_NAME:-}"
RELEASE_CANDIDATE_DIR=""
PREVIOUS_RELEASE=""
PREVIOUS_ENV_CONFIG=""
INSTALL_TRANSACTION_ID=""
INSTALL_TRANSACTION_ACTIVE=0
INSTALL_TRANSACTION_COMMITTED=0
INSTALL_LOCK_HELD=0
PYTHON_LIB_DIR="${INSTALL_DIR}/python"
AUTO_XDP_PACKAGE_DIR="${PYTHON_LIB_DIR}/auto_xdp"
CONFIG_DIR="/etc/auto_xdp"
INSTALL_TRANSACTION_FILE="${CONFIG_DIR}/install-transaction.json"
CONFIG_FILE="${CONFIG_DIR}/auto_xdp.env"
TOML_CONFIG="${CONFIG_DIR}/config.toml"
SYNC_SCRIPT="${CURRENT_LINK}/xdp_port_sync.py"
RELAY_SCRIPT="${CURRENT_LINK}/pkt_relay.py"
AXDP_CMD="/usr/local/bin/axdp"
RUNNER_SCRIPT="${CURRENT_LINK}/auto_xdp_start.sh"
RUNNER_SRC="runtime/auto_xdp_start.sh"
RUNTIME_COMMON_SRC="runtime/auto_xdp_runtime_common.sh"
XDP_OBJ_INSTALLED="${INSTALL_DIR}/xdp_firewall.o"
SOCK_STATE_SRC="bpf/sock_state_track.c"
SOCK_STATE_OBJ="sock_state_track.o"
SOCK_STATE_OBJ_INSTALLED="${INSTALL_DIR}/sock_state_track.o"
BPF_HELPER_SRC="auto_xdp_bpf_helpers.py"
BPF_HELPER_INSTALLED="${INSTALL_DIR}/auto_xdp_bpf_helpers.py"
BPF_HELPER_BOOTSTRAP=""
BUILD_STAGING_DIR=""
SOURCE_ROOT="${AUTO_XDP_PRESTAGED_SOURCE_ROOT:-}"
BOOTSTRAP_LOCAL_ROOT=""
SOURCE_REVISION=""
SOURCE_VERSION=""
MACHINE_STATE="${CONFIG_DIR}/machine-state.json"
RUNTIME_STATE="${CONFIG_DIR}/runtime-state.json"
APPROVAL_STORE="${CONFIG_DIR}/approval_requests.json"
MACHINE_STATE_CANDIDATE=""
CANDIDATE_TOML_CONFIG=""
INTERFACE_CONFIG_MODE="auto"
INTERFACE_CONFIG_INCLUDE=()
INTERFACE_CONFIG_EXCLUDE=()
INTERFACE_ALLOW_CONTAINER=0
INTERFACE_XDP_MODE="auto"
INTERFACE_POLICY_PRESENT=0
AUTO_XDP_ALLOW_CONTAINER=0

export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SERVICE_NAME="xdp-port-sync"
RELAY_SERVICE_NAME="auto-xdp-relay"
RAW_BASE_URL="https://raw.githubusercontent.com/Kookiejarz/Auto_XDP"
AUTO_XDP_SOURCE_REF="${AUTO_XDP_SOURCE_REF:-}"
RAW_URL=""
PREFER_REMOTE_SOURCES=0
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"
SYSTEMD_RUN_DIR="${SYSTEMD_RUN_DIR:-/run/systemd/system}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
OPENRC_INIT_DIR="${OPENRC_INIT_DIR:-/etc/init.d}"

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
if [[ $PREFER_REMOTE_SOURCES -eq 0 && -r "${BASH_SOURCE[0]:-}" ]]; then
    BOOTSTRAP_LOCAL_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
fi

case "${AUTO_XDP_FORCE_REMOTE:-0}" in
    1|true|TRUE|yes|YES|on|ON)
        PREFER_REMOTE_SOURCES=1
        ;;
esac

valid_source_ref() {
    local ref="$1"

    if [[ "$ref" =~ ^[0-9a-fA-F]{40}$ ]]; then
        return 0
    fi
    [[ "$ref" =~ ^refs/(heads|tags)/[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || return 1
    [[ "$ref" != *".."* && "$ref" != *"//"* && "$ref" != */ ]]
}

if [[ -z "$AUTO_XDP_SOURCE_REF" ]]; then
    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        die "Remote installation requires AUTO_XDP_SOURCE_REF (for example refs/tags/v26.7.7a); use the release archive command from README.md."
    fi
    AUTO_XDP_SOURCE_REF="refs/heads/main"
fi
valid_source_ref "$AUTO_XDP_SOURCE_REF" \
    || die "Invalid AUTO_XDP_SOURCE_REF: $AUTO_XDP_SOURCE_REF"
RAW_URL="${RAW_BASE_URL}/${AUTO_XDP_SOURCE_REF}"

PKG_MANAGER=""
INIT_SYSTEM="none"
SYSTEMD_AVAILABLE=0
OPENRC_AVAILABLE=0
ACTIVE_BACKEND="nftables"
ACTIVE_XDP_MODE="none"
XDP_FALLBACK_REASON=""
REQUESTED_BACKEND="auto"
PENDING_NFT_CUTOVER=0
POLICY_DEFERRED=0
PYTHON3_BIN=""
CHECK_UPDATES=0
FORCE=0
EXISTING_INSTALL=0
CHECK_ENV=0
DRY_RUN=0
INTERNAL_PHASE2=0
RESULT_FILE=""
DISTRO_ID="unknown"
DISTRO_NAME="unknown"
DISTRO_LIKE=""
DISTRO_FAMILY="unknown"

_SETUP_TMPFILES=()
_cleanup_setup_tmpfiles() {
    local f
    for f in "${_SETUP_TMPFILES[@]:-}"; do
        [[ -f "$f" ]] && rm -f "$f"
    done
    return 0
}
_cleanup_on_exit() {
    local exit_status=$?
    if [[ $exit_status -ne 0 && ${INSTALL_TRANSACTION_ACTIVE:-0} -eq 1 \
            && ${INSTALL_TRANSACTION_COMMITTED:-0} -eq 0 ]] \
            && declare -F rollback_install_transaction >/dev/null 2>&1; then
        rollback_install_transaction || true
    fi
    if [[ ${INSTALL_LOCK_HELD:-0} -eq 1 ]] \
            && declare -F release_install_lock >/dev/null 2>&1; then
        release_install_lock || true
    fi
    if [[ -n "${RELEASE_CANDIDATE_DIR:-}" \
            && "$(basename "$RELEASE_CANDIDATE_DIR")" == .staging-* \
            && -d "$RELEASE_CANDIDATE_DIR" ]]; then
        if declare -F as_root >/dev/null 2>&1 && [[ -n "${PRIV_MODE:-}" ]]; then
            as_root rm -rf "$RELEASE_CANDIDATE_DIR" 2>/dev/null || true
        else
            rm -rf "$RELEASE_CANDIDATE_DIR" 2>/dev/null || true
        fi
    fi
    _cleanup_setup_tmpfiles
    if [[ -n "${BUILD_STAGING_DIR:-}" && -d "$BUILD_STAGING_DIR" ]]; then
        rm -rf "$BUILD_STAGING_DIR"
    fi
    if declare -F _stop_priv_keepalive >/dev/null 2>&1; then
        _stop_priv_keepalive
    fi
    return "$exit_status"
}
trap '_cleanup_on_exit' EXIT

bootstrap_remote_source_tree() {
    [[ $PREFER_REMOTE_SOURCES -eq 1 ]] || return 0
    [[ -n "${SOURCE_ROOT:-}" && -d "$SOURCE_ROOT" ]] && return 0
    command -v curl >/dev/null 2>&1 || die "Remote installation requires curl."
    command -v tar >/dev/null 2>&1 || die "Remote installation requires tar."

    BUILD_STAGING_DIR=$(mktemp -d)
    local encoded_ref response archive extract_root unpacked
    if [[ "$AUTO_XDP_SOURCE_REF" =~ ^[0-9a-fA-F]{40}$ ]]; then
        SOURCE_REVISION="${AUTO_XDP_SOURCE_REF,,}"
    else
        encoded_ref=$(python3 -c \
            'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' \
            "$AUTO_XDP_SOURCE_REF")
        response=$(curl -fsSL \
            "https://api.github.com/repos/Kookiejarz/Auto_XDP/commits/${encoded_ref}") \
            || die "Could not resolve ${AUTO_XDP_SOURCE_REF} to an immutable commit."
        SOURCE_REVISION=$(printf '%s' "$response" | python3 -c '
import json, re, sys
sha = json.load(sys.stdin).get("sha", "")
if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
    raise SystemExit(1)
print(sha.lower())
') || die "GitHub returned an invalid source commit."
    fi
    archive="${BUILD_STAGING_DIR}/source.tar.gz"
    extract_root="${BUILD_STAGING_DIR}/archive"
    mkdir -p "$extract_root"
    curl -fsSL \
        "https://codeload.github.com/Kookiejarz/Auto_XDP/tar.gz/${SOURCE_REVISION}" \
        -o "$archive" || die "Could not download the source archive."
    tar -xzf "$archive" -C "$extract_root" || die "Could not unpack the source archive."
    unpacked=$(find "$extract_root" -mindepth 1 -maxdepth 1 -type d | head -n 1)
    [[ -n "$unpacked" ]] || die "Source archive is empty."
    SOURCE_ROOT="${BUILD_STAGING_DIR}/source"
    mkdir -p "$SOURCE_ROOT"
    cp -R "$unpacked"/. "$SOURCE_ROOT"/
    local required_path
    for required_path in setup_xdp.sh config.toml auto_xdp bpf handlers lib runtime; do
        [[ -e "${SOURCE_ROOT}/${required_path}" ]] \
            || die "Source archive failed manifest validation: ${required_path} missing."
    done
    SOURCE_VERSION="${SOURCE_REVISION:0:12}"
}

bootstrap_remote_source_tree

source_setup_lib() {
    local relative_path="$1"
    local source_path="$relative_path"
    if [[ -n "${SOURCE_ROOT:-}" && -r "${SOURCE_ROOT}/${relative_path}" ]]; then
        source_path="${SOURCE_ROOT}/${relative_path}"
    elif [[ -n "${BOOTSTRAP_LOCAL_ROOT:-}" \
            && -r "${BOOTSTRAP_LOCAL_ROOT}/${relative_path}" ]]; then
        source_path="${BOOTSTRAP_LOCAL_ROOT}/${relative_path}"
    elif [[ $PREFER_REMOTE_SOURCES -eq 1 || ! -r "$source_path" ]]; then
        source_path=$(mktemp)
        _SETUP_TMPFILES+=("$source_path")
        curl -fsSL "${RAW_URL}/${relative_path}" -o "$source_path" \
            || die "Failed to load ${relative_path}"
    fi
    # shellcheck disable=SC1090
    source "$source_path"
}

source_setup_lib "lib/setup/core.sh"
source_setup_lib "lib/setup/log.sh"
log_init_colors
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
    if [[ -n "${SOURCE_ROOT:-}" && -r "${SOURCE_ROOT}/${RUNTIME_COMMON_SRC}" ]]; then
        lib_path="${SOURCE_ROOT}/${RUNTIME_COMMON_SRC}"
    elif [[ -n "${BOOTSTRAP_LOCAL_ROOT:-}" \
            && -r "${BOOTSTRAP_LOCAL_ROOT}/${RUNTIME_COMMON_SRC}" ]]; then
        lib_path="${BOOTSTRAP_LOCAL_ROOT}/${RUNTIME_COMMON_SRC}"
    elif [[ $PREFER_REMOTE_SOURCES -eq 1 || ! -r "$lib_path" ]]; then
        lib_path=$(mktemp)
        _SETUP_TMPFILES+=("$lib_path")
        if ! fetch_local_or_remote "$RUNTIME_COMMON_SRC" "$RUNTIME_COMMON_SRC" "$lib_path"; then
            die "Failed to load ${RUNTIME_COMMON_SRC}"
        fi
    fi
    # shellcheck disable=SC1090
    source "$lib_path"
}

load_runtime_common_lib
source_setup_lib "lib/setup/install.sh"
source_setup_lib "lib/setup/release.sh"

# The backend bring-up: load the XDP/nftables backend, register handlers, and
# install + start the system service. These steps run the shared
# runtime library in-process, so they execute as a single privileged unit.
configured_policy_mode() {
    PYTHONPATH="${PYTHON_LIB_DIR}${PYTHONPATH:+:${PYTHONPATH}}" \
        "$PYTHON3_BIN" -c '
from auto_xdp.config import load_toml_config
import sys
print(str(load_toml_config(sys.argv[1]).get("policy", {}).get("mode", "audit")).lower())
' "$TOML_CONFIG"
}

deactivate_installed_runtime() {
    PYTHONPATH="${PYTHON_LIB_DIR}${PYTHONPATH:+:${PYTHONPATH}}" \
        "$PYTHON3_BIN" -m auto_xdp.admin.main \
        --env-config "$CONFIG_FILE" \
        --bpf-pin-dir "$BPF_PIN_DIR" \
        --run-state-dir "$RUN_STATE_DIR" \
        --nft-family "$NFT_FAMILY" \
        --nft-table "$NFT_TABLE" \
        deactivate
}

run_backend_phase() {
    if [[ "$(configured_policy_mode)" != "enforce" ]]; then
        POLICY_DEFERRED=1
        ACTIVE_BACKEND=$(_auto_xdp_resolve_preferred_backend "$TOML_CONFIG" "auto")
        ACTIVE_XDP_MODE="none"
        step_begin "Deferring firewall activation until axdp enable"
        step_ok "audit-only"
        deactivate_installed_runtime
        run_initial_sync_step
        install_runtime_service_step
        return
    fi
    deploy_backend_step
    load_configured_slot_handlers_step
    load_configured_port_handlers_step
    run_initial_sync_step
    install_runtime_service_step
}

# Persist the backend outcome so a sudo re-exec can hand it back to the
# unprivileged parent for the deployment summary.
_emit_backend_results() {
    local rf="$1"
    [[ -n "$rf" ]] || return 0
    {
        printf 'ACTIVE_BACKEND=%q\n' "$ACTIVE_BACKEND"
        printf 'ACTIVE_XDP_MODE=%q\n' "$ACTIVE_XDP_MODE"
        printf 'XDP_FALLBACK_REASON=%q\n' "$XDP_FALLBACK_REASON"
        printf 'REQUESTED_BACKEND=%q\n' "$REQUESTED_BACKEND"
        printf 'POLICY_DEFERRED=%q\n' "$POLICY_DEFERRED"
    } > "$rf"
}

# Resolve a runnable path to this installer for the privileged re-exec. When the
# installer is being piped from curl there is no file on disk, so materialize a
# copy from GitHub.
_resolve_self_path() {
    if [[ -n "${SOURCE_ROOT:-}" && -r "${SOURCE_ROOT}/setup_xdp.sh" ]]; then
        printf '%s' "${SOURCE_ROOT}/setup_xdp.sh"
        return 0
    fi
    if [[ -n "${BOOTSTRAP_LOCAL_ROOT:-}" \
            && -r "${BOOTSTRAP_LOCAL_ROOT}/setup_xdp.sh" ]]; then
        printf '%s' "${BOOTSTRAP_LOCAL_ROOT}/setup_xdp.sh"
        return 0
    fi
    if [[ $PREFER_REMOTE_SOURCES -eq 0 && -r "${BASH_SOURCE[0]:-}" ]]; then
        printf '%s' "${BASH_SOURCE[0]}"
        return 0
    fi
    local self
    self=$(mktemp)
    _SETUP_TMPFILES+=("$self")
    curl -fsSL "${RAW_URL}/setup_xdp.sh" -o "$self" || return 1
    printf '%s' "$self"
}

# Run run_backend_phase as a single privileged unit. Already root: in-process.
# Non-root: re-exec just this phase under sudo (one elevated process) and import
# the resulting backend state, so the shared runtime library never has to
# escalate command-by-command.
run_backend_phase_dispatch() {
    if [[ "$PRIV_MODE" == "root" ]]; then
        run_backend_phase
        return 0
    fi

    local self rf
    self=$(_resolve_self_path) || die "Could not locate the installer to escalate the backend phase."
    rf=$(mktemp)
    _SETUP_TMPFILES+=("$rf")

    local -a force_arg=()
    [[ $FORCE -eq 1 ]] && force_arg=(--force)

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        as_root env \
            "AUTO_XDP_SOURCE_REF=${AUTO_XDP_SOURCE_REF}" \
            "AUTO_XDP_FORCE_REMOTE=1" \
            "AUTO_XDP_PRESTAGED_SOURCE_ROOT=${SOURCE_ROOT}" \
            "AUTO_XDP_RELEASE_NAME=${RELEASE_NAME}" \
            bash "$self" --internal-phase2 --result-file "$rf" \
            "${force_arg[@]}" "${IFACES[@]}" \
            || die "Backend bring-up failed under sudo."
    else
        as_root env "AUTO_XDP_RELEASE_NAME=${RELEASE_NAME}" \
            bash "$self" --internal-phase2 --result-file "$rf" \
            "${force_arg[@]}" "${IFACES[@]}" \
            || die "Backend bring-up failed under sudo."
    fi

    # shellcheck disable=SC1090
    [[ -s "$rf" ]] && source "$rf"
}

# Privileged continuation invoked via --internal-phase2 under sudo. Almost all
# install paths are constants set when this script is sourced; only a handful of
# values need re-deriving before running the backend phase.
run_internal_phase2() {
    PRIV_MODE="root"
    [[ ${#IFACES[@]} -gt 0 ]] || die "Internal backend phase requires target interfaces."
    IFACE="${IFACES[0]}"
    detect_os_release
    detect_pkg_manager || true
    detect_init_system
    PYTHON3_BIN="$(command -v python3 || echo python3)"
    BPF_HELPER_BOOTSTRAP="$BPF_HELPER_INSTALLED"
    run_backend_phase
    _emit_backend_results "$RESULT_FILE"
}

main() {
    parse_args "$@"

    if [[ $INTERNAL_PHASE2 -eq 1 ]]; then
        run_internal_phase2
        exit 0
    fi

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

    # Detection runs silently first so the basic-info block opens the output;
    # per-item checks and install steps follow; the LOGO + deployment details
    # come last.
    detect_privilege_mode
    detect_environment
    # Interface discovery itself depends on iproute2. Minimal hosts therefore
    # bootstrap runtime tools under the install lock before resolving NICs.
    priv_init
    acquire_install_lock_step
    recover_interrupted_install_step
    check_required_tools_step
    load_interface_policy
    resolve_target_interfaces
    if existing_install_detected; then
        EXISTING_INSTALL=1
    fi
    print_basic_info
    check_github_updates_once
    prepare_source_tree_step
    bootstrap_bpf_helper_step
    prepare_candidate_config_step
    compile_bpf_objects_step
    stage_runtime_release_step
    replace_existing_install_step
    begin_install_transaction_step
    activate_candidate_release_step
    # Backend bring-up runs as a single privileged unit (root in-process, or one
    # sudo re-exec when started as a normal user).
    run_backend_phase_dispatch
    commit_install_transaction_step
    cleanup_build_artifacts_step
    print_deployment_summary
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
