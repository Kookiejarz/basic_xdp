#!/bin/bash

# setup_xdp.sh — Basic XDP installer / loader / fallback bootstrap
# Usage: sudo bash setup_xdp.sh [--check-update] [--force] [--check-env] [--dry-run] [interface]
# Supports Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }

IFACE=""
XDP_SRC="xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
TC_SRC="tc_flow_track.c"
TC_OBJ="tc_flow_track.o"
SYNC_INTERVAL=30

INSTALL_DIR="/usr/local/lib/basic_xdp"
CONFIG_DIR="/etc/basic_xdp"
CONFIG_FILE="${CONFIG_DIR}/basic_xdp.env"
SYNC_SCRIPT="/usr/local/bin/xdp_port_sync.py"
BXDP_CMD="/usr/local/bin/bxdp"
RUNNER_SCRIPT="/usr/local/bin/basic_xdp_start.sh"
XDP_OBJ_INSTALLED="${INSTALL_DIR}/xdp_firewall.o"
TC_OBJ_INSTALLED="${INSTALL_DIR}/tc_flow_track.o"
BPF_HELPER_SRC="basic_xdp_bpf_helpers.py"
BPF_HELPER_INSTALLED="${INSTALL_DIR}/basic_xdp_bpf_helpers.py"
BPF_HELPER_BOOTSTRAP=""

export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SERVICE_NAME="xdp-port-sync"
RAW_URL="https://raw.githubusercontent.com/Kookiejarz/basic_xdp/main"
TC_FILTER_PREF=49152
PREFER_REMOTE_SOURCES=0

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

usage() {
    cat <<'EOF'
Usage: sudo bash setup_xdp.sh [--check-update] [--force] [interface]

Options:
  --check-update   Compare local files with GitHub by SHA-256 and ask before pulling
  --force          Skip confirmations and apply update/replace actions automatically
    --check-env      Print detected package manager and init system, then exit
    --dry-run        Report planned actions without changing the system
  -h, --help       Show this help
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
                if [[ -z "$IFACE" ]]; then
                    IFACE="$1"
                else
                    die "Unexpected argument: $1"
                fi
                shift
                ;;
        esac
    done

    if [[ $# -gt 0 ]]; then
        die "Unexpected argument: $1"
    fi
}

detect_pkg_manager() {
    detect_os_release

    local candidates=()
    case "$DISTRO_FAMILY" in
        debian)
            candidates=(apt-get dnf yum zypper pacman apk)
            ;;
        rpm)
            candidates=(dnf yum apt-get zypper pacman apk)
            ;;
        suse)
            candidates=(zypper dnf yum apt-get pacman apk)
            ;;
        arch)
            candidates=(pacman apt-get dnf yum zypper apk)
            ;;
        alpine)
            candidates=(apk apt-get dnf yum zypper pacman)
            ;;
        *)
            candidates=(apt-get dnf yum zypper pacman apk)
            ;;
    esac

    for pm in "${candidates[@]}"; do
        if command -v "$pm" &>/dev/null; then
            PKG_MANAGER="$pm"
            return 0
        fi
    done
    return 1
}

detect_os_release() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
    fi

    DISTRO_ID="${ID:-unknown}"
    DISTRO_NAME="${NAME:-$DISTRO_ID}"
    DISTRO_LIKE="${ID_LIKE:-}"

    case " ${DISTRO_ID} ${DISTRO_LIKE} " in
        *" ubuntu "*|*" debian "*)
            DISTRO_FAMILY="debian"
            ;;
        *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" alma "*|*" amzn "*)
            DISTRO_FAMILY="rpm"
            ;;
        *" opensuse "*|*" suse "*)
            DISTRO_FAMILY="suse"
            ;;
        *" arch "*)
            DISTRO_FAMILY="arch"
            ;;
        *" alpine "*)
            DISTRO_FAMILY="alpine"
            ;;
        *)
            DISTRO_FAMILY="unknown"
            ;;
    esac
}

detect_init_system() {
    if command -v systemctl &>/dev/null && [[ -d /run/systemd/system ]]; then
        SYSTEMD_AVAILABLE=1
        INIT_SYSTEM="systemd"
        return
    fi

    if command -v rc-service &>/dev/null && command -v rc-update &>/dev/null; then
        OPENRC_AVAILABLE=1
        INIT_SYSTEM="openrc"
        return
    fi
}

pkg_update() {
    case "$PKG_MANAGER" in
        apt-get)
            apt-get update -qq
            ;;
        dnf|yum)
            "$PKG_MANAGER" -y makecache
            ;;
        zypper)
            zypper --non-interactive refresh
            ;;
        pacman)
            pacman -Sy --noconfirm
            ;;
        apk)
            apk update
            ;;
        *)
            return 1
            ;;
    esac
}

pkg_install() {
    case "$PKG_MANAGER" in
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
            ;;
        dnf)
            dnf install -y "$@"
            ;;
        yum)
            yum install -y "$@"
            ;;
        zypper)
            zypper --non-interactive install -y "$@"
            ;;
        pacman)
            pacman -S --noconfirm --needed "$@"
            ;;
        apk)
            apk add --no-cache "$@"
            ;;
        *)
            return 1
            ;;
    esac
}

pkg_install_optional() {
    if ! pkg_install "$@"; then
        warn "Optional packages could not be installed: $*"
    fi
}

package_list_for_manager() {
    case "$PKG_MANAGER" in
        apt-get)
            echo "clang llvm libbpf-dev build-essential iproute2 curl python3 python3-pip bpftool nftables"
            ;;
        dnf|yum)
            echo "clang llvm libbpf-devel bpftool iproute curl python3 python3-pip gcc make nftables"
            ;;
        zypper)
            echo "clang llvm libbpf-devel bpftool iproute2 curl python3 python3-pip gcc make nftables"
            ;;
        pacman)
            echo "clang llvm libbpf iproute2 curl python python-pip bpftool base-devel nftables"
            ;;
        apk)
            echo "clang llvm libbpf-dev bpftool iproute2 curl python3 py3-pip build-base nftables"
            ;;
        *)
            return 1
            ;;
    esac
}

optional_package_list_for_manager() {
    case "$PKG_MANAGER" in
        apt-get)
            echo "linux-headers-$(uname -r)"
            ;;
        dnf|yum)
            echo "kernel-headers kernel-devel"
            ;;
        zypper)
            echo "kernel-devel"
            ;;
        pacman|apk)
            echo "linux-headers"
            ;;
        *)
            return 1
            ;;
    esac
}

install_packages() {
    local package_list=()
    local optional_list=()

    mapfile -t package_list < <(package_list_for_manager | tr ' ' '\n')
    mapfile -t optional_list < <(optional_package_list_for_manager | tr ' ' '\n')

    pkg_update
    pkg_install "${package_list[@]}"
    for optional_package in "${optional_list[@]}"; do
        [[ -n "$optional_package" ]] || continue
        pkg_install_optional "$optional_package"
    done
}

ensure_psutil() {
    if python3 -c "import psutil" 2>/dev/null; then
        return 0
    fi

    case "$PKG_MANAGER" in
        apt-get)
            apt-get install -y -qq python3-psutil 2>/dev/null || python3 -m pip install --quiet --break-system-packages psutil
            ;;
        dnf|yum)
            "$PKG_MANAGER" install -y python3-psutil 2>/dev/null || python3 -m pip install --quiet --break-system-packages psutil
            ;;
        zypper)
            zypper --non-interactive install -y python3-psutil 2>/dev/null || python3 -m pip install --quiet --break-system-packages psutil
            ;;
        pacman)
            pacman -S --noconfirm --needed python-psutil 2>/dev/null || python3 -m pip install --quiet --break-system-packages psutil
            ;;
        apk)
            apk add --no-cache py3-psutil 2>/dev/null || python3 -m pip install --quiet --break-system-packages psutil
            ;;
        *)
            python3 -m pip install --quiet --break-system-packages psutil
            ;;
    esac
}

dry_run_report() {
    detect_pkg_manager || die "No supported package manager found."
    detect_init_system

    local detected_iface=""
    detected_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}' || true)

    echo "mode=dry-run"
    echo "distro_id=$DISTRO_ID"
    echo "distro_name=$DISTRO_NAME"
    echo "distro_family=$DISTRO_FAMILY"
    echo "package_manager=$PKG_MANAGER"
    echo "init_system=$INIT_SYSTEM"
    echo "interface=${IFACE:-${detected_iface:-undetected}}"
    echo "missing_commands=$(for cmd in clang bpftool python3 curl ip tc nft; do command -v "$cmd" >/dev/null 2>&1 || printf '%s ' "$cmd"; done | sed 's/[[:space:]]*$//')"
    echo "planned_packages=$(package_list_for_manager; optional_package_list_for_manager; printf ' python3-psutil')"
    echo "planned_actions=check-dependencies,compile-xdp,deploy-backend,install-runtime,initial-sync,install-service"
    echo "note=dry-run performs no installs, no downloads, and no system changes"
}

sha256_of_file() {
    python3 -c "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" "$1"
}

confirm_yes_no() {
    local prompt="$1"
    local no_tty_mode="${2:-deny}"
    local reply=""

    if [[ $FORCE -eq 1 ]]; then
        info "Force mode enabled; proceeding without confirmation."
        return 0
    fi

    if [[ -r /dev/tty ]]; then
        printf "%s" "$prompt" > /dev/tty
        read -r reply < /dev/tty
    elif [[ -t 0 ]]; then
        read -r -p "$prompt" reply
    else
        case "$no_tty_mode" in
            abort)
                return 2
                ;;
            *)
                return 1
                ;;
        esac
    fi

    case "$reply" in
        y|Y|yes|YES|Yes)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

prompt_pull_github() {
    local remote_name="$1"
    local local_hash="$2"
    local remote_hash="$3"

    warn "${remote_name} differs from GitHub."
    warn "  local : ${local_hash}"
    warn "  github: ${remote_hash}"

    if confirm_yes_no "Pull GitHub version for ${remote_name}? [y/N] "; then
        return 0
    fi

    warn "Keeping local ${remote_name}."
    return 1
}

fetch_local_or_remote() {
    local local_path="$1"
    local remote_name="$2"
    local target_path="$3"
    local tmp_file=""
    local local_hash=""
    local remote_hash=""

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        info "Installer is running from stdin; fetching ${remote_name} from GitHub..."
        curl -fsSL "${RAW_URL}/${remote_name}" -o "$target_path"
        return 0
    fi

    if [[ -f "$local_path" ]]; then
        if [[ $CHECK_UPDATES -eq 1 ]]; then
            tmp_file=$(mktemp)
            info "Checking GitHub version of ${remote_name}..."
            if ! curl -fsSL "${RAW_URL}/${remote_name}" -o "$tmp_file"; then
                warn "Could not fetch ${remote_name} from GitHub for comparison; keeping local copy."
                rm -f "$tmp_file"
                if [[ "$local_path" != "$target_path" ]]; then
                    cp "$local_path" "$target_path"
                fi
                return 0
            fi

            local_hash=$(sha256_of_file "$local_path")
            remote_hash=$(sha256_of_file "$tmp_file")

            if [[ "$local_hash" == "$remote_hash" ]]; then
                info "Local ${remote_name} matches GitHub."
                rm -f "$tmp_file"
                if [[ "$local_path" != "$target_path" ]]; then
                    cp "$local_path" "$target_path"
                fi
                return 0
            fi

            if prompt_pull_github "$remote_name" "$local_hash" "$remote_hash"; then
                cp "$tmp_file" "$local_path"
                info "Updated local ${remote_name} from GitHub."
            else
                info "Keeping local ${remote_name}."
            fi

            rm -f "$tmp_file"
        fi

        if [[ "$local_path" != "$target_path" ]]; then
            cp "$local_path" "$target_path"
        fi
        info "Using local ${remote_name}"
        return 0
    fi

    info "Fetching ${remote_name} from GitHub..."
    curl -fsSL "${RAW_URL}/${remote_name}" -o "$target_path"
}

ensure_bpffs() {
    if ! mount | grep -q 'type bpf'; then
        info "Mounting bpffs on /sys/fs/bpf..."
        mount -t bpf bpf /sys/fs/bpf || die "bpffs mount failed."
    fi
}

cleanup_tc_egress_filter() {
    command -v tc &>/dev/null || return 0
    tc filter del dev "$IFACE" egress pref "$TC_FILTER_PREF" 2>/dev/null || true
}

xdp_maps_ready() {
    local required=(
        "${BPF_PIN_DIR}/prog"
        "${BPF_PIN_DIR}/tcp_whitelist"
        "${BPF_PIN_DIR}/udp_whitelist"
        "${BPF_PIN_DIR}/tcp_conntrack"
        "${BPF_PIN_DIR}/udp_conntrack"
        "${BPF_PIN_DIR}/trusted_src_ips"
    )
    local path=""
    for path in "${required[@]}"; do
        [[ -e "$path" ]] || return 1
    done
    return 0
}

cleanup_existing_xdp() {
    cleanup_tc_egress_filter

    if ip -d link show dev "$IFACE" 2>/dev/null | grep -Eq 'xdp|xdpgeneric|xdpoffload'; then
        warn "Existing XDP program detected on $IFACE."
        if confirm_yes_no "Unload the existing XDP program from $IFACE and continue? [y/N] " "abort"; then
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

        info "Detaching XDP from $IFACE..."
        ip link set dev "$IFACE" xdp off 2>/dev/null || true
        ip link set dev "$IFACE" xdp generic off 2>/dev/null || true

        if ip -d link show dev "$IFACE" 2>/dev/null | grep -Eq 'xdp|xdpgeneric|xdpoffload'; then
            die "Failed to clear the existing XDP program from $IFACE. Detach it manually and rerun."
        fi

        ok "Existing XDP program removed from $IFACE."
    fi

    if [[ -d "$BPF_PIN_DIR" ]]; then
        warn "Removing old BPF pin directory $BPF_PIN_DIR..."
        rm -rf "$BPF_PIN_DIR"
    fi
    mkdir -p "$BPF_PIN_DIR"
}

pin_program_maps() {
    local prog_id="$1"
    [[ -n "$BPF_HELPER_BOOTSTRAP" ]] || {
        warn "BPF helper is not available for bootstrap pinning."
        return 1
    }
    "$PYTHON3_BIN" "$BPF_HELPER_BOOTSTRAP" pin-maps \
        --prog-id "$prog_id" \
        --pin-dir "$BPF_PIN_DIR" || return 1
}

seed_existing_tcp_conntrack() {
    local map_path="${BPF_PIN_DIR}/tcp_conntrack"
    local seeded=""

    [[ -e "$map_path" ]] || return 0

    [[ -n "$BPF_HELPER_BOOTSTRAP" ]] || {
        warn "BPF helper is not available for conntrack seeding."
        return 0
    }

    # Pre-seed established TCP flows so reloading XDP does not cut off
    # existing sessions before a fresh SYN can recreate conntrack state.
    if ! seeded=$("$PYTHON3_BIN" "$BPF_HELPER_BOOTSTRAP" seed-tcp-conntrack --map-path "$map_path"); then
        warn "Failed to pre-seed tcp_conntrack; established sessions may reconnect."
        return 0
    fi

    if [[ "$seeded" != "0" ]]; then
        info "Seeded ${seeded} existing TCP session(s) into tcp_conntrack."
    fi
}

ensure_bpf_helper_bootstrap() {
    local helper_path="$BPF_HELPER_SRC"
    if [[ ! -f "$helper_path" ]]; then
        helper_path=$(mktemp)
    fi
    if ! fetch_local_or_remote "$BPF_HELPER_SRC" "$BPF_HELPER_SRC" "$helper_path"; then
        warn "Failed to fetch ${BPF_HELPER_SRC}; helper-based map operations will be unavailable."
        return 1
    fi
    BPF_HELPER_BOOTSTRAP="$helper_path"
    return 0
}

load_tc_egress_program() {
    local tc_prog_path="${BPF_PIN_DIR}/tc_egress_prog"

    if ! command -v tc &>/dev/null; then
        warn "tc not found; TCP/UDP reply tracking on egress will be skipped."
        return 1
    fi

    rm -f "$tc_prog_path"
    if [[ ! -f "$TC_OBJ_INSTALLED" ]]; then
        warn "tc egress object not found; TCP/UDP reply tracking on egress will be skipped."
        return 1
    fi

    if ! bpftool prog load "$TC_OBJ_INSTALLED" "$tc_prog_path" \
        type classifier \
        map name tcp_conntrack pinned "${BPF_PIN_DIR}/tcp_conntrack" \
        map name udp_conntrack pinned "${BPF_PIN_DIR}/udp_conntrack" >/dev/null 2>&1; then
        warn "Failed to load tc egress program; outbound TCP/UDP reply tracking will be limited."
        return 1
    fi

    tc qdisc add dev "$IFACE" clsact 2>/dev/null || true
    if ! tc filter replace dev "$IFACE" egress pref "$TC_FILTER_PREF" \
        bpf direct-action object-pinned "$tc_prog_path" >/dev/null 2>&1; then
        warn "Failed to attach tc egress filter; outbound TCP/UDP reply tracking will be limited."
        rm -f "$tc_prog_path"
        return 1
    fi

    info "Attached tc egress TCP/UDP tracker on $IFACE."
    return 0
}

compile_bpf_object() {
    local src_path="$1"
    local obj_path="$2"

    if ! clang -O3 -g \
        -target bpf \
        -mcpu=v3 \
        "-D__TARGET_ARCH_${TARGET_ARCH}" \
        -fno-stack-protector \
        -Wall -Wno-unused-value \
        -I/usr/include \
        -I"$ASM_INC" \
        -I/usr/include/bpf \
        -c "$src_path" -o "$obj_path"; then
        return 1
    fi
    return 0
}

compile_xdp_program() {
    if ! command -v clang &>/dev/null || ! command -v bpftool &>/dev/null; then
        warn "clang or bpftool missing; XDP backend will be skipped."
        return 1
    fi

    if ! fetch_local_or_remote "$XDP_SRC" "$XDP_SRC" "$XDP_SRC"; then
        warn "Unable to fetch ${XDP_SRC}; XDP backend will be skipped."
        return 1
    fi

    info "Compiling ${XDP_SRC}..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  ASM_INC="/usr/include/x86_64-linux-gnu";   TARGET_ARCH="x86"   ;;
        aarch64) ASM_INC="/usr/include/aarch64-linux-gnu";  TARGET_ARCH="arm64" ;;
        armv7*)  ASM_INC="/usr/include/arm-linux-gnueabihf"; TARGET_ARCH="arm"  ;;
        *)       ASM_INC="/usr/include/${ARCH}-linux-gnu";  TARGET_ARCH="$ARCH" ;;
    esac

    if [[ ! -d "$ASM_INC" ]]; then
        ASM_INC="/usr/src/linux-headers-$(uname -r)/arch/${TARGET_ARCH}/include/generated"
    fi
    if [[ ! -d "$ASM_INC" && -d "/usr/include/asm" ]]; then
        ASM_INC="/usr/include"
    fi
    if [[ ! -d "$ASM_INC" ]]; then
        ASM_INC=$(find /usr/src -name "asm" -type d -print -quit | xargs dirname 2>/dev/null || echo "")
    fi
    if [[ ! -d "$ASM_INC" ]]; then
        warn "ASM headers not found; XDP backend will be skipped."
        return 1
    fi
    info "Using ASM headers: $ASM_INC"

    if ! compile_bpf_object "$XDP_SRC" "$XDP_OBJ"; then
        warn "Failed to compile ${XDP_SRC}; XDP backend will be skipped."
        return 1
    fi

    mkdir -p "$INSTALL_DIR"
    cp "$XDP_OBJ" "$XDP_OBJ_INSTALLED"
    ok "Compiled -> $XDP_OBJ"

    if ! fetch_local_or_remote "$TC_SRC" "$TC_SRC" "$TC_SRC"; then
        warn "Unable to fetch ${TC_SRC}; TCP/UDP tc egress tracker will be skipped."
        return 0
    fi
    if ! compile_bpf_object "$TC_SRC" "$TC_OBJ"; then
        warn "Failed to compile ${TC_SRC}; TCP/UDP tc egress tracker will be skipped."
        return 0
    fi
    cp "$TC_OBJ" "$TC_OBJ_INSTALLED"
    ok "Compiled -> $TC_OBJ"
    return 0
}

deploy_xdp_backend() {
    if [[ ! -f "$XDP_OBJ_INSTALLED" ]]; then
        warn "Compiled XDP object not found; skipping XDP backend."
        return 1
    fi

    ensure_bpffs
    cleanup_existing_xdp

    info "Loading XDP program onto $IFACE..."
    if ! bpftool prog load "$XDP_OBJ_INSTALLED" "$BPF_PIN_DIR/prog" type xdp; then
        warn "bpftool prog load failed; falling back from XDP."
        rm -rf "$BPF_PIN_DIR"
        return 1
    fi

    PROG_ID=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])") || {
        warn "Unable to inspect loaded XDP program."
        rm -rf "$BPF_PIN_DIR"
        return 1
    }
    info "Loaded program ID: $PROG_ID"

    if ! pin_program_maps "$PROG_ID"; then
        warn "Map pinning failed; falling back from XDP."
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

    if ip link set dev "$IFACE" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
        ACTIVE_BACKEND="xdp"
        ACTIVE_XDP_MODE="native"
        ok "XDP attached in native mode on $IFACE"
        return 0
    fi

    warn "Native mode unsupported — trying generic XDP..."
    if ip link set dev "$IFACE" xdp generic pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
        ACTIVE_BACKEND="xdp"
        ACTIVE_XDP_MODE="generic"
        ok "XDP attached in generic mode on $IFACE"
        return 0
    fi

    warn "Generic XDP also unsupported — using nftables fallback."
    cleanup_tc_egress_filter
    ip link set dev "$IFACE" xdp off 2>/dev/null || true
    rm -rf "$BPF_PIN_DIR"
    return 1
}

ensure_nftables_available() {
    if command -v nft &>/dev/null; then
        return 0
    fi

    warn "nft not found — attempting to install nftables..."
    pkg_install_optional nftables
    command -v nft &>/dev/null
}

stop_existing_service() {
    case "$INIT_SYSTEM" in
        systemd)
            systemctl stop "$SERVICE_NAME" 2>/dev/null || true
            ;;
        openrc)
            rc-service "$SERVICE_NAME" stop 2>/dev/null || true
            ;;
    esac

    pkill -f "basic_xdp_start.sh" 2>/dev/null || true
    pkill -f "xdp_port_sync.py" 2>/dev/null || true
}

write_config() {
    mkdir -p "$CONFIG_DIR"
    cat > "$CONFIG_FILE" <<EOF_CFG
IFACE="${IFACE}"
SYNC_INTERVAL="${SYNC_INTERVAL}"
LOG_LEVEL="${LOG_LEVEL}"
SYNC_SCRIPT="${SYNC_SCRIPT}"
PYTHON3_BIN="${PYTHON3_BIN}"
BPF_PIN_DIR="${BPF_PIN_DIR}"
XDP_OBJ_PATH="${XDP_OBJ_INSTALLED}"
TC_OBJ_PATH="${TC_OBJ_INSTALLED}"
PREFERRED_BACKEND="auto"
BPF_HELPER_SCRIPT="${BPF_HELPER_INSTALLED}"
export BPF_PIN_DIR
EOF_CFG
}

write_runner_script() {
    cat > "$RUNNER_SCRIPT" <<'EOF_RUNNER'
#!/bin/bash
set -euo pipefail

CONFIG_FILE="/etc/basic_xdp/basic_xdp.env"
RUN_STATE_DIR="/run/basic_xdp"

[[ -f "$CONFIG_FILE" ]] || {
    echo "[basic_xdp] missing config: $CONFIG_FILE" >&2
    exit 1
}

# shellcheck disable=SC1091
source "$CONFIG_FILE"

sync_script_supports_log_level() {
    "$PYTHON3_BIN" "$SYNC_SCRIPT" --help 2>/dev/null | grep -q -- "--log-level"
}

run_sync_script() {
    local mode="$1"
    shift || true

    if sync_script_supports_log_level; then
        if [[ "$mode" == "watch" ]]; then
            exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --log-level "$LOG_LEVEL" --watch --interval "$SYNC_INTERVAL" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
        fi
        exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --log-level "$LOG_LEVEL" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
    fi

    echo "[basic_xdp] warning: installed xdp_port_sync.py does not support --log-level; running without it" >&2
    if [[ "$mode" == "watch" ]]; then
        exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --watch --interval "$SYNC_INTERVAL" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
    fi
    exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
}

ensure_bpffs() {
    if ! mount | grep -q 'type bpf'; then
        mount -t bpf bpf /sys/fs/bpf
    fi
}

pin_program_maps() {
    local prog_id="$1"
    "$PYTHON3_BIN" "$BPF_HELPER_SCRIPT" pin-maps --prog-id "$prog_id" --pin-dir "$BPF_PIN_DIR" >/dev/null
}

cleanup_tc_egress_filter() {
    command -v tc &>/dev/null || return 0
    tc filter del dev "$IFACE" egress pref 49152 2>/dev/null || true
}

xdp_maps_ready() {
    local required=(
        "${BPF_PIN_DIR}/prog"
        "${BPF_PIN_DIR}/tcp_whitelist"
        "${BPF_PIN_DIR}/udp_whitelist"
        "${BPF_PIN_DIR}/tcp_conntrack"
        "${BPF_PIN_DIR}/udp_conntrack"
        "${BPF_PIN_DIR}/trusted_src_ips"
    )
    local path=""
    for path in "${required[@]}"; do
        [[ -e "$path" ]] || return 1
    done
    return 0
}

seed_existing_tcp_conntrack() {
    local map_path="${BPF_PIN_DIR}/tcp_conntrack"
    local seeded=""

    [[ -e "$map_path" ]] || return 0

    if ! seeded=$("$PYTHON3_BIN" "$BPF_HELPER_SCRIPT" seed-tcp-conntrack --map-path "$map_path"); then
        echo "[basic_xdp] failed to pre-seed tcp_conntrack" >&2
        return 0
    fi

    if [[ "$seeded" != "0" ]]; then
        echo "[basic_xdp] seeded ${seeded} existing TCP session(s) into tcp_conntrack" >&2
    fi
}

load_tc_egress_program() {
    local tc_prog_path="${BPF_PIN_DIR}/tc_egress_prog"

    command -v tc &>/dev/null || return 1
    rm -f "$tc_prog_path"
    [[ -f "$TC_OBJ_PATH" ]] || return 1

    if ! bpftool prog load "$TC_OBJ_PATH" "$tc_prog_path" \
        type classifier \
        map name tcp_conntrack pinned "${BPF_PIN_DIR}/tcp_conntrack" \
        map name udp_conntrack pinned "${BPF_PIN_DIR}/udp_conntrack" >/dev/null 2>&1; then
        return 1
    fi

    tc qdisc add dev "$IFACE" clsact 2>/dev/null || true
    if ! tc filter replace dev "$IFACE" egress pref 49152 \
        bpf direct-action object-pinned "$tc_prog_path" >/dev/null 2>&1; then
        rm -f "$tc_prog_path"
        return 1
    fi
    return 0
}

ensure_xdp_loaded() {
    command -v bpftool &>/dev/null || return 1
    [[ -f "$XDP_OBJ_PATH" ]] || return 1

    ensure_bpffs

    cleanup_failed_load() {
        cleanup_tc_egress_filter
        ip link set dev "$IFACE" xdp off 2>/dev/null || true
        rm -rf "$BPF_PIN_DIR"
    }

    if [[ -f "$BPF_PIN_DIR/prog" ]] && ip link show "$IFACE" | grep -q "xdp"; then
        if xdp_maps_ready; then
            echo "existing" > "${RUN_STATE_DIR}/xdp_mode"
            return 0
        fi
        echo "[basic_xdp] existing XDP maps incomplete; reloading runtime objects" >&2
    fi

    rm -rf "$BPF_PIN_DIR"
    mkdir -p "$BPF_PIN_DIR"

    bpftool prog load "$XDP_OBJ_PATH" "$BPF_PIN_DIR/prog" type xdp >/dev/null 2>&1 || return 1
    local prog_id
    prog_id=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])") || {
        cleanup_failed_load
        return 1
    }
    pin_program_maps "$prog_id" || {
        cleanup_failed_load
        return 1
    }
    xdp_maps_ready || {
        echo "[basic_xdp] pinned XDP maps incomplete after pinning; fallback to nftables" >&2
        cleanup_failed_load
        return 1
    }
    seed_existing_tcp_conntrack
    load_tc_egress_program || true

    if ip link set dev "$IFACE" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
        echo "native" > "${RUN_STATE_DIR}/xdp_mode"
        return 0
    fi

    if ip link set dev "$IFACE" xdp generic pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
        echo "generic" > "${RUN_STATE_DIR}/xdp_mode"
        return 0
    fi

    cleanup_failed_load
    return 1
}

select_backend() {
    mkdir -p "$RUN_STATE_DIR"

    if [[ "${PREFERRED_BACKEND}" != "nftables" ]] && ensure_xdp_loaded; then
        echo "xdp" > "${RUN_STATE_DIR}/backend"
        return 0
    fi

    command -v nft &>/dev/null || {
        echo "[basic_xdp] nft not found and XDP unavailable" >&2
        exit 1
    }
    echo "nftables" > "${RUN_STATE_DIR}/backend"
}

if [[ "${1:-}" == "--sync-once" ]]; then
    shift
    select_backend
    run_sync_script once "$@"
fi

select_backend
run_sync_script watch
EOF_RUNNER

    chmod +x "$RUNNER_SCRIPT"
}

install_sync_script() {
    if ! fetch_local_or_remote "xdp_port_sync.py" "xdp_port_sync.py" "$SYNC_SCRIPT"; then
        die "Failed to install xdp_port_sync.py"
    fi
    chmod +x "$SYNC_SCRIPT"
}

install_bpf_helper() {
    if ! fetch_local_or_remote "$BPF_HELPER_SRC" "$BPF_HELPER_SRC" "$BPF_HELPER_INSTALLED"; then
        die "Failed to install ${BPF_HELPER_SRC}"
    fi
    chmod +x "$BPF_HELPER_INSTALLED"
}

install_bxdp_command() {
    if ! fetch_local_or_remote "bxdp" "bxdp" "$BXDP_CMD"; then
        die "Failed to install bxdp"
    fi
    chmod +x "$BXDP_CMD"
}

install_runtime_files() {
    info "Installing runtime files..."
    mkdir -p "$INSTALL_DIR"
    install_sync_script
    install_bpf_helper
    install_bxdp_command
    write_config
    write_runner_script
    ok "Runtime installed under $INSTALL_DIR and $CONFIG_DIR"
}

install_systemd_service() {
    info "Creating systemd service: $SERVICE_NAME..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF_UNIT
[Unit]
Description=Basic XDP Loader + Port Whitelist Auto-Sync
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
description="Basic XDP loader + port whitelist auto-sync"
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

# 1. Root check
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

[[ $EUID -eq 0 ]] || die "Please run this script with sudo."

# 2. Interface detection
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    [[ -n "$IFACE" ]] || die "Cannot detect default interface. Specify manually: sudo bash $0 eth0"
    info "Detected interface: $IFACE"
fi
ip link show "$IFACE" &>/dev/null || die "Interface $IFACE does not exist."

# 3. Dependencies
info "Checking dependencies..."
detect_pkg_manager || die "No supported package manager found."
detect_init_system

MISSING=()
for cmd in clang bpftool python3 curl ip tc nft; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing: ${MISSING[*]} — installing via $PKG_MANAGER..."
    install_packages
fi

command -v python3 &>/dev/null || die "python3 not found after installation."
command -v curl &>/dev/null || die "curl not found after installation."
command -v ip &>/dev/null || die "ip command not found after installation."
ensure_psutil
PYTHON3_BIN=$(command -v python3)
ok "Base dependencies satisfied."

ensure_bpf_helper_bootstrap || true

if ! command -v bpftool &>/dev/null || ! command -v clang &>/dev/null; then
    warn "bpftool or clang still missing; XDP backend may be unavailable."
fi

# 4. Stop existing runtime before replacing files
stop_existing_service

# 5. Compile XDP when available and try to deploy it now
compile_xdp_program || true
if deploy_xdp_backend; then
    :
else
    ACTIVE_BACKEND="nftables"
    ACTIVE_XDP_MODE="none"
    ensure_nftables_available || die "Neither XDP nor nftables backend is available."
fi

# 6. Install runtime and boot-time launcher
install_runtime_files

# 7. Initial sync for whichever backend is active now
run_initial_sync

# 8. Install service for boot-time auto start
case "$INIT_SYSTEM" in
    systemd)
        install_systemd_service
        ;;
    openrc)
        install_openrc_service
        ;;
    *)
        warn "No supported init system detected; skipping service installation."
        warn "Start manually: ${RUNNER_SCRIPT}"
        ;;
esac

# 9. Summary
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment Complete!                  ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Interface      : $IFACE"
echo "  Active backend : $ACTIVE_BACKEND"
if [[ "$ACTIVE_BACKEND" == "xdp" ]]; then
    echo "  XDP mode       : $ACTIVE_XDP_MODE"
    echo "  BPF maps       : $BPF_PIN_DIR/"
    echo "  TC egress obj  : $TC_OBJ_INSTALLED"
else
    echo "  nftables table : inet basic_xdp"
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
echo "  Command        : $BXDP_CMD"
echo ""
echo "  Next Commands"
echo "  bxdp           : sudo bxdp"
echo "  bxdp watch     : sudo bxdp watch"
echo "  bxdp rates     : sudo bxdp stats --rates"
echo "  bxdp live      : sudo bxdp stats --watch --rates --interval 2"
echo "  bxdp sync      : sudo bxdp sync"
if [[ "$INIT_SYSTEM" == "systemd" ]]; then
    echo "  service status : sudo bxdp status"
    echo "  service restart: sudo bxdp restart"
elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
    echo "  service status : sudo bxdp status"
    echo "  service restart: sudo bxdp restart"
fi
