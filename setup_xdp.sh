#!/bin/bash

# setup_xdp.sh — Basic XDP installer / loader / fallback bootstrap
# Usage: sudo bash setup_xdp.sh [--check-update] [--force] [--check-env] [--dry-run] [interface]
# Supports Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.


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
IFACE=""
XDP_SRC="xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
TC_SRC="tc_udp_track.c"
TC_OBJ="tc_udp_track.o"
SYNC_INTERVAL=30

INSTALL_DIR="/usr/local/lib/basic_xdp"
CONFIG_DIR="/etc/basic_xdp"
CONFIG_FILE="${CONFIG_DIR}/basic_xdp.env"
TC_SRC="tc_udp_track.c"
TC_OBJ="tc_udp_track.o"
SYNC_INTERVAL=30

INSTALL_DIR="/usr/local/lib/basic_xdp"
CONFIG_DIR="/etc/basic_xdp"
CONFIG_FILE="${CONFIG_DIR}/basic_xdp.env"
SYNC_SCRIPT="/usr/local/bin/xdp_port_sync.py"
BXDP_CMD="/usr/local/bin/bxdp"
RUNNER_SCRIPT="/usr/local/bin/basic_xdp_start.sh"
XDP_OBJ_INSTALLED="${INSTALL_DIR}/xdp_firewall.o"
TC_OBJ_INSTALLED="${INSTALL_DIR}/tc_udp_track.o"

export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
BXDP_CMD="/usr/local/bin/bxdp"
RUNNER_SCRIPT="/usr/local/bin/basic_xdp_start.sh"
XDP_OBJ_INSTALLED="${INSTALL_DIR}/xdp_firewall.o"
TC_OBJ_INSTALLED="${INSTALL_DIR}/tc_udp_track.o"

export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SERVICE_NAME="xdp-port-sync"
RAW_URL="https://raw.githubusercontent.com/Kookiejarz/basic_xdp/main"
TC_FILTER_PREF=49152

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
    bpftool -j prog show id "$prog_id" | python3 -c "
import json, subprocess, sys, os
prog = json.load(sys.stdin)
pin_dir = os.environ['BPF_PIN_DIR']
for map_id in prog.get('map_ids', []):
    info = json.loads(subprocess.check_output(['bpftool', '-j', 'map', 'show', 'id', str(map_id)]))
    name = info.get('name', f'map_{map_id}')
    pin_path = f'{pin_dir}/{name}'
    subprocess.check_call(['bpftool', 'map', 'pin', 'id', str(map_id), pin_path])
    print(f'  pinned [{name}] -> {pin_path}')
" || return 1
}

seed_existing_tcp_conntrack() {
    local map_path="${BPF_PIN_DIR}/tcp_conntrack"
    local seeded=""

    [[ -e "$map_path" ]] || return 0

    # Pre-seed established IPv4 TCP flows so reloading XDP does not cut off
    # the current SSH session before a fresh SYN can recreate conntrack state.
    if ! seeded=$("$PYTHON3_BIN" - "$map_path" <<'PY'
import ctypes
import ctypes.util
import os
import platform
import socket
import struct
import sys
import time

try:
    import psutil
except ImportError:
    print(0)
    sys.exit(0)

NR_BPF = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def bpf(cmd, attr):
    ret = libc.syscall(NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret

def obj_get(path):
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return bpf(BPF_OBJ_GET, attr)

def iter_established_ipv4():
    getter = getattr(psutil, "connections", psutil.net_connections)
    for conn in getter(kind="inet"):
        if getattr(conn, "family", None) != socket.AF_INET:
            continue
        if getattr(conn, "type", None) != socket.SOCK_STREAM:
            continue
        if conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.laddr or not conn.raddr:
            continue
        yield conn

fd = obj_get(sys.argv[1])
key = ctypes.create_string_buffer(12)
value = ctypes.create_string_buffer(8)
attr = ctypes.create_string_buffer(128)
struct.pack_into(
    "=I4xQQQ",
    attr,
    0,
    fd,
    ctypes.cast(key, ctypes.c_void_p).value or 0,
    ctypes.cast(value, ctypes.c_void_p).value or 0,
    0,
)

seeded = 0
stamp = time.monotonic_ns()
for conn in iter_established_ipv4():
    try:
        packed = struct.pack(
            "!4s4sHH",
            socket.inet_aton(conn.raddr.ip),
            socket.inet_aton(conn.laddr.ip),
            conn.raddr.port,
            conn.laddr.port,
        )
        ctypes.memmove(key, packed, len(packed))
        struct.pack_into("=Q", value, 0, stamp)
        bpf(BPF_MAP_UPDATE_ELEM, attr)
        seeded += 1
    except OSError:
        continue

os.close(fd)
print(seeded)
PY
); then
        warn "Failed to pre-seed tcp_conntrack; established sessions may reconnect."
        return 0
    fi

    if [[ "$seeded" != "0" ]]; then
        info "Seeded ${seeded} existing IPv4 TCP session(s) into tcp_conntrack."
    fi
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
        aarch64) ASM_INC="/usr/include/aarch64-linux-gnu";   TARGET_ARCH="arm64" ;;
        armv7*)  ASM_INC="/usr/include/arm-linux-gnueabihf"; TARGET_ARCH="arm"   ;;
        *)       ASM_INC="/usr/include/${ARCH}-linux-gnu";   TARGET_ARCH="$ARCH" ;;
    esac
TC_FILTER_PREF=49152

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
    bpftool -j prog show id "$prog_id" | python3 -c "
import json, subprocess, sys, os
prog = json.load(sys.stdin)
pin_dir = os.environ['BPF_PIN_DIR']
for map_id in prog.get('map_ids', []):
    info = json.loads(subprocess.check_output(['bpftool', '-j', 'map', 'show', 'id', str(map_id)]))
    name = info.get('name', f'map_{map_id}')
    pin_path = f'{pin_dir}/{name}'
    subprocess.check_call(['bpftool', 'map', 'pin', 'id', str(map_id), pin_path])
    print(f'  pinned [{name}] -> {pin_path}')
" || return 1
}

seed_existing_tcp_conntrack() {
    local map_path="${BPF_PIN_DIR}/tcp_conntrack"
    local seeded=""

    [[ -e "$map_path" ]] || return 0

    # Pre-seed established IPv4 TCP flows so reloading XDP does not cut off
    # the current SSH session before a fresh SYN can recreate conntrack state.
    if ! seeded=$("$PYTHON3_BIN" - "$map_path" <<'PY'
import ctypes
import ctypes.util
import os
import platform
import socket
import struct
import sys
import time

try:
    import psutil
except ImportError:
    print(0)
    sys.exit(0)

NR_BPF = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def bpf(cmd, attr):
    ret = libc.syscall(NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret

def obj_get(path):
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return bpf(BPF_OBJ_GET, attr)

def iter_established_ipv4():
    getter = getattr(psutil, "connections", psutil.net_connections)
    for conn in getter(kind="inet"):
        if getattr(conn, "family", None) != socket.AF_INET:
            continue
        if getattr(conn, "type", None) != socket.SOCK_STREAM:
            continue
        if conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.laddr or not conn.raddr:
            continue
        yield conn

fd = obj_get(sys.argv[1])
key = ctypes.create_string_buffer(12)
value = ctypes.create_string_buffer(8)
attr = ctypes.create_string_buffer(128)
struct.pack_into(
    "=I4xQQQ",
    attr,
    0,
    fd,
    ctypes.cast(key, ctypes.c_void_p).value or 0,
    ctypes.cast(value, ctypes.c_void_p).value or 0,
    0,
)

seeded = 0
stamp = time.monotonic_ns()
for conn in iter_established_ipv4():
    try:
        packed = struct.pack(
            "!4s4sHH",
            socket.inet_aton(conn.raddr.ip),
            socket.inet_aton(conn.laddr.ip),
            conn.raddr.port,
            conn.laddr.port,
        )
        ctypes.memmove(key, packed, len(packed))
        struct.pack_into("=Q", value, 0, stamp)
        bpf(BPF_MAP_UPDATE_ELEM, attr)
        seeded += 1
    except OSError:
        continue

os.close(fd)
print(seeded)
PY
); then
        warn "Failed to pre-seed tcp_conntrack; established sessions may reconnect."
        return 0
    fi

    if [[ "$seeded" != "0" ]]; then
        info "Seeded ${seeded} existing IPv4 TCP session(s) into tcp_conntrack."
    fi
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
        aarch64) ASM_INC="/usr/include/aarch64-linux-gnu";   TARGET_ARCH="arm64" ;;
        armv7*)  ASM_INC="/usr/include/arm-linux-gnueabihf"; TARGET_ARCH="arm"   ;;
        *)       ASM_INC="/usr/include/${ARCH}-linux-gnu";   TARGET_ARCH="$ARCH" ;;
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

    PROG_ID=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])") || {
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

    PROG_ID=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])") || {
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
    cat > "$CONFIG_FILE" <<EOF
IFACE="${IFACE}"
SYNC_INTERVAL="${SYNC_INTERVAL}"
SYNC_SCRIPT="${SYNC_SCRIPT}"
PYTHON3_BIN="${PYTHON3_BIN}"
BPF_PIN_DIR="${BPF_PIN_DIR}"
XDP_OBJ_PATH="${XDP_OBJ_INSTALLED}"
TC_OBJ_PATH="${TC_OBJ_INSTALLED}"
PREFERRED_BACKEND="auto"
export BPF_PIN_DIR
EOF
}

write_runner_script() {
    cat > "$RUNNER_SCRIPT" <<'EOF'
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

ensure_bpffs() {
    if ! mount | grep -q 'type bpf'; then
        mount -t bpf bpf /sys/fs/bpf
    fi
}

pin_program_maps() {
    local prog_id="$1"
    bpftool -j prog show id "$prog_id" | python3 -c "
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
    cat > "$CONFIG_FILE" <<EOF
IFACE="${IFACE}"
SYNC_INTERVAL="${SYNC_INTERVAL}"
SYNC_SCRIPT="${SYNC_SCRIPT}"
PYTHON3_BIN="${PYTHON3_BIN}"
BPF_PIN_DIR="${BPF_PIN_DIR}"
XDP_OBJ_PATH="${XDP_OBJ_INSTALLED}"
TC_OBJ_PATH="${TC_OBJ_INSTALLED}"
PREFERRED_BACKEND="auto"
export BPF_PIN_DIR
EOF
}

write_runner_script() {
    cat > "$RUNNER_SCRIPT" <<'EOF'
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

ensure_bpffs() {
    if ! mount | grep -q 'type bpf'; then
        mount -t bpf bpf /sys/fs/bpf
    fi
}

pin_program_maps() {
    local prog_id="$1"
    bpftool -j prog show id "$prog_id" | python3 -c "
import json, subprocess, sys, os
prog = json.load(sys.stdin)
prog = json.load(sys.stdin)
pin_dir = os.environ['BPF_PIN_DIR']
for map_id in prog.get('map_ids', []):
    info = json.loads(subprocess.check_output(['bpftool', '-j', 'map', 'show', 'id', str(map_id)]))
    name = info.get('name', f'map_{map_id}')
    info = json.loads(subprocess.check_output(['bpftool', '-j', 'map', 'show', 'id', str(map_id)]))
    name = info.get('name', f'map_{map_id}')
    pin_path = f'{pin_dir}/{name}'
    subprocess.check_call(['bpftool', 'map', 'pin', 'id', str(map_id), pin_path])
" >/dev/null
}

cleanup_tc_egress_filter() {
    command -v tc &>/dev/null || return 0
    tc filter del dev "$IFACE" egress pref 49152 2>/dev/null || true
}

seed_existing_tcp_conntrack() {
    local map_path="${BPF_PIN_DIR}/tcp_conntrack"
    local seeded=""

    [[ -e "$map_path" ]] || return 0

    # Preserve already-established IPv4 TCP sessions during on-demand XDP loads.
    if ! seeded=$("$PYTHON3_BIN" - "$map_path" <<'PY'
import ctypes
import ctypes.util
import os
import platform
import socket
import struct
import sys
import time

try:
    import psutil
except ImportError:
    print(0)
    sys.exit(0)

NR_BPF = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def bpf(cmd, attr):
    ret = libc.syscall(NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret

def obj_get(path):
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return bpf(BPF_OBJ_GET, attr)

def iter_established_ipv4():
    getter = getattr(psutil, "connections", psutil.net_connections)
    for conn in getter(kind="inet"):
        if getattr(conn, "family", None) != socket.AF_INET:
            continue
        if getattr(conn, "type", None) != socket.SOCK_STREAM:
            continue
        if conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.laddr or not conn.raddr:
            continue
        yield conn

fd = obj_get(sys.argv[1])
key = ctypes.create_string_buffer(12)
value = ctypes.create_string_buffer(8)
attr = ctypes.create_string_buffer(128)
struct.pack_into(
    "=I4xQQQ",
    attr,
    0,
    fd,
    ctypes.cast(key, ctypes.c_void_p).value or 0,
    ctypes.cast(value, ctypes.c_void_p).value or 0,
    0,
)

seeded = 0
stamp = time.monotonic_ns()
for conn in iter_established_ipv4():
    try:
        packed = struct.pack(
            "!4s4sHH",
            socket.inet_aton(conn.raddr.ip),
            socket.inet_aton(conn.laddr.ip),
            conn.raddr.port,
            conn.laddr.port,
        )
        ctypes.memmove(key, packed, len(packed))
        struct.pack_into("=Q", value, 0, stamp)
        bpf(BPF_MAP_UPDATE_ELEM, attr)
        seeded += 1
    except OSError:
        continue

os.close(fd)
print(seeded)
PY
); then
        echo "[basic_xdp] failed to pre-seed tcp_conntrack" >&2
        return 0
    fi

    if [[ "$seeded" != "0" ]]; then
        echo "[basic_xdp] seeded ${seeded} existing IPv4 TCP session(s) into tcp_conntrack" >&2
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
        echo "existing" > "${RUN_STATE_DIR}/xdp_mode"
        return 0
    fi

    rm -rf "$BPF_PIN_DIR"
    mkdir -p "$BPF_PIN_DIR"

    bpftool prog load "$XDP_OBJ_PATH" "$BPF_PIN_DIR/prog" type xdp >/dev/null 2>&1 || return 1
    local prog_id
    prog_id=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])") || {
        cleanup_failed_load
        return 1
    }
    pin_program_maps "$prog_id" || {
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
    exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
fi

select_backend
exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --watch --interval "$SYNC_INTERVAL" --backend "$(cat "${RUN_STATE_DIR}/backend")"
EOF

    chmod +x "$RUNNER_SCRIPT"
}

install_sync_script() {
    if ! fetch_local_or_remote "xdp_port_sync.py" "xdp_port_sync.py" "$SYNC_SCRIPT"; then
        die "Failed to install xdp_port_sync.py"
    fi
    chmod +x "$SYNC_SCRIPT"
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
    install_bxdp_command
    write_config
    write_runner_script
    ok "Runtime installed under $INSTALL_DIR and $CONFIG_DIR"
}

install_systemd_service() {
    info "Creating systemd service: $SERVICE_NAME..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
    subprocess.check_call(['bpftool', 'map', 'pin', 'id', str(map_id), pin_path])
" >/dev/null
}

cleanup_tc_egress_filter() {
    command -v tc &>/dev/null || return 0
    tc filter del dev "$IFACE" egress pref 49152 2>/dev/null || true
}

seed_existing_tcp_conntrack() {
    local map_path="${BPF_PIN_DIR}/tcp_conntrack"
    local seeded=""

    [[ -e "$map_path" ]] || return 0

    # Preserve already-established IPv4 TCP sessions during on-demand XDP loads.
    if ! seeded=$("$PYTHON3_BIN" - "$map_path" <<'PY'
import ctypes
import ctypes.util
import os
import platform
import socket
import struct
import sys
import time

try:
    import psutil
except ImportError:
    print(0)
    sys.exit(0)

NR_BPF = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

def bpf(cmd, attr):
    ret = libc.syscall(NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret

def obj_get(path):
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return bpf(BPF_OBJ_GET, attr)

def iter_established_ipv4():
    getter = getattr(psutil, "connections", psutil.net_connections)
    for conn in getter(kind="inet"):
        if getattr(conn, "family", None) != socket.AF_INET:
            continue
        if getattr(conn, "type", None) != socket.SOCK_STREAM:
            continue
        if conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.laddr or not conn.raddr:
            continue
        yield conn

fd = obj_get(sys.argv[1])
key = ctypes.create_string_buffer(12)
value = ctypes.create_string_buffer(8)
attr = ctypes.create_string_buffer(128)
struct.pack_into(
    "=I4xQQQ",
    attr,
    0,
    fd,
    ctypes.cast(key, ctypes.c_void_p).value or 0,
    ctypes.cast(value, ctypes.c_void_p).value or 0,
    0,
)

seeded = 0
stamp = time.monotonic_ns()
for conn in iter_established_ipv4():
    try:
        packed = struct.pack(
            "!4s4sHH",
            socket.inet_aton(conn.raddr.ip),
            socket.inet_aton(conn.laddr.ip),
            conn.raddr.port,
            conn.laddr.port,
        )
        ctypes.memmove(key, packed, len(packed))
        struct.pack_into("=Q", value, 0, stamp)
        bpf(BPF_MAP_UPDATE_ELEM, attr)
        seeded += 1
    except OSError:
        continue

os.close(fd)
print(seeded)
PY
); then
        echo "[basic_xdp] failed to pre-seed tcp_conntrack" >&2
        return 0
    fi

    if [[ "$seeded" != "0" ]]; then
        echo "[basic_xdp] seeded ${seeded} existing IPv4 TCP session(s) into tcp_conntrack" >&2
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
        echo "existing" > "${RUN_STATE_DIR}/xdp_mode"
        return 0
    fi

    rm -rf "$BPF_PIN_DIR"
    mkdir -p "$BPF_PIN_DIR"

    bpftool prog load "$XDP_OBJ_PATH" "$BPF_PIN_DIR/prog" type xdp >/dev/null 2>&1 || return 1
    local prog_id
    prog_id=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" \
        | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])") || {
        cleanup_failed_load
        return 1
    }
    pin_program_maps "$prog_id" || {
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
    exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --backend "$(cat "${RUN_STATE_DIR}/backend")" "$@"
fi

select_backend
exec "$PYTHON3_BIN" "$SYNC_SCRIPT" --watch --interval "$SYNC_INTERVAL" --backend "$(cat "${RUN_STATE_DIR}/backend")"
EOF

    chmod +x "$RUNNER_SCRIPT"
}

install_sync_script() {
    if ! fetch_local_or_remote "xdp_port_sync.py" "xdp_port_sync.py" "$SYNC_SCRIPT"; then
        die "Failed to install xdp_port_sync.py"
    fi
    chmod +x "$SYNC_SCRIPT"
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
    install_bxdp_command
    write_config
    write_runner_script
    ok "Runtime installed under $INSTALL_DIR and $CONFIG_DIR"
}

install_systemd_service() {
    info "Creating systemd service: $SERVICE_NAME..."
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Basic XDP Loader + Port Whitelist Auto-Sync
After=network-online.target
Wants=network-online.target
Description=Basic XDP Loader + Port Whitelist Auto-Sync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${RUNNER_SCRIPT}
ExecStart=${RUNNER_SCRIPT}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    ok "Service started and enabled: $SERVICE_NAME"
}

install_openrc_service() {
    info "Creating OpenRC service: $SERVICE_NAME..."
    cat > "/etc/init.d/${SERVICE_NAME}" <<EOF
#!/sbin/openrc-run
description="Basic XDP loader + port whitelist auto-sync"
command="${RUNNER_SCRIPT}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
    need net
}
EOF

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
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"
    ok "Service started and enabled: $SERVICE_NAME"
}

install_openrc_service() {
    info "Creating OpenRC service: $SERVICE_NAME..."
    cat > "/etc/init.d/${SERVICE_NAME}" <<EOF
#!/sbin/openrc-run
description="Basic XDP loader + port whitelist auto-sync"
command="${RUNNER_SCRIPT}"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"

depend() {
    need net
}
EOF

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
