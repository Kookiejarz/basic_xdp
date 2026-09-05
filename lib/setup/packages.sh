pkg_update() {
    case "$PKG_MANAGER" in
        apt-get)
            as_root apt-get update -qq
            ;;
        dnf|yum)
            as_root "$PKG_MANAGER" -y makecache
            ;;
        zypper)
            as_root zypper --non-interactive refresh
            ;;
        pacman)
            if [[ -w /etc/pacman.conf ]] && ! grep -qx 'DisableSandbox' /etc/pacman.conf; then
                printf '\nDisableSandbox\n' >> /etc/pacman.conf
            fi
            as_root pacman -Sy --noconfirm
            ;;
        apk)
            as_root apk update
            ;;
        *)
            return 1
            ;;
    esac
}

pkg_install() {
    case "$PKG_MANAGER" in
        apt-get)
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
            ;;
        dnf)
            as_root dnf install -y "$@"
            ;;
        yum)
            as_root yum install -y "$@"
            ;;
        zypper)
            as_root zypper --non-interactive install -y "$@"
            ;;
        pacman)
            as_root pacman -S --disable-sandbox --noconfirm --needed "$@"
            ;;
        apk)
            as_root apk add --no-cache "$@"
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
            # gcc-multilib only exists on x86_64; requesting it elsewhere makes
            # apt abort the whole install transaction.
            local multilib=""
            if [[ "$(uname -m)" == "x86_64" ]]; then
                multilib=" gcc-multilib"
            fi
            echo "clang llvm libbpf-dev build-essential iproute2 curl tar findutils python3 python3-pip nftables${multilib}"
            ;;
        dnf|yum)
            echo "clang llvm libbpf-devel bpftool iproute curl tar findutils python3 python3-pip gcc make nftables"
            ;;
        zypper)
            echo "clang llvm libbpf-devel bpftool iproute2 curl tar findutils python3 python3-pip gcc make nftables"
            ;;
        pacman)
            echo "clang llvm libbpf iproute2 curl tar findutils python python-pip bpf base-devel nftables"
            ;;
        apk)
            echo "clang llvm libbpf-dev bpftool iproute2 curl tar findutils python3 py3-pip build-base nftables"
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

install_bpftool_apt() {
    local kernel_tools_package="linux-tools-$(uname -r)"
    _tool_present bpftool && return 0
    pkg_install "$kernel_tools_package" || true
    _tool_present bpftool && return 0
    pkg_install bpftool || true
    _tool_present bpftool
}

enable_rpm_build_repos() {
    [[ "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ]] || return 0
    case " ${DISTRO_ID:-} ${DISTRO_LIKE:-} " in
        *" rocky "*|*" alma "*|*" rhel "*|*" centos "*) ;;
        *) return 0 ;;
    esac
    command -v dnf >/dev/null 2>&1 || return 0
    as_root dnf -y install dnf-plugins-core >/dev/null 2>&1 || true
    as_root dnf config-manager --enable crb >/dev/null 2>&1 \
        || as_root dnf config-manager --enable powertools >/dev/null 2>&1 \
        || true
}

install_packages() {
    local package_list=()
    local optional_list=()

    enable_rpm_build_repos
    mapfile -t package_list < <(package_list_for_manager | tr ' ' '\n')
    mapfile -t optional_list < <(optional_package_list_for_manager | tr ' ' '\n')

    pkg_update || warn "Package index refresh failed; trying install with cached index"
    pkg_install "${package_list[@]}" || return 1
    for optional_package in "${optional_list[@]}"; do
        [[ -n "$optional_package" ]] || continue
        pkg_install_optional "$optional_package"
    done

    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        install_bpftool_apt
    fi
    return 0
}

ensure_psutil() {
    if python3 -c "import psutil" 2>/dev/null; then
        return 0
    fi

    case "$PKG_MANAGER" in
        apt-get)
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        dnf|yum)
            as_root "$PKG_MANAGER" install -y python3-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        zypper)
            as_root zypper --non-interactive install -y python3-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        pacman)
            as_root pacman -S --noconfirm --needed python-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        apk)
            as_root apk add --no-cache py3-psutil 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
        *)
            as_root python3 -m pip install --quiet --break-system-packages psutil
            ;;
    esac
}

ensure_curses() {
    python3 -c "import curses" 2>/dev/null && return 0
    [[ "$PKG_MANAGER" == "zypper" ]] || return 1
    local curses_package
    curses_package=$(python3 -c \
        'import sys; print(f"python{sys.version_info.major}{sys.version_info.minor}-curses")')
    as_root zypper --non-interactive install -y "$curses_package" 2>/dev/null \
        && python3 -c "import curses" 2>/dev/null
}

ensure_python_runtime() {
    python3 - <<'PY' || die "Auto XDP requires Python 3.10 or newer."
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY
}

ensure_tomli_for_python310() {
    if python3 - <<'PY'
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY
    then
        return 0
    fi

    if python3 -c "import tomli" 2>/dev/null; then
        return 0
    fi

    case "$PKG_MANAGER" in
        apt-get)
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        dnf|yum)
            as_root "$PKG_MANAGER" install -y python3-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        zypper)
            as_root zypper --non-interactive install -y python3-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        pacman)
            as_root pacman -S --noconfirm --needed python-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        apk)
            as_root apk add --no-cache py3-tomli 2>/dev/null || as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
        *)
            as_root python3 -m pip install --quiet --break-system-packages tomli
            ;;
    esac
}

_tool_present() {
    if [[ "$1" == "bpftool" ]] && declare -F _auto_xdp_resolve_bpftool >/dev/null 2>&1; then
        _auto_xdp_resolve_bpftool
    else
        command -v "$1" &>/dev/null || return 1
        [[ "$1" != "bpftool" ]] || bpftool version >/dev/null 2>&1
    fi
}

# One checklist line per tool: ✓ when present, ✗ when missing. Missing tools
# are installed via the package manager, then re-checked line by line.
check_required_tools_step() {
    local missing=()
    local cmd

    step_begin "Checking required tools"
    for cmd in clang bpftool python3 curl tar find ip nft; do
        substep_run "$cmd" _tool_present "$cmd" || missing+=("$cmd")
    done

    local missing_bpf_headers=0
    if declare -F bpf_header_exists >/dev/null 2>&1; then
        if ! substep_run "BPF development headers" bpf_header_exists \
                "bpf/bpf_helpers.h" "/usr/include" "/usr/local/include"; then
            missing_bpf_headers=1
        fi
    elif [[ ! -f /usr/include/bpf/bpf_helpers.h && ! -f /usr/local/include/bpf/bpf_helpers.h ]]; then
        missing_bpf_headers=1
    fi

    if [[ ${#missing[@]} -gt 0 || $missing_bpf_headers -eq 1 ]]; then
        substep_run "Installing via $PKG_MANAGER: ${missing[*]}" install_packages \
            || die_with_next "Package installation failed." "install the missing packages manually, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
        for cmd in "${missing[@]}"; do
            if ! substep_run "$cmd (after install)" _tool_present "$cmd"; then
                case "$cmd" in
                    clang)
                        warn "$cmd still missing — XDP backend may be unavailable"
                        ;;
                    bpftool)
                        warn "bpftool still missing — XDP backend may be unavailable"
                        warn "Install linux-tools-$(uname -r) and rerun."
                        ;;
                    tar)
                        warn "$cmd still missing — remote source staging will be unavailable"
                        ;;
                    nft)
                        warn "nft still missing — nftables fallback backend will be unavailable"
                        ;;
                esac
            fi
        done
        if [[ $missing_bpf_headers -eq 1 ]]; then
            if declare -F bpf_header_exists >/dev/null 2>&1 \
                    && ! substep_run "BPF development headers (after install)" bpf_header_exists \
                        "bpf/bpf_helpers.h" "/usr/include" "/usr/local/include"; then
                warn "BPF development headers still missing — XDP backend may be unavailable"
            fi
        fi
    fi

    if declare -F bpf_header_exists >/dev/null 2>&1 \
            && ! bpf_header_exists "bpf/bpf_helpers.h" "/usr/include" "/usr/local/include"; then
        substep_run "Installing BPF headers via $PKG_MANAGER" install_packages || true
    fi

    _tool_present python3 || die_with_next "python3 not found after installation." "install Python 3.10 or newer, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    _tool_present curl || die_with_next "curl not found after installation." "install curl, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]] && ! _tool_present tar; then
        die_with_next "tar not found after installation." "install tar, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    fi
    _tool_present ip || die_with_next "ip command not found after installation." "install iproute2/iproute, then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    substep_run "python3 >= 3.10" ensure_python_runtime
    substep_run "python3 psutil module" ensure_psutil \
        || die_with_next "Failed to install the psutil Python module." "install python3-psutil (or pip install psutil), then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    substep_run "python3 curses module" ensure_curses \
        || die_with_next "Failed to load the curses Python module." "install the matching Python curses package (for example python313-curses), then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    substep_run "python3 TOML support" ensure_tomli_for_python310 \
        || die_with_next "Failed to install the tomli Python module." "install python3-tomli (or pip install tomli), then rerun: bash setup_xdp.sh --force ${IFACES[*]}"
    PYTHON3_BIN=$(command -v python3)
    IN_STEP=0; _STEP_NEWLINED=0; _PENDING_NL=0
}
