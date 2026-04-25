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
            echo "clang llvm libbpf-dev build-essential iproute2 curl python3 python3-pip nftables gcc-multilib"
            ;;
        dnf|yum)
            echo "clang llvm libbpf-devel bpftool iproute curl python3 python3-pip gcc make nftables"
            ;;
        zypper)
            echo "clang llvm libbpf-devel bpftool iproute2 curl python3 python3-pip gcc make nftables"
            ;;
        pacman)
            echo "clang llvm libbpf iproute2 curl python python-pip bpf base-devel nftables"
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

install_bpftool_apt() {
    command -v bpftool &>/dev/null && return 0
    if DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bpftool 2>/dev/null; then
        return 0
    fi
    pkg_install_optional "linux-tools-$(uname -r)" linux-tools-common
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

    [[ "$PKG_MANAGER" == "apt-get" ]] && install_bpftool_apt
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
