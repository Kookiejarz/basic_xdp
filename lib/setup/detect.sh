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
    if [[ -r "$OS_RELEASE_FILE" ]]; then
        # shellcheck disable=SC1091
        source "$OS_RELEASE_FILE"
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
        *" opensuse"*|*" suse "*)
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
    if command -v systemctl &>/dev/null && [[ -d "$SYSTEMD_RUN_DIR" ]]; then
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
