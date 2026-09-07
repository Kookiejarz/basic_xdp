_step_tag() {
    printf "${CYAN}[INFO]${NC}     "
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
        printf " ${OK_MARK}%s\n" "${1:+  ($1)}"
    elif [[ $nl -eq 1 ]]; then
        printf "${_STEP_INDENT}${OK_MARK}%s\n" "${1:+  ($1)}"
    else
        [[ -n "${1:-}" ]] && printf "${GREEN}($1)${NC} ${OK_MARK}\n" || printf " ${OK_MARK}\n"
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
        printf " ${FAIL_MARK}\n"
    fi
    printf "${_STEP_INDENT}${RED}[ERROR]${NC}  %s\n" "${1:-Failed}" >&2
}

step_error() {
    if [[ $IN_STEP -eq 1 && $_STEP_NEWLINED -eq 0 ]]; then
        printf "\n"
        _STEP_NEWLINED=1
    fi
    if [[ $_PENDING_NL -eq 1 ]]; then
        printf "\n"
        _PENDING_NL=0
    fi
    printf "${_STEP_INDENT}${RED}[ERROR]${NC}  %s\n" "${1:-Error}" >&2
    _STEP_NEWLINED=1
}

step_warn() {
    local nl=$_STEP_NEWLINED
    local pending=$_PENDING_NL
    IN_STEP=0
    _STEP_NEWLINED=0
    _PENDING_NL=0
    if [[ $pending -eq 1 ]]; then
        printf " ${WARN_MARK}%s\n" "${1:+  ($1)}"
    elif [[ $nl -eq 1 ]]; then
        printf "${_STEP_INDENT}${WARN_MARK}%s\n" "${1:+  ($1)}"
    else
        printf " ${WARN_MARK}%s\n" "${1:+  ($1)}"
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

    printf "${_STEP_INDENT}${CYAN}[INFO]${NC}  %-46s" "${label} …"
    _STEP_NEWLINED=0

    if "$@"; then
        if [[ $_PENDING_NL -eq 1 ]]; then
            printf " ${OK_MARK}\n"
            _PENDING_NL=0
        else
            printf " ${OK_MARK}\n"
        fi
        _STEP_NEWLINED=1
        return 0
    else
        local status=$?
        if [[ $_PENDING_NL -eq 1 ]]; then
            printf " ${FAIL_MARK}\n"
            _PENDING_NL=0
        else
            printf " ${FAIL_MARK}\n"
        fi
        _STEP_NEWLINED=1
        return "$status"
    fi
}

# ---------------------------------------------------------------------------
# Privilege handling
#
# The installer launches as an ordinary user and only escalates for the steps
# that genuinely need it: package installs, writes under /usr/local/lib & /etc,
# service management, and loading the BPF/XDP backend. PRIV_MODE is resolved
# once, without prompting, by detect_privilege_mode:
#   root  -> already EUID 0; the helpers run commands directly
#   sudo  -> sudo is on PATH; the helpers escalate per command
# The first password prompt is deferred to priv_init, called right before the
# first system-mutating step, so detection and the basic-info block run as the
# user.
# ---------------------------------------------------------------------------
PRIV_MODE="root"
PRIV_PRIMED=0
_PRIV_KEEPALIVE_PID=""

# Silent: resolves PRIV_MODE only; the result is reported in the basic-info
# block printed at the top of the run.
detect_privilege_mode() {
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        PRIV_MODE="root"
        return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
        PRIV_MODE="sudo"
        return 0
    fi
    die_with_next "Some steps need root, but neither root nor sudo is available." \
        "re-run as root (su -) or install sudo, then run: bash $0 ${IFACES[*]:-}"
}

# Run a command with root privileges (direct when already root).
as_root() {
    if [[ "$PRIV_MODE" == "root" ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Prime the sudo timestamp once (single password prompt) and keep it warm for
# the rest of the run so long steps never re-prompt. No-op when already root.
priv_init() {
    [[ "$PRIV_MODE" == "sudo" ]] || return 0
    [[ $PRIV_PRIMED -eq 1 ]] && return 0
    info "Some steps need administrative privileges; requesting sudo access..."
    sudo -v || die "Could not obtain sudo privileges."
    PRIV_PRIMED=1
    ( while true; do sudo -n -v 2>/dev/null || exit 0; sleep 50; done ) &
    _PRIV_KEEPALIVE_PID=$!
}

_stop_priv_keepalive() {
    [[ -n "$_PRIV_KEEPALIVE_PID" ]] || return 0
    kill "$_PRIV_KEEPALIVE_PID" 2>/dev/null || true
    _PRIV_KEEPALIVE_PID=""
}

# True when the current user can write PATH (the nearest existing ancestor for
# a not-yet-created path), i.e. no escalation is needed to create/replace it.
_can_write_path() {
    local p="$1"
    if [[ -e "$p" ]]; then
        [[ -w "$p" ]]
        return
    fi
    local dir
    dir="$(dirname "$p")"
    while [[ -n "$dir" && "$dir" != "/" && ! -e "$dir" ]]; do
        dir="$(dirname "$dir")"
    done
    [[ -w "$dir" ]]
}

# mkdir -p that escalates only when the target tree is not user-writable.
priv_mkdir() {
    local dir="$1"
    if _can_write_path "$dir"; then
        mkdir -p "$dir"
    else
        as_root mkdir -p "$dir"
    fi
}

# Write stdin to DEST, escalating only when DEST is not user-writable.
write_file() {
    local dest="$1"
    local tmp
    tmp=$(mktemp)
    _SETUP_TMPFILES+=("$tmp")
    cat > "$tmp"
    place_file "$tmp" "$dest"
}

# Copy SRC to DEST through a same-directory temporary and atomically rename it.
place_file() {
    local src="$1" dest="$2"
    local tmp="${dest}.auto-xdp-tmp-${BASHPID:-$$}"
    priv_mkdir "$(dirname "$dest")"
    if _can_write_path "$dest"; then
        cp "$src" "$tmp" && mv -f "$tmp" "$dest"
    else
        as_root cp "$src" "$tmp" && as_root mv -f "$tmp" "$dest"
    fi
}

usage() {
    cat <<'EOF'
Usage: bash setup_xdp.sh [--check-update] [--force] [--all-interfaces] [interface...]

Runs as an ordinary user and escalates with sudo only for the steps that need
it (package installs, writes under /usr/local/lib & /etc, service management,
and loading the XDP backend). Running the whole script with sudo still works.

Options:
  --check-update     Compare local files with GitHub by SHA-256 and ask before pulling
  --force            Skip confirmations and apply update/replace actions automatically
  --check-env        Print detected package manager and init system, then exit
  --dry-run          Report planned actions without changing the system
  --all-interfaces   Deploy to all active non-loopback interfaces automatically
  --allow-container-interfaces
                     Allow explicitly included veth/container interfaces
  -h, --help         Show this help

Examples:
  bash setup_xdp.sh                    # auto-detect default route interface
  bash setup_xdp.sh --all-interfaces   # deploy to all active interfaces
  bash setup_xdp.sh eth0 eth1          # deploy to specific interfaces
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
            --internal-phase2)
                # Hidden: privileged backend continuation re-exec'd via sudo.
                INTERNAL_PHASE2=1
                shift
                ;;
            --result-file)
                RESULT_FILE="$2"
                shift 2
                ;;
            --all-interfaces|-a)
                ALL_IFACES=1
                shift
                ;;
            --allow-container-interfaces)
                AUTO_XDP_ALLOW_CONTAINER=1
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

# Basic-info block printed before any install step. Detection (privileges,
# distro, package manager, interfaces, existing install) must already be done.
load_interface_policy() {
    [[ -f "$TOML_CONFIG" ]] || return 0
    local line key value
    while IFS= read -r line; do
        key=${line%%=*}
        value=${line#*=}
        case "$key" in
            present) INTERFACE_POLICY_PRESENT="$value" ;;
            mode) INTERFACE_CONFIG_MODE="$value" ;;
            include) INTERFACE_CONFIG_INCLUDE+=("$value") ;;
            exclude) INTERFACE_CONFIG_EXCLUDE+=("$value") ;;
            allow_container) INTERFACE_ALLOW_CONTAINER="$value" ;;
            xdp_mode) INTERFACE_XDP_MODE="$value" ;;
        esac
    done < <("${PYTHON3_BIN:-python3}" - "$TOML_CONFIG" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    import tomli as tomllib
try:
    with open(sys.argv[1], "rb") as handle:
        table = tomllib.load(handle).get("interfaces", {})
except Exception:
    table = {}
print(f"present={1 if table else 0}")
print(f"mode={table.get('mode', 'auto')}")
for name in table.get("include", []):
    print(f"include={name}")
for name in table.get("exclude", []):
    print(f"exclude={name}")
print(f"allow_container={1 if table.get('allow_container', False) else 0}")
print(f"xdp_mode={table.get('xdp_mode', 'auto')}")
PY
)
}

print_basic_info() {
    log_printf '%b\n' "\n${BOLD}${CYAN}Auto XDP Installer${NC}\n"
    log_printf '%b\n' "${BOLD}Basic information${NC}"
    echo "  distro         : ${DISTRO_NAME} (${DISTRO_FAMILY} family)"
    echo "  kernel         : $(uname -r) $(uname -m)"
    if [[ ${#IFACES[@]} -eq 1 ]]; then
        echo "  interface      : ${IFACES[0]}  [${IFACE_SOURCE:-arguments}]"
    else
        echo "  interfaces     : ${IFACES[*]}  [${IFACE_SOURCE:-arguments}]"
    fi
    echo "  backend        : auto (XDP preferred, nftables fallback)"
    echo "  package manager: $PKG_MANAGER"
    echo "  service manager: $INIT_SYSTEM"
    if [[ "$PRIV_MODE" == "root" ]]; then
        echo "  privilege      : root"
    else
        echo "  privilege      : ${USER:-$(id -un)} (sudo escalation when needed)"
    fi
    echo "  install dir    : $INSTALL_DIR"
    echo "  config dir     : $CONFIG_DIR"
    if [[ ${EXISTING_INSTALL:-0} -eq 1 ]]; then
        log_printf '%b\n' "  existing       : ${YELLOW}detected${NC} — runtime files will be replaced"
    else
        echo "  existing       : none (fresh install)"
    fi
    echo ""
}

get_active_interfaces() {
    local source_root="${SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
    local state_json=""
    local -a exclude_args=()
    local excluded_iface
    for excluded_iface in "${INTERFACE_CONFIG_EXCLUDE[@]:-}"; do
        [[ -n "$excluded_iface" ]] && exclude_args+=(--exclude "$excluded_iface")
    done
    state_json=$(ip -j -d link show up 2>/dev/null \
        | PYTHONPATH="$source_root" "${PYTHON3_BIN:-python3}" \
            -m auto_xdp.install_state select --input - "${exclude_args[@]}" 2>/dev/null) || state_json=""
    if [[ -n "$state_json" ]]; then
        "${PYTHON3_BIN:-python3}" -c '
import json, sys
for name in json.load(sys.stdin).get("interfaces", {}):
    print(name)
' <<< "$state_json"
        return 0
    fi

    # Compatibility fallback for older iproute2 without JSON output.
    ip -o link show up 2>/dev/null \
        | awk -F': ' '{print $2}' \
        | awk '{print $1}' \
        | grep -v '^lo$' \
        | grep -v '@' \
        | grep -Ev '^(dummy|virbr|docker|veth|cni|flannel|cali|kube-ipvs)' \
        || true
}

_stage_machine_interface_state() {
    local source_root="${SOURCE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
    local link_json="" state_file=""
    link_json=$(ip -j -d link show 2>/dev/null) || return 0
    state_file=$(mktemp)
    _SETUP_TMPFILES+=("$state_file")

    local -a explicit_args=()
    if [[ "$IFACE_SOURCE" == "arguments" || "$IFACE_SOURCE" == "config.toml interfaces.include" ]]; then
        local iface
        for iface in "${IFACES[@]}"; do
            explicit_args+=(--interface "$iface")
        done
    fi
    local -a previous_args=()
    [[ -f "$MACHINE_STATE" ]] && previous_args=(--machine-state "$MACHINE_STATE")
    local -a container_args=()
    case "${AUTO_XDP_ALLOW_CONTAINER:-${INTERFACE_ALLOW_CONTAINER:-0}}" in
        1|true|TRUE|yes|YES) container_args=(--allow-container) ;;
    esac
    local -a exclude_args=()
    local excluded_iface
    for excluded_iface in "${INTERFACE_CONFIG_EXCLUDE[@]:-}"; do
        [[ -n "$excluded_iface" ]] && exclude_args+=(--exclude "$excluded_iface")
    done

    if printf '%s\n' "$link_json" \
        | PYTHONPATH="$source_root" "${PYTHON3_BIN:-python3}" \
            -m auto_xdp.install_state select --input - \
            "${explicit_args[@]}" "${previous_args[@]}" "${container_args[@]}" \
            "${exclude_args[@]}" --default-xdp-mode "${INTERFACE_XDP_MODE:-auto}" \
            --write "$state_file" >/dev/null; then
        MACHINE_STATE_CANDIDATE="$state_file"
    elif [[ ${#explicit_args[@]} -gt 0 ]]; then
        return 1
    fi
}

# How the target interfaces were chosen; shown in the basic-info block and the
# deployment summary so a reinstall never silently changes coverage.
IFACE_SOURCE="arguments"

# Reuse the IFACES recorded by a previous install so a bare re-run keeps
# covering the same interfaces. Saved interfaces that no longer exist are
# dropped (with a note in IFACE_SOURCE); returns 1 when nothing usable remains.
_reuse_installed_ifaces() {
    [[ -r "$CONFIG_FILE" ]] || return 1

    local line="" saved=""
    line=$(grep -m1 '^IFACES=' "$CONFIG_FILE" 2>/dev/null) || return 1
    saved="${line#IFACES=}"
    saved="${saved%\"}"
    saved="${saved#\"}"
    [[ -n "$saved" ]] || return 1

    local -a valid=() gone=()
    local _iface
    for _iface in $saved; do
        if ip link show "$_iface" &>/dev/null; then
            valid+=("$_iface")
        else
            gone+=("$_iface")
        fi
    done
    [[ ${#valid[@]} -gt 0 ]] || return 1

    IFACES=("${valid[@]}")
    if [[ ${#gone[@]} -gt 0 ]]; then
        IFACE_SOURCE="existing install; dropped missing: ${gone[*]}"
    else
        IFACE_SOURCE="existing install"
    fi
    return 0
}

_detect_default_route_iface() {
    local _default_iface
    _default_iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    [[ -n "$_default_iface" ]] || die "Cannot detect default interface. Specify manually: sudo bash $0 eth0"
    IFACES=("$_default_iface")
    IFACE_SOURCE="default route auto-detect"
}

# Silent: resolves IFACES/IFACE only; the result is reported in the basic-info
# block printed at the top of the run.
resolve_target_interfaces() {
    if [[ ${#IFACES[@]} -eq 0 && ${#INTERFACE_CONFIG_INCLUDE[@]} -gt 0 ]]; then
        IFACES=("${INTERFACE_CONFIG_INCLUDE[@]}")
        IFACE_SOURCE="config.toml interfaces.include"
    fi
    if [[ $ALL_IFACES -eq 1 ]]; then
        mapfile -t IFACES < <(get_active_interfaces)
        [[ ${#IFACES[@]} -gt 0 ]] || die "No active non-loopback interfaces found."
        IFACE_SOURCE="all active interfaces"
    elif [[ ${#IFACES[@]} -eq 0 ]]; then
        if [[ ${INTERFACE_POLICY_PRESENT:-0} -eq 0 ]] && _reuse_installed_ifaces; then
            :
        else
            mapfile -t IFACES < <(get_active_interfaces)
            if [[ ${#IFACES[@]} -gt 0 ]]; then
                IFACE_SOURCE="host auto-discovery"
            else
                _detect_default_route_iface
            fi
        fi
    fi

    local _iface
    for _iface in "${IFACES[@]}"; do
        ip link show "$_iface" &>/dev/null || die "Interface '$_iface' does not exist."
    done

    IFACE="${IFACES[0]}"
    _stage_machine_interface_state
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
    echo ""
    log_printf '%b\n' "${GREEN}Deployment summary${NC}"
    log_printf '%b\n' "  Status         : ${OK_MARK} complete"
    echo "  Source         : ${SOURCE_REVISION:-local}"
    if [[ ${#IFACES[@]} -eq 1 ]]; then
        echo "  Interface      : ${IFACES[0]}  [${IFACE_SOURCE:-arguments}]"
    else
        echo "  Interfaces     : ${IFACES[*]}  [${IFACE_SOURCE:-arguments}]"
    fi
    if [[ ${POLICY_DEFERRED:-0} -eq 1 ]]; then
        echo "  Backend        : inactive (audit-only)"
        echo "  Next step      : review with 'sudo axdp discover', then run 'sudo axdp enable'"
    elif [[ "$ACTIVE_BACKEND" == "xdp" ]]; then
        echo "  Backend        : XDP ($ACTIVE_XDP_MODE mode)"
        echo "  Verification   : every interface program ID"
        echo "  BPF maps       : $BPF_PIN_DIR/"
    else
        echo "  Backend        : nftables fallback"
        echo "  Fallback reason: ${XDP_FALLBACK_REASON:-XDP unavailable}"
        echo "  nftables table : ${NFT_FAMILY:-inet} ${NFT_TABLE:-auto_xdp}"
        echo "  Coverage       : ports, ACL, trust, malformed/bogon, rates and conn caps"
        echo "  XDP-only       : BPF handlers, ring-buffer telemetry, pre-stack throughput"
    fi
    echo "  Init system    : $INIT_SYSTEM"
    if [[ "$INIT_SYSTEM" == "systemd" ]]; then
        echo "  Sync service   : systemd $SERVICE_NAME"
        echo "  Relay service  : systemd ${RELAY_SERVICE_NAME:-auto-xdp-relay}"
    elif [[ "$INIT_SYSTEM" == "openrc" ]]; then
        echo "  Sync service   : openrc $SERVICE_NAME"
        echo "  Relay service  : openrc ${RELAY_SERVICE_NAME:-auto-xdp-relay}"
    else
        echo "  Sync service   : not installed"
        echo "  Relay service  : not installed"
    fi
    echo "  Config         : $TOML_CONFIG"
    echo "  Machine state  : $MACHINE_STATE"
    echo "  Runtime state  : $RUNTIME_STATE"
    echo "  Launcher       : $RUNNER_SCRIPT"
    echo "  Command        : $AXDP_CMD"
    if [[ ${EXISTING_INSTALL:-0} -eq 1 ]]; then
        echo "install_status=replace"
    else
        echo "install_status=fresh"
    fi
    echo "install_result=complete"
    echo ""
    echo "Next commands"
    echo "  status         : sudo axdp status"
    echo "  dashboard      : sudo axdp"
    echo "  live stats     : sudo axdp stats --watch --rates --interval 2"
    echo "  sync ports     : sudo axdp sync"
    echo "  list ports     : sudo axdp ports"
    if [[ "$INIT_SYSTEM" == "systemd" || "$INIT_SYSTEM" == "openrc" ]]; then
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
    echo "missing_commands=$(for cmd in clang bpftool python3 curl tar ip nft; do command -v "$cmd" >/dev/null 2>&1 || printf '%s ' "$cmd"; done | sed 's/[[:space:]]*$//')"
    echo "planned_packages=$(package_list_for_manager; optional_package_list_for_manager; printf ' python3-psutil python3-tomli-if-python310')"
    echo "planned_actions=check-dependencies,compile-xdp,deploy-backend,install-runtime,initial-sync,install-service"
    echo "note=dry-run performs no installs, no downloads, and no system changes"
}
