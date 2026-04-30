#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
BASE_PATH="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"
# shellcheck source=tests/bash/testlib.sh
source "$REPO_ROOT/tests/bash/testlib.sh"

test_detect_os_release_maps_supported_families() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)

    local cases=(
        'ubuntu|Ubuntu|debian|debian'
        'fedora|Fedora Linux||rpm'
        'opensuse-leap|openSUSE Leap||suse'
        'arch|Arch Linux||arch'
        'alpine|Alpine Linux||alpine'
    )
    local entry id name like expected

    for entry in "${cases[@]}"; do
        IFS='|' read -r id name like expected <<<"$entry"
        cat >"$tmpdir/os-release" <<EOF_CASE
ID=$id
NAME="$name"
ID_LIKE="$like"
EOF_CASE
        OS_RELEASE_FILE="$tmpdir/os-release"
        DISTRO_ID=""
        DISTRO_NAME=""
        DISTRO_LIKE=""
        DISTRO_FAMILY=""
        detect_os_release
        assert_eq "$DISTRO_FAMILY" "$expected" "$id" || return 1
    done
)

test_detect_pkg_manager_prefers_family_order() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"
    cat >"$tmpdir/os-release" <<'EOF_OS'
ID=fedora
NAME="Fedora Linux"
EOF_OS

    cat >"$tmpdir/bin/yum" <<'EOF_YUM'
#!/bin/sh
exit 0
EOF_YUM
    cat >"$tmpdir/bin/apt-get" <<'EOF_APT'
#!/bin/sh
exit 0
EOF_APT
    chmod +x "$tmpdir/bin/yum" "$tmpdir/bin/apt-get"

    PATH="$tmpdir/bin"
    OS_RELEASE_FILE="$tmpdir/os-release"
    PKG_MANAGER=""

    detect_pkg_manager || return 1
    assert_eq "$PKG_MANAGER" "yum"
)

test_detect_pkg_manager_fails_when_no_manager_exists() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"

    PATH="$tmpdir/bin"
    OS_RELEASE_FILE="$tmpdir/missing-os-release"
    PKG_MANAGER=""

    detect_pkg_manager >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1"
)

test_detect_init_system_supports_systemd_and_openrc() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)

    mkdir -p "$tmpdir/bin-systemd" "$tmpdir/run-systemd/system"
    cat >"$tmpdir/bin-systemd/systemctl" <<'EOF_SYSTEMCTL'
#!/bin/sh
exit 0
EOF_SYSTEMCTL
    chmod +x "$tmpdir/bin-systemd/systemctl"

    PATH="$tmpdir/bin-systemd:$BASE_PATH"
    SYSTEMD_RUN_DIR="$tmpdir/run-systemd/system"
    INIT_SYSTEM="none"
    SYSTEMD_AVAILABLE=0
    OPENRC_AVAILABLE=0
    detect_init_system
    assert_eq "$INIT_SYSTEM" "systemd" || return 1
    assert_eq "$SYSTEMD_AVAILABLE" "1" || return 1

    mkdir -p "$tmpdir/bin-openrc"
    cat >"$tmpdir/bin-openrc/rc-service" <<'EOF_RCSERVICE'
#!/bin/sh
exit 0
EOF_RCSERVICE
    cat >"$tmpdir/bin-openrc/rc-update" <<'EOF_RCUPDATE'
#!/bin/sh
exit 0
EOF_RCUPDATE
    chmod +x "$tmpdir/bin-openrc/rc-service" "$tmpdir/bin-openrc/rc-update"

    PATH="$tmpdir/bin-openrc:$BASE_PATH"
    SYSTEMD_RUN_DIR="$tmpdir/missing-systemd"
    INIT_SYSTEM="none"
    SYSTEMD_AVAILABLE=0
    OPENRC_AVAILABLE=0
    detect_init_system
    assert_eq "$INIT_SYSTEM" "openrc" || return 1
    assert_eq "$OPENRC_AVAILABLE" "1"
)

test_package_lists_cover_all_supported_managers() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local managers=(apt-get dnf yum zypper pacman apk)
    local pm packages optional

    for pm in "${managers[@]}"; do
        PKG_MANAGER="$pm"
        packages=$(package_list_for_manager)
        optional=$(optional_package_list_for_manager)
        assert_contains "$packages" "curl" "$pm packages" || return 1
        assert_contains "$packages" "python" "$pm packages" || return 1
        [[ -n "$optional" ]] || {
            printf 'optional package list empty for [%s]\n' "$pm"
            return 1
        }
    done
)

test_dry_run_report_emits_ci_fields() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    detect_pkg_manager() { PKG_MANAGER="apk"; }
    detect_init_system() { INIT_SYSTEM="openrc"; }
    package_list_for_manager() { echo "pkg-a pkg-b"; }
    optional_package_list_for_manager() { echo "pkg-opt"; }
    ip() { echo "default via 192.0.2.1 dev eth9"; }

    DISTRO_ID="alpine"
    DISTRO_NAME="Alpine Linux"
    DISTRO_FAMILY="alpine"
    IFACE=""

    local output
    output=$(dry_run_report)

    assert_contains "$output" "mode=dry-run" || return 1
    assert_contains "$output" "package_manager=apk" || return 1
    assert_contains "$output" "init_system=openrc" || return 1
    assert_contains "$output" "interfaces=eth9" || return 1
    assert_contains "$output" "planned_packages=pkg-a pkg-b" || return 1
    assert_contains "$output" "planned_actions=check-dependencies,compile-xdp,deploy-backend,install-runtime,initial-sync,install-service"
)

test_confirm_yes_no_force_and_no_tty_abort_modes() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    FORCE=1
    confirm_yes_no "force prompt" || return 1

    FORCE=0
    confirm_yes_no "abort prompt" abort >/dev/null 2>&1
    local status=$?
    [[ $status -ne 0 ]] || {
        printf 'expected non-zero status when no confirmation input is available\n'
        return 1
    }
)

test_confirm_existing_install_step_aborts_without_confirmation() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir log status output
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    : >"$CONFIG_FILE"

    confirm_yes_no() { return 1; }

    log="$tmpdir/output.log"
    set +e
    ( confirm_existing_install_step ) >"$log" 2>&1
    status=$?
    set -e
    output=$(<"$log")

    [[ $status -ne 0 ]] || {
        printf 'expected confirm_existing_install_step to abort when confirmation is denied\n'
        return 1
    }
    assert_contains "$output" "Checking existing installation" || return 1
    assert_contains "$output" "Installation aborted; existing deployment left untouched."
)

test_fetch_local_or_remote_uses_local_copy_without_network() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir src dst
    tmpdir=$(mktemp -d)
    src="$tmpdir/local.txt"
    dst="$tmpdir/target.txt"

    printf 'local copy\n' > "$src"

    PREFER_REMOTE_SOURCES=0
    CHECK_UPDATES=0
    fetch_local_or_remote "$src" "remote.txt" "$dst" || return 1

    assert_file_contains "$dst" "local copy"
)

test_write_config_enables_queue_auto_tuning() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_DIR="$tmpdir/etc"
    CONFIG_FILE="$CONFIG_DIR/auto_xdp.env"
    IFACES=(eth0 eth1)
    SYNC_SCRIPT="/tmp/xdp_port_sync.py"
    PYTHON3_BIN="/usr/bin/python3"
    BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
    XDP_OBJ_INSTALLED="/tmp/xdp_firewall.o"
    TC_OBJ_INSTALLED="/tmp/tc_flow_track.o"
    BPF_HELPER_INSTALLED="/tmp/auto_xdp_bpf_helpers.py"
    INSTALL_DIR="/tmp/auto_xdp"
    PYTHON_LIB_DIR="/tmp/auto_xdp/python"

    write_config || return 1

    assert_file_contains "$CONFIG_FILE" 'AUTO_TUNE_QUEUES="1"'
    assert_file_contains "$CONFIG_FILE" 'PYTHON_LIB_DIR="/tmp/auto_xdp/python"'
)

test_auto_tune_interface_parallelism_sets_combined_channels() (
    set +e

    local tmpdir log
    tmpdir=$(mktemp -d)
    log="$tmpdir/ethtool.log"

    export AUTO_XDP_CPU_ONLINE_FILE="$tmpdir/cpu_online"
    printf '0-5\n' > "$AUTO_XDP_CPU_ONLINE_FILE"

    # shellcheck disable=SC1090
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"

    IFACES=(eth0)
    AUTO_TUNE_QUEUES=1

    ethtool() {
        if [[ "$1" == "-l" ]]; then
            cat <<'EOF_ETHTOOL'
Channel parameters for eth0:
Pre-set maximums:
RX:             0
TX:             0
Other:          1
Combined:       4
Current hardware settings:
RX:             0
TX:             0
Other:          1
Combined:       1
EOF_ETHTOOL
            return 0
        fi
        if [[ "$1" == "-L" ]]; then
            printf '%s\n' "$*" > "$log"
            return 0
        fi
        return 1
    }

    auto_tune_interface_parallelism || return 1
    assert_file_contains "$log" "-L eth0 combined 4"
)

test_auto_tune_interface_parallelism_balances_irqs() (
    set +e

    local tmpdir irq
    tmpdir=$(mktemp -d)

    export AUTO_XDP_SYS_CLASS_NET_DIR="$tmpdir/sys/class/net"
    export AUTO_XDP_PROC_IRQ_DIR="$tmpdir/proc/irq"
    export AUTO_XDP_PROC_INTERRUPTS="$tmpdir/proc/interrupts"
    export AUTO_XDP_CPU_ONLINE_FILE="$tmpdir/sys/devices/system/cpu/online"

    mkdir -p "$AUTO_XDP_SYS_CLASS_NET_DIR/eth0/device/msi_irqs"
    mkdir -p "$AUTO_XDP_PROC_IRQ_DIR"
    mkdir -p "$(dirname "$AUTO_XDP_CPU_ONLINE_FILE")"

    printf '0-2\n' > "$AUTO_XDP_CPU_ONLINE_FILE"
    cat > "$AUTO_XDP_PROC_INTERRUPTS" <<'EOF_IRQS'
 32: 10 0 0 0 PCI-MSI  eth0-TxRx-0
 33: 0 10 0 0 PCI-MSI  eth0-TxRx-1
 34: 0 0 10 0 PCI-MSI  eth0-TxRx-2
EOF_IRQS

    for irq in 32 33 34; do
        : > "$AUTO_XDP_SYS_CLASS_NET_DIR/eth0/device/msi_irqs/$irq"
        mkdir -p "$AUTO_XDP_PROC_IRQ_DIR/$irq"
        : > "$AUTO_XDP_PROC_IRQ_DIR/$irq/smp_affinity_list"
    done

    # shellcheck disable=SC1090
    source "$REPO_ROOT/runtime/auto_xdp_runtime_common.sh"

    IFACES=(eth0)
    AUTO_TUNE_QUEUES=1
    ethtool() { return 1; }

    auto_tune_interface_parallelism || return 1

    assert_file_contains "$AUTO_XDP_PROC_IRQ_DIR/32/smp_affinity_list" "0" || return 1
    assert_file_contains "$AUTO_XDP_PROC_IRQ_DIR/33/smp_affinity_list" "1" || return 1
    assert_file_contains "$AUTO_XDP_PROC_IRQ_DIR/34/smp_affinity_list" "2"
)

test_bpf_header_exists_checks_multiple_include_roots() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/inc-a/linux" "$tmpdir/inc-b/bpf"
    : >"$tmpdir/inc-a/linux/bpf.h"
    : >"$tmpdir/inc-b/bpf/bpf_helpers.h"

    bpf_header_exists "linux/bpf.h" "$tmpdir/inc-b" "$tmpdir/inc-a" || return 1
    bpf_header_exists "bpf/bpf_helpers.h" "$tmpdir/inc-a" "$tmpdir/inc-b" || return 1

    bpf_header_exists "linux/missing.h" "$tmpdir/inc-a" "$tmpdir/inc-b" >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1"
)

test_warn_from_log_file_prefixes_and_truncates_output() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir log output
    tmpdir=$(mktemp -d)
    log="$tmpdir/handler.log"
    printf 'line one\nline two\nline three\n' >"$log"

    output=$(warn_from_log_file "$log" "handler build: " 2)

    assert_contains "$output" "handler build: line one" || return 1
    assert_contains "$output" "handler build: line two" || return 1
    assert_contains "$output" "handler build: (additional output truncated)"
)

test_prepare_slot_handler_sources_uses_staging_dir() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir fetched
    tmpdir=$(mktemp -d)
    fetched="$tmpdir/fetched.log"
    BUILD_STAGING_DIR="$tmpdir/stage"

    fetch_local_or_remote() {
        printf '%s -> %s\n' "$1" "$3" >>"$fetched"
        mkdir -p "$(dirname "$3")"
        : >"$3"
    }

    cd "$tmpdir" || return 1
    prepare_slot_handler_sources || return 1
    assert_file_contains "$fetched" "handlers/Makefile -> $BUILD_STAGING_DIR/handlers/Makefile" || return 1
    [[ ! -e "$tmpdir/handlers/Makefile" ]] || {
        printf 'expected handlers/Makefile to stay out of the current working directory\n'
        return 1
    }
)

test_info_prints_within_active_step() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local output
    output=$(
        step_begin "Testing info output"
        info "Preparing runtime files"
        step_ok
    )

    assert_contains "$output" "[INFO]" || return 1
    assert_contains "$output" "Preparing runtime files"
)

test_substep_run_prints_success_and_failure_markers() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local success_output failure_output status

    success_output=$(
        step_begin "Testing substep success"
        substep_run "Installing thing" true
        step_ok
    )
    assert_contains "$success_output" "Installing thing" || return 1
    assert_contains "$success_output" "✓" || return 1

    local failure_log
    failure_log=$(mktemp)
    set +e
    (
        step_begin "Testing substep failure"
        substep_run "Installing broken thing" false
    ) >"$failure_log" 2>&1
    status=$?
    set -e
    failure_output=$(<"$failure_log")
    assert_eq "$status" "1" || return 1
    assert_contains "$failure_output" "Installing broken thing" || return 1
    assert_contains "$failure_output" "✗"
)

test_xdp_maps_ready_requires_all_expected_pins() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir map_name
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir"

    map_name=$(xdp_required_map_names | head -n 1)
    [[ -n "$map_name" ]] || {
        printf 'expected shared XDP map manifest to be readable\n'
        return 1
    }

    touch "$tmpdir/$map_name"

    xdp_maps_ready >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1

    while IFS= read -r map_name; do
        [[ -n "$map_name" ]] || continue
        touch "$tmpdir/$map_name"
    done < <(xdp_required_map_names)

    xdp_maps_ready >/dev/null 2>&1
    status=$?
    assert_eq "$status" "0"
)

test_load_tc_egress_program_reuses_sctp_conntrack_map() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    TC_OBJ_INSTALLED="$tmpdir/tc_flow_track.o"
    IFACE="eth9"
    IFACES=("eth9")
    mkdir -p "$BPF_PIN_DIR" "$tmpdir/bin"
    touch "$TC_OBJ_INSTALLED" \
        "$BPF_PIN_DIR/tcp_ct4" \
        "$BPF_PIN_DIR/tcp_ct6" \
        "$BPF_PIN_DIR/udp_ct4" \
        "$BPF_PIN_DIR/udp_ct6" \
        "$BPF_PIN_DIR/sctp_conntrack"

    cat >"$tmpdir/bin/bpftool" <<EOF_BPFSH
#!/bin/sh
printf '%s\n' "\$*" >> "$tmpdir/bpftool.log"
exit 0
EOF_BPFSH
    cat >"$tmpdir/bin/tc" <<EOF_TCSH
#!/bin/sh
printf '%s\n' "\$*" >> "$tmpdir/tc.log"
exit 0
EOF_TCSH
    chmod +x "$tmpdir/bin/bpftool" "$tmpdir/bin/tc"

    PATH="$tmpdir/bin:$BASE_PATH"
    load_tc_egress_program || return 1

    assert_file_contains "$tmpdir/bpftool.log" "map name sctp_conntrack pinned $BPF_PIN_DIR/sctp_conntrack"
)

test_resolve_target_interfaces_step_uses_default_route_interface() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    ALL_IFACES=0
    IFACE=""
    IFACES=()

    ip() {
        case "$*" in
            "route show default")
                echo "default via 192.0.2.1 dev eth9"
                ;;
            "link show eth9")
                return 0
                ;;
            *)
                return 1
                ;;
        esac
    }

    resolve_target_interfaces_step >/dev/null || return 1
    assert_eq "$IFACE" "eth9" || return 1
    assert_eq "${IFACES[*]}" "eth9"
)

test_check_required_tools_step_only_requires_runtime_commands() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    mkdir -p "$tmpdir/bin"

    local cmd
    for cmd in python3 curl ip tc nft; do
        cat >"$tmpdir/bin/$cmd" <<'EOF_CMD'
#!/bin/sh
exit 0
EOF_CMD
        chmod +x "$tmpdir/bin/$cmd"
    done

    PATH="$tmpdir/bin"
    PKG_MANAGER="apk"
    PYTHON3_BIN=""

    install_packages() { :; }
    ensure_psutil() { :; }

    check_required_tools_step >/dev/null || return 1
    assert_eq "$PYTHON3_BIN" "$tmpdir/bin/python3"
)

test_deploy_backend_step_falls_back_to_nftables() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    IFACES=("eth9")
    ACTIVE_BACKEND="xdp"
    ACTIVE_XDP_MODE="native"

    deploy_xdp_backend() { return 1; }
    ensure_nftables_available() { return 0; }

    deploy_backend_step >/dev/null || return 1
    assert_eq "$ACTIVE_BACKEND" "nftables" || return 1
    assert_eq "$ACTIVE_XDP_MODE" "none"
)

test_install_runtime_service_step_warns_without_init_system() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    INIT_SYSTEM="none"
    RUNNER_SCRIPT="/tmp/auto_xdp_start.sh"

    local output
    output=$(install_runtime_service_step)
    assert_contains "$output" "start manually: $RUNNER_SCRIPT"
)

test_load_configured_slot_handlers_step_only_runs_for_xdp() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local called=0
    load_slot_handlers() { called=$((called + 1)); }

    ACTIVE_BACKEND="nftables"
    load_configured_slot_handlers_step >/dev/null || return 1
    assert_eq "$called" "0" || return 1

    ACTIVE_BACKEND="xdp"
    load_configured_slot_handlers_step >/dev/null || return 1
    assert_eq "$called" "1"
)

test_cleanup_build_artifacts_step_preserves_local_sources() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)

    XDP_OBJ="$tmpdir/xdp_firewall.o"
    TC_OBJ="$tmpdir/tc_flow_track.o"
    XDP_SRC="$tmpdir/xdp_firewall.c"
    TC_SRC="$tmpdir/tc_flow_track.c"
    BPF_HELPER_SRC="$tmpdir/auto_xdp_bpf_helpers.py"
    BPF_HELPER_BOOTSTRAP="$tmpdir/bootstrap-helper.py"
    PREFER_REMOTE_SOURCES=0

    : >"$XDP_OBJ"
    : >"$TC_OBJ"
    : >"$XDP_SRC"
    : >"$TC_SRC"
    : >"$BPF_HELPER_SRC"
    : >"$BPF_HELPER_BOOTSTRAP"

    cleanup_build_artifacts_step >/dev/null || return 1

    [[ ! -f "$XDP_OBJ" && ! -f "$TC_OBJ" && ! -f "$BPF_HELPER_BOOTSTRAP" ]] || {
        printf 'expected objects and bootstrap helper to be removed\n'
        return 1
    }
    [[ -f "$XDP_SRC" && -f "$TC_SRC" && -f "$BPF_HELPER_SRC" ]] || {
        printf 'expected local source files to be preserved\n'
        return 1
    }
)

test_restore_compiled_slot_handlers_step_reinstalls_builtin_objects() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BUILD_STAGING_DIR="$tmpdir/stage"
    INSTALL_DIR="$tmpdir/install"

    mkdir -p "$BUILD_STAGING_DIR/handlers" "$INSTALL_DIR/handlers"
    printf 'gre' >"$BUILD_STAGING_DIR/handlers/gre_handler.o"
    printf 'esp' >"$BUILD_STAGING_DIR/handlers/esp_handler.o"

    restore_compiled_slot_handlers_step >/dev/null || return 1

    [[ -s "$INSTALL_DIR/handlers/gre_handler.o" ]] || {
        printf 'expected gre handler object to be restored after SDK install\n'
        return 1
    }
    [[ -s "$INSTALL_DIR/handlers/esp_handler.o" ]] || {
        printf 'expected esp handler object to be restored after SDK install\n'
        return 1
    }
)

test_install_python_support_package_includes_state_module() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir fetched
    tmpdir=$(mktemp -d)
    AUTO_XDP_PACKAGE_DIR="$tmpdir/auto_xdp"
    fetched="$tmpdir/fetched.log"

    fetch_local_or_remote() {
        printf '%s -> %s\n' "$1" "$3" >>"$fetched"
        mkdir -p "$(dirname "$3")"
        : >"$3"
    }

    install_python_support_package || return 1
    assert_file_contains "$fetched" "auto_xdp/state.py -> ${AUTO_XDP_PACKAGE_DIR}/state.py"
    assert_file_contains "$fetched" "auto_xdp/xdp_required_maps.txt -> ${AUTO_XDP_PACKAGE_DIR}/xdp_required_maps.txt"
)

test_install_python_support_package_removes_stale_files() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir fetched
    tmpdir=$(mktemp -d)
    AUTO_XDP_PACKAGE_DIR="$tmpdir/auto_xdp"
    fetched="$tmpdir/fetched.log"

    mkdir -p "$AUTO_XDP_PACKAGE_DIR/obsolete"
    : >"$AUTO_XDP_PACKAGE_DIR/stale.py"
    : >"$AUTO_XDP_PACKAGE_DIR/obsolete/old.txt"

    fetch_local_or_remote() {
        printf '%s -> %s\n' "$1" "$3" >>"$fetched"
        mkdir -p "$(dirname "$3")"
        printf 'fresh\n' >"$3"
    }

    install_python_support_package || return 1
    [[ ! -e "$AUTO_XDP_PACKAGE_DIR/stale.py" ]] || {
        printf 'expected stale package file to be removed\n'
        return 1
    }
    [[ ! -e "$AUTO_XDP_PACKAGE_DIR/obsolete/old.txt" ]] || {
        printf 'expected stale package subdirectory to be removed\n'
        return 1
    }
    assert_file_contains "$AUTO_XDP_PACKAGE_DIR/state.py" "fresh"
)

test_install_slot_handler_sdk_cleans_stale_files_and_preserves_configured_custom_handlers() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir fetched
    tmpdir=$(mktemp -d)
    INSTALL_DIR="$tmpdir/install"
    CONFIG_DIR="$tmpdir/etc"
    PYTHON3_BIN="${PYTHON3_BIN:-python3}"
    fetched="$tmpdir/fetched.log"

    mkdir -p "$INSTALL_DIR/handlers" "$CONFIG_DIR"
    cat >"$CONFIG_DIR/config.toml" <<EOF_CFG
[slots]
enabled = [{ proto = 99, path = "${INSTALL_DIR}/handlers/custom_99_keep.o" }]

[port_handlers.tcp]
"25565" = "${INSTALL_DIR}/handlers/minecraft_handler.o"
EOF_CFG

    : >"$INSTALL_DIR/handlers/gre_handler.o"
    : >"$INSTALL_DIR/handlers/old_removed_handler.o"
    : >"$INSTALL_DIR/handlers/custom_99_keep.o"
    : >"$INSTALL_DIR/handlers/minecraft_handler.o"
    : >"$INSTALL_DIR/handlers/xdp_slot_ctx.h"
    : >"$INSTALL_DIR/handlers/Makefile"

    fetch_local_or_remote() {
        printf '%s -> %s\n' "$1" "$3" >>"$fetched"
        mkdir -p "$(dirname "$3")"
        printf 'sdk\n' >"$3"
    }

    install_slot_handler_sdk || return 1
    [[ ! -e "$INSTALL_DIR/handlers/gre_handler.o" ]] || {
        printf 'expected old built-in handler object to be removed\n'
        return 1
    }
    [[ ! -e "$INSTALL_DIR/handlers/old_removed_handler.o" ]] || {
        printf 'expected stale unconfigured handler object to be removed\n'
        return 1
    }
    [[ -e "$INSTALL_DIR/handlers/custom_99_keep.o" ]] || {
        printf 'expected configured custom slot handler to be preserved\n'
        return 1
    }
    [[ -e "$INSTALL_DIR/handlers/minecraft_handler.o" ]] || {
        printf 'expected configured custom port handler to be preserved\n'
        return 1
    }
    assert_file_contains "$INSTALL_DIR/handlers/Makefile" "sdk"
)

run_test "setup_xdp detects distro families" test_detect_os_release_maps_supported_families
run_test "setup_xdp prefers distro package-manager order" test_detect_pkg_manager_prefers_family_order
run_test "setup_xdp reports missing package managers" test_detect_pkg_manager_fails_when_no_manager_exists
run_test "setup_xdp detects systemd and openrc" test_detect_init_system_supports_systemd_and_openrc
run_test "setup_xdp package lists cover supported managers" test_package_lists_cover_all_supported_managers
run_test "setup_xdp dry-run report emits CI fields" test_dry_run_report_emits_ci_fields
run_test "setup_xdp confirmation handles force and no-tty abort" test_confirm_yes_no_force_and_no_tty_abort_modes
run_test "setup_xdp aborts when existing install is not confirmed" test_confirm_existing_install_step_aborts_without_confirmation
run_test "setup_xdp prefers local files when available" test_fetch_local_or_remote_uses_local_copy_without_network
run_test "setup_xdp writes queue auto tuning into runtime config" test_write_config_enables_queue_auto_tuning
run_test "setup_xdp sizes combined channels to available CPUs" test_auto_tune_interface_parallelism_sets_combined_channels
run_test "setup_xdp balances interface irqs across CPUs" test_auto_tune_interface_parallelism_balances_irqs
run_test "setup_xdp detects required BPF headers across include roots" test_bpf_header_exists_checks_multiple_include_roots
run_test "setup_xdp surfaces truncated handler build logs" test_warn_from_log_file_prefixes_and_truncates_output
run_test "setup_xdp stages handler sources outside the current directory" test_prepare_slot_handler_sources_uses_staging_dir
run_test "setup_xdp prints info lines within active step output" test_info_prints_within_active_step
run_test "setup_xdp prints substep success and failure markers" test_substep_run_prints_success_and_failure_markers
run_test "setup_xdp validates pinned map set completeness" test_xdp_maps_ready_requires_all_expected_pins
run_test "setup_xdp reuses SCTP conntrack map for tc egress" test_load_tc_egress_program_reuses_sctp_conntrack_map
run_test "setup_xdp resolves default route interface for step helper" test_resolve_target_interfaces_step_uses_default_route_interface
run_test "setup_xdp keeps clang and bpftool optional for runtime tool checks" test_check_required_tools_step_only_requires_runtime_commands
run_test "setup_xdp backend step falls back to nftables" test_deploy_backend_step_falls_back_to_nftables
run_test "setup_xdp service step warns when no init system exists" test_install_runtime_service_step_warns_without_init_system
run_test "setup_xdp loads configured slot handlers only for xdp backend" test_load_configured_slot_handlers_step_only_runs_for_xdp
run_test "setup_xdp cleanup step preserves local sources" test_cleanup_build_artifacts_step_preserves_local_sources
run_test "setup_xdp restores compiled builtin slot handlers after runtime install" test_restore_compiled_slot_handlers_step_reinstalls_builtin_objects
run_test "setup_xdp installs auto_xdp state module into runtime package" test_install_python_support_package_includes_state_module
run_test "setup_xdp removes stale installed python package files" test_install_python_support_package_removes_stale_files
run_test "setup_xdp cleans stale handler artifacts but preserves configured custom handlers" test_install_slot_handler_sdk_cleans_stale_files_and_preserves_configured_custom_handlers

finish_tests
