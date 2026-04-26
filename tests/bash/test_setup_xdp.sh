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
    assert_contains "$output" "interface=eth9" || return 1
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

test_xdp_maps_ready_requires_all_expected_pins() (
    source "$REPO_ROOT/setup_xdp.sh"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir"

    touch \
        "$tmpdir/prog" \
        "$tmpdir/tcp_whitelist" \
        "$tmpdir/udp_whitelist" \
        "$tmpdir/sctp_whitelist" \
        "$tmpdir/tcp_conntrack" \
        "$tmpdir/udp_conntrack" \
        "$tmpdir/sctp_conntrack"

    xdp_maps_ready >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1

    touch \
        "$tmpdir/trusted_ipv4" \
        "$tmpdir/trusted_ipv6" \
        "$tmpdir/udp_global_rl" \
        "$tmpdir/proto_handlers" \
        "$tmpdir/slot_ctx_map" \
        "$tmpdir/slot_def_action"
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
    mkdir -p "$BPF_PIN_DIR" "$tmpdir/bin"
    touch "$TC_OBJ_INSTALLED" \
        "$BPF_PIN_DIR/tcp_conntrack" \
        "$BPF_PIN_DIR/udp_conntrack" \
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

run_test "setup_xdp detects distro families" test_detect_os_release_maps_supported_families
run_test "setup_xdp prefers distro package-manager order" test_detect_pkg_manager_prefers_family_order
run_test "setup_xdp reports missing package managers" test_detect_pkg_manager_fails_when_no_manager_exists
run_test "setup_xdp detects systemd and openrc" test_detect_init_system_supports_systemd_and_openrc
run_test "setup_xdp package lists cover supported managers" test_package_lists_cover_all_supported_managers
run_test "setup_xdp dry-run report emits CI fields" test_dry_run_report_emits_ci_fields
run_test "setup_xdp confirmation handles force and no-tty abort" test_confirm_yes_no_force_and_no_tty_abort_modes
run_test "setup_xdp prefers local files when available" test_fetch_local_or_remote_uses_local_copy_without_network
run_test "setup_xdp detects required BPF headers across include roots" test_bpf_header_exists_checks_multiple_include_roots
run_test "setup_xdp surfaces truncated handler build logs" test_warn_from_log_file_prefixes_and_truncates_output
run_test "setup_xdp validates pinned map set completeness" test_xdp_maps_ready_requires_all_expected_pins
run_test "setup_xdp reuses SCTP conntrack map for tc egress" test_load_tc_egress_program_reuses_sctp_conntrack_map

finish_tests
