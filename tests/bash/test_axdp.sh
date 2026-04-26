#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
BASE_PATH="${PATH:-/usr/bin:/bin:/usr/sbin:/sbin}"
# shellcheck source=tests/bash/testlib.sh
source "$REPO_ROOT/tests/bash/testlib.sh"

test_format_helpers_render_human_output() (
    source "$REPO_ROOT/axdp"
    set +e

    assert_eq "$(human_bytes 1536)" "1.50 KiB" || return 1
    assert_eq "$(human_bytes -1)" "-" || return 1
    assert_eq "$(human_bps 1500)" "1.50 Kbps" || return 1
    assert_eq "$(format_rate 10 125 1)" "10.00 pps / 1.00 Kbps"
)

test_parse_stats_args_sets_expected_flags() (
    source "$REPO_ROOT/axdp"
    set +e

    WATCH_MODE=0
    SHOW_RATES=0
    INTERVAL=1
    IFACE=""

    parse_stats_args --watch --rates --interval 5 --interface eth9 || return 1
    assert_eq "$WATCH_MODE" "1" || return 1
    assert_eq "$SHOW_RATES" "1" || return 1
    assert_eq "$INTERVAL" "5" || return 1
    assert_eq "$IFACE" "eth9"
)

test_parse_ports_args_sets_expected_flags() (
    source "$REPO_ROOT/axdp"
    set +e

    PORTS_WATCH=0
    PORTS_INTERVAL=2

    parse_ports_args watch --interval 7 || return 1
    assert_eq "$PORTS_WATCH" "1" || return 1
    assert_eq "$PORTS_INTERVAL" "7" || return 1

    PORTS_WATCH=0
    PORTS_INTERVAL=2

    parse_ports_args --watch || return 1
    assert_eq "$PORTS_WATCH" "1"
)

test_csv_helpers_sort_and_diff_ports() (
    source "$REPO_ROOT/axdp"
    set +e

    local sorted
    sorted=$(csv_to_sorted_lines "443,22,80")
    assert_eq "$sorted" $'22\n80\n443' || return 1
    assert_eq "$(diff_csv "22,80" "22,443" added)" "443" || return 1
    assert_eq "$(diff_csv "22,80" "22,443" removed)" "80"
)

test_valid_log_level_and_config_updates() (
    source "$REPO_ROOT/axdp"
    set +e

    valid_log_level debug || return 1
    valid_log_level trace >/dev/null 2>&1
    local status=$?
    assert_eq "$status" "1" || return 1

    local tmpdir
    tmpdir=$(mktemp -d)
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    cat >"$CONFIG_FILE" <<'EOF_CFG'
LOG_LEVEL="info"
EOF_CFG

    set_config_var "LOG_LEVEL" "debug" || return 1
    assert_file_contains "$CONFIG_FILE" 'LOG_LEVEL="debug"'
)

test_run_log_level_reads_and_updates_config() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    TOML_CONFIG="$tmpdir/config.toml"
    cat >"$TOML_CONFIG" <<'EOF_CFG'
[daemon]
log_level = "info"
EOF_CFG

    PATH="$tmpdir/empty-bin:$BASE_PATH"
    mkdir -p "$tmpdir/empty-bin"
    reload_daemon() { :; }

    assert_eq "$(run_log_level)" "info" || return 1

    local output
    output=$(run_log_level DEBUG 2>&1) || return 1
    assert_contains "$output" "daemon.log_level=debug" || return 1
    assert_file_contains "$TOML_CONFIG" "[daemon]"
    assert_file_contains "$TOML_CONFIG" 'log_level = "debug"'
)

test_config_updates_preserve_unrelated_sections() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    TOML_CONFIG="$tmpdir/config.toml"
    reload_daemon() { :; }

    cat >"$TOML_CONFIG" <<'EOF_CFG'
[firewall]
bogon_filter = false

[permanent_ports]
tcp = [22]
udp = []
sctp = [3868]

[trusted_ips]
"203.0.113.1/32" = "office"

[slots]
default_action = "drop"
enabled = ["sctp", { proto = 47, path = "/tmp/gre_handler.o" }]
EOF_CFG

    run_trust add "198.51.100.8/32" office >/dev/null || return 1

    assert_file_contains "$TOML_CONFIG" "[firewall]" || return 1
    assert_file_contains "$TOML_CONFIG" "bogon_filter = false" || return 1
    assert_file_contains "$TOML_CONFIG" "[slots]" || return 1
    assert_file_contains "$TOML_CONFIG" 'default_action = "drop"' || return 1
    assert_file_contains "$TOML_CONFIG" 'enabled = ["sctp", { proto = 47, path = "/tmp/gre_handler.o" }]' || return 1
    assert_file_contains "$TOML_CONFIG" "sctp = [3868]" || return 1
    assert_file_contains "$TOML_CONFIG" '"198.51.100.8/32" = "office"'
)

test_run_permanent_supports_sctp_ports() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    TOML_CONFIG="$tmpdir/config.toml"
    reload_daemon() { :; }

    cat >"$TOML_CONFIG" <<'EOF_CFG'
[permanent_ports]
tcp = []
udp = []
sctp = []
EOF_CFG

    run_permanent add sctp 3868 >/dev/null || return 1

    local output
    output=$(run_permanent list) || return 1
    assert_contains "$output" "SCTP 3868" || return 1
    assert_file_contains "$TOML_CONFIG" "sctp = [3868]"
)

test_detect_backend_prefers_xdp_runtime_state() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    BPF_PIN_DIR="$tmpdir/bpf"
    mkdir -p "$RUN_STATE_DIR" "$BPF_PIN_DIR"
    printf 'xdp\n' > "$RUN_STATE_DIR/backend"
    touch "$BPF_PIN_DIR/pkt_counters"

    BACKEND=""
    IFACE="eth0"
    detect_backend || return 1
    assert_eq "$BACKEND" "xdp"
)

test_detect_backend_falls_back_to_nftables() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    BPF_PIN_DIR="$tmpdir/bpf"
    mkdir -p "$RUN_STATE_DIR" "$BPF_PIN_DIR" "$tmpdir/bin"
    printf 'nftables\n' > "$RUN_STATE_DIR/backend"

    cat >"$tmpdir/bin/nft" <<'EOF_NFT'
#!/bin/sh
exit 0
EOF_NFT
    chmod +x "$tmpdir/bin/nft"

    PATH="$tmpdir/bin:$BASE_PATH"
    BACKEND=""
    IFACE="eth0"
    detect_backend || return 1
    assert_eq "$BACKEND" "nftables"
)

test_detect_backend_reports_missing_state() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    BPF_PIN_DIR="$tmpdir/bpf"
    mkdir -p "$RUN_STATE_DIR" "$BPF_PIN_DIR" "$tmpdir/bin"

    PATH="$tmpdir/bin:$BASE_PATH"
    IFACE="eth0"

    local output status
    output=$(detect_backend 2>&1)
    status=$?
    assert_eq "$status" "1" || return 1
    assert_contains "$output" "No active Auto XDP backend detected."
)

test_run_backend_reports_runtime_state_and_conntrack_counts() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    BPF_PIN_DIR="$tmpdir/bpf"
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    mkdir -p "$RUN_STATE_DIR" "$BPF_PIN_DIR" "$tmpdir/bin"
    printf 'xdp\n' > "$RUN_STATE_DIR/backend"
    printf 'native\n' > "$RUN_STATE_DIR/xdp_mode"
    touch "$BPF_PIN_DIR/pkt_counters" "$BPF_PIN_DIR/tcp_conntrack" "$BPF_PIN_DIR/udp_conntrack"
    cat >"$CONFIG_FILE" <<'EOF_CFG'
IFACES="eth9"
PREFERRED_BACKEND="auto"
EOF_CFG

    cat >"$tmpdir/bin/ip" <<'EOF_IP'
#!/bin/sh
printf '%s\n' '2: eth9: <BROADCAST> mtu 1500 xdp'
EOF_IP
    cat >"$tmpdir/bin/tc" <<'EOF_TC'
#!/bin/sh
if [ "$1" = "filter" ]; then
  printf '%s\n' 'filter protocol all pref 49152 bpf chain 0'
fi
EOF_TC
    cat >"$tmpdir/bin/bpftool" <<EOF_BPF
#!/bin/sh
case "\$*" in
  *"tcp_conntrack"*)
    printf '%s\n' '[{"key":[2,0,0,0,0,80,0,22]},{"key":[2,0,0,0,0,81,1,187]}]'
    ;;
  *"udp_conntrack"*)
    printf '%s\n' '[{"key":[2,0,0,0,0,53,0,53]}]'
    ;;
  *)
    printf '%s\n' '[]'
    ;;
esac
EOF_BPF
    chmod +x "$tmpdir/bin/ip" "$tmpdir/bin/tc" "$tmpdir/bin/bpftool"

    PATH="$tmpdir/bin:$BASE_PATH"
    IFACE=""
    BACKEND=""

    local output
    output=$(run_backend) || return 1
    assert_contains "$output" "Backend   : xdp" || return 1
    assert_contains "$output" "XDP mode  : native" || return 1
    assert_contains "$output" "XDP attach: eth9=native" || return 1
    assert_contains "$output" "tc egress : eth9=attached" || return 1
    assert_contains "$output" "Conntrack : tcp=2 udp=1"
)

test_run_backend_json_reports_runtime_state_and_conntrack_counts() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    RUN_STATE_DIR="$tmpdir/run"
    BPF_PIN_DIR="$tmpdir/bpf"
    CONFIG_FILE="$tmpdir/auto_xdp.env"
    mkdir -p "$RUN_STATE_DIR" "$BPF_PIN_DIR" "$tmpdir/bin"
    printf 'xdp\n' > "$RUN_STATE_DIR/backend"
    printf 'native\n' > "$RUN_STATE_DIR/xdp_mode"
    touch "$BPF_PIN_DIR/pkt_counters" "$BPF_PIN_DIR/tcp_conntrack" "$BPF_PIN_DIR/udp_conntrack"
    cat >"$CONFIG_FILE" <<'EOF_CFG'
IFACES="eth9"
PREFERRED_BACKEND="auto"
EOF_CFG

    cat >"$tmpdir/bin/ip" <<'EOF_IP'
#!/bin/sh
printf '%s\n' '2: eth9: <BROADCAST> mtu 1500 xdp'
EOF_IP
    cat >"$tmpdir/bin/tc" <<'EOF_TC'
#!/bin/sh
if [ "$1" = "filter" ]; then
  printf '%s\n' 'filter protocol all pref 49152 bpf chain 0'
fi
EOF_TC
    cat >"$tmpdir/bin/bpftool" <<EOF_BPF
#!/bin/sh
case "\$*" in
  *"tcp_conntrack"*)
    printf '%s\n' '[{"key":[2,0,0,0,0,80,0,22]},{"key":[2,0,0,0,0,81,1,187]}]'
    ;;
  *"udp_conntrack"*)
    printf '%s\n' '[{"key":[2,0,0,0,0,53,0,53]}]'
    ;;
  *)
    printf '%s\n' '[]'
    ;;
esac
EOF_BPF
    chmod +x "$tmpdir/bin/ip" "$tmpdir/bin/tc" "$tmpdir/bin/bpftool"

    PATH="$tmpdir/bin:$BASE_PATH"

    local output
    output=$(run_backend --json) || return 1
    python3 - "$output" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])
assert data["backend"] == "xdp"
assert data["preferred_backend"] == "auto"
assert data["interfaces"] == ["eth9"]
assert data["xdp_mode"] == "native"
assert data["xdp_attach"] == {"eth9": "native"}
assert data["tc_egress"] == {"eth9": "attached"}
assert data["conntrack"] == {"tcp": 2, "udp": 1}
PY
)

test_run_conntrack_summarizes_destination_ports() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    mkdir -p "$BPF_PIN_DIR" "$tmpdir/bin"
    touch "$BPF_PIN_DIR/tcp_conntrack" "$BPF_PIN_DIR/udp_conntrack"

    cat >"$tmpdir/bin/bpftool" <<EOF_BPF
#!/bin/sh
case "\$*" in
  *"tcp_conntrack"*)
    printf '%s\n' '[{"key":[2,0,0,0,0,80,0,22]},{"key":[10,0,0,0,0,81,0,22]},{"key":[2,0,0,0,0,82,1,187]}]'
    ;;
  *"udp_conntrack"*)
    printf '%s\n' '[{"key":[2,0,0,0,0,53,0,53]}]'
    ;;
  *)
    printf '%s\n' '[]'
    ;;
esac
EOF_BPF
    chmod +x "$tmpdir/bin/bpftool"

    PATH="$tmpdir/bin:$BASE_PATH"

    local output
    output=$(run_conntrack tcp --limit 2) || return 1
    assert_contains "$output" "TCP conntrack:" || return 1
    assert_contains "$output" "dport 22" || return 1
    assert_contains "$output" "ipv4=1" || return 1
    assert_contains "$output" "ipv6=1" || return 1
    assert_contains "$output" "total=3"
)

test_cli_help_runs_without_runtime_state() (
    local output
    output=$(bash "$REPO_ROOT/axdp" help)
    assert_contains "$output" "Usage: axdp"
)

test_slot_load_sctp_reuses_shared_maps() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    INSTALL_DIR="$tmpdir/install"
    TOML_CONFIG="$tmpdir/config.toml"
    mkdir -p "$BPF_PIN_DIR/handlers" "$INSTALL_DIR/handlers" "$tmpdir/bin"
    touch \
        "$BPF_PIN_DIR/slot_ctx_map" \
        "$BPF_PIN_DIR/sctp_whitelist" \
        "$BPF_PIN_DIR/sctp_conntrack" \
        "$BPF_PIN_DIR/proto_handlers" \
        "$INSTALL_DIR/handlers/sctp_handler.o"
    cat >"$TOML_CONFIG" <<'EOF_CFG'
[slots]
enabled = []
EOF_CFG

    cat >"$tmpdir/bin/bpftool" <<EOF_BPFSH
#!/bin/sh
printf '%s\n' "\$*" >> "$tmpdir/bpftool.log"
exit 0
EOF_BPFSH
    chmod +x "$tmpdir/bin/bpftool"

    PATH="$tmpdir/bin:$BASE_PATH"
    run_slot load sctp >/dev/null || return 1

    assert_file_contains "$tmpdir/bpftool.log" "map name slot_ctx_map pinned $BPF_PIN_DIR/slot_ctx_map" || return 1
    assert_file_contains "$tmpdir/bpftool.log" "map name sctp_whitelist pinned $BPF_PIN_DIR/sctp_whitelist" || return 1
    assert_file_contains "$tmpdir/bpftool.log" "map name sctp_conntrack pinned $BPF_PIN_DIR/sctp_conntrack"
)

test_slot_load_custom_c_compiles_and_persists_object_path() (
    source "$REPO_ROOT/axdp"
    set +e

    local tmpdir
    tmpdir=$(mktemp -d)
    BPF_PIN_DIR="$tmpdir/bpf"
    INSTALL_DIR="$tmpdir/install"
    TOML_CONFIG="$tmpdir/config.toml"
    mkdir -p "$BPF_PIN_DIR/handlers" "$INSTALL_DIR/handlers" "$tmpdir/bin"
    touch \
        "$BPF_PIN_DIR/slot_ctx_map" \
        "$BPF_PIN_DIR/proto_handlers" \
        "$INSTALL_DIR/handlers/xdp_slot_ctx.h"
    cat >"$TOML_CONFIG" <<'EOF_CFG'
[slots]
enabled = []
EOF_CFG
    cat >"$tmpdir/custom_handler.c" <<'EOF_SRC'
// test source
EOF_SRC

    cat >"$tmpdir/bin/clang" <<EOF_CLANG
#!/bin/sh
out=""
prev=""
for arg in "\$@"; do
  if [ "\$prev" = "-o" ]; then
    out="\$arg"
    break
  fi
  prev="\$arg"
done
printf '%s\n' "\$*" >> "$tmpdir/clang.log"
: > "\$out"
exit 0
EOF_CLANG
    cat >"$tmpdir/bin/bpftool" <<EOF_BPFSH
#!/bin/sh
printf '%s\n' "\$*" >> "$tmpdir/bpftool.log"
exit 0
EOF_BPFSH
    chmod +x "$tmpdir/bin/clang" "$tmpdir/bin/bpftool"

    PATH="$tmpdir/bin:$BASE_PATH"
    run_slot load 99 "$tmpdir/custom_handler.c" >/dev/null || return 1

    assert_file_contains "$tmpdir/clang.log" "$tmpdir/custom_handler.c" || return 1
    assert_file_contains "$tmpdir/bpftool.log" "$INSTALL_DIR/handlers/custom_99_custom_handler.o" || return 1
    assert_file_contains "$TOML_CONFIG" "[[slots.enabled]]" || return 1
    assert_file_contains "$TOML_CONFIG" 'proto = 99' || return 1
    assert_file_contains "$TOML_CONFIG" 'path = "'"$INSTALL_DIR"'/handlers/custom_99_custom_handler.o"'
)

run_test "axdp formats human-readable counters and rates" test_format_helpers_render_human_output
run_test "axdp parses stats flags" test_parse_stats_args_sets_expected_flags
run_test "axdp parses ports flags" test_parse_ports_args_sets_expected_flags
run_test "axdp sorts and diffs csv port lists" test_csv_helpers_sort_and_diff_ports
run_test "axdp validates log levels and rewrites config" test_valid_log_level_and_config_updates
run_test "axdp reads and updates runtime log level" test_run_log_level_reads_and_updates_config
run_test "axdp preserves unrelated TOML sections on config update" test_config_updates_preserve_unrelated_sections
run_test "axdp permanent supports SCTP ports" test_run_permanent_supports_sctp_ports
run_test "axdp detects active xdp backend from runtime state" test_detect_backend_prefers_xdp_runtime_state
run_test "axdp detects nftables fallback backend" test_detect_backend_falls_back_to_nftables
run_test "axdp reports when no backend is active" test_detect_backend_reports_missing_state
run_test "axdp backend reports runtime attach state and conntrack counts" test_run_backend_reports_runtime_state_and_conntrack_counts
run_test "axdp backend json reports runtime attach state and conntrack counts" test_run_backend_json_reports_runtime_state_and_conntrack_counts
run_test "axdp conntrack summarizes destination ports" test_run_conntrack_summarizes_destination_ports
run_test "axdp help works without installation" test_cli_help_runs_without_runtime_state
run_test "axdp slot load sctp reuses shared SCTP maps" test_slot_load_sctp_reuses_shared_maps
run_test "axdp slot load custom c compiles and persists object path" test_slot_load_custom_c_compiles_and_persists_object_path

finish_tests
