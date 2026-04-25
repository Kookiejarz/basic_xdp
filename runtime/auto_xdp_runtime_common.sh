#!/bin/bash

_auto_xdp_first_value() {
    local name=""
    for name in "$@"; do
        if [[ -n "${!name:-}" ]]; then
            printf '%s' "${!name}"
            return 0
        fi
    done
    return 1
}

_auto_xdp_iface_var_name() {
    local name=""
    for name in AUTO_XDP_IFACES _IFACES IFACES; do
        if declare -p "$name" >/dev/null 2>&1; then
            printf '%s' "$name"
            return 0
        fi
    done
    return 1
}

_auto_xdp_info() {
    if declare -F auto_xdp_shared_info >/dev/null 2>&1; then
        auto_xdp_shared_info "$@"
    fi
}

_auto_xdp_warn() {
    if declare -F auto_xdp_shared_warn >/dev/null 2>&1; then
        auto_xdp_shared_warn "$@"
    else
        printf '[auto_xdp] warning: %s\n' "$*" >&2
    fi
}

ensure_bpffs() {
    if ! mount | grep -q 'type bpf'; then
        _auto_xdp_info "Mounting bpffs on /sys/fs/bpf..."
        mount -t bpf bpf /sys/fs/bpf || {
            _auto_xdp_warn "bpffs mount failed."
            return 1
        }
    fi
}

cleanup_tc_egress_filter() {
    command -v tc &>/dev/null || return 0
    local iface_var iface
    iface_var=$(_auto_xdp_iface_var_name) || return 0
    local -n ifaces_ref="$iface_var"
    for iface in "${ifaces_ref[@]}"; do
        tc filter del dev "$iface" egress pref "${TC_FILTER_PREF:-49152}" 2>/dev/null || true
    done
}

xdp_maps_ready() {
    local required=(
        "${BPF_PIN_DIR}/prog"
        "${BPF_PIN_DIR}/tcp_whitelist"
        "${BPF_PIN_DIR}/udp_whitelist"
        "${BPF_PIN_DIR}/sctp_whitelist"
        "${BPF_PIN_DIR}/tcp_conntrack"
        "${BPF_PIN_DIR}/udp_conntrack"
        "${BPF_PIN_DIR}/sctp_conntrack"
        "${BPF_PIN_DIR}/trusted_ipv4"
        "${BPF_PIN_DIR}/trusted_ipv6"
        "${BPF_PIN_DIR}/syn_rate_ports"
        "${BPF_PIN_DIR}/udp_rate_ports"
        "${BPF_PIN_DIR}/syn_agg_rate_ports"
        "${BPF_PIN_DIR}/tcp_conn_limit_ports"
        "${BPF_PIN_DIR}/udp_agg_rate_ports"
        "${BPF_PIN_DIR}/udp_global_rl"
        "${BPF_PIN_DIR}/bogon_cfg"
        "${BPF_PIN_DIR}/proto_handlers"
        "${BPF_PIN_DIR}/slot_ctx_map"
        "${BPF_PIN_DIR}/slot_def_action"
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
    local helper_script=""

    [[ -e "$map_path" ]] || return 0

    helper_script=$(_auto_xdp_first_value BPF_HELPER_BOOTSTRAP BPF_HELPER_SCRIPT) || {
        _auto_xdp_warn "BPF helper is not available for conntrack seeding."
        return 0
    }

    if ! seeded=$("${PYTHON3_BIN:-python3}" "$helper_script" seed-tcp-conntrack --map-path "$map_path"); then
        _auto_xdp_warn "Failed to pre-seed tcp_conntrack; established sessions may reconnect."
        return 0
    fi

    if [[ "$seeded" != "0" ]]; then
        _auto_xdp_info "Seeded ${seeded} existing TCP session(s) into tcp_conntrack."
    fi
}

load_tc_egress_program() {
    local tc_prog_path="${BPF_PIN_DIR}/tc_egress_prog"
    local tc_obj_path=""
    local iface_var iface attached=0

    if ! command -v tc &>/dev/null; then
        _auto_xdp_warn "tc not found; TCP/UDP/SCTP reply tracking on egress will be skipped."
        return 1
    fi

    tc_obj_path=$(_auto_xdp_first_value TC_OBJ_PATH TC_OBJ_INSTALLED) || tc_obj_path=""
    rm -f "$tc_prog_path"
    if [[ ! -f "$tc_obj_path" ]]; then
        _auto_xdp_warn "tc egress object not found; TCP/UDP/SCTP reply tracking on egress will be skipped."
        return 1
    fi

    if ! bpftool prog load "$tc_obj_path" "$tc_prog_path" \
        type classifier \
        map name tcp_conntrack pinned "${BPF_PIN_DIR}/tcp_conntrack" \
        map name udp_conntrack pinned "${BPF_PIN_DIR}/udp_conntrack" \
        map name sctp_conntrack pinned "${BPF_PIN_DIR}/sctp_conntrack" >/dev/null 2>&1; then
        _auto_xdp_warn "Failed to load tc egress program; outbound TCP/UDP/SCTP reply tracking will be limited."
        return 1
    fi

    iface_var=$(_auto_xdp_iface_var_name) || {
        _auto_xdp_warn "No interfaces configured for tc egress attach."
        return 1
    }
    local -n ifaces_ref="$iface_var"
    if [[ ${#ifaces_ref[@]} -eq 0 ]]; then
        _auto_xdp_warn "No interfaces configured for tc egress attach."
        return 1
    fi

    for iface in "${ifaces_ref[@]}"; do
        tc qdisc add dev "$iface" clsact 2>/dev/null || true
        if tc filter replace dev "$iface" egress pref "${TC_FILTER_PREF:-49152}" \
            bpf direct-action object-pinned "$tc_prog_path" >/dev/null 2>&1; then
            _auto_xdp_info "Attached tc egress TCP/UDP/SCTP tracker on $iface."
            attached=$((attached + 1))
        else
            _auto_xdp_warn "Failed to attach tc egress filter on $iface; reply tracking will be limited for this interface."
        fi
    done

    [[ $attached -gt 0 ]] && return 0 || return 1
}

load_slot_handlers() {
    local handlers_dir="${AUTO_XDP_HANDLERS_DIR:-${HANDLERS_DIR:-${INSTALL_DIR}/handlers}}"
    local py_bin="${PYTHON3_BIN:-python3}"

    [[ -e "${BPF_PIN_DIR}/proto_handlers" ]] || {
        _auto_xdp_warn "proto_handlers map not pinned; skipping slot handler loading."
        return 0
    }

    local default_action="pass"
    if command -v "$py_bin" &>/dev/null && [[ -f "$TOML_CONFIG" ]]; then
        default_action=$("$py_bin" -c "
import sys
try:
    import tomllib
    with open('${TOML_CONFIG}', 'rb') as f:
        cfg = tomllib.load(f)
    print(cfg.get('slots', {}).get('default_action', 'pass'))
except Exception:
    print('pass')
" 2>/dev/null) || default_action="pass"
    fi
    local action_val=0
    [[ "$default_action" == "drop" ]] && action_val=1
    bpftool map update pinned "${BPF_PIN_DIR}/slot_def_action" \
        key 0 0 0 0 value "$action_val" 0 0 0 2>/dev/null \
        && _auto_xdp_info "Slot default_action: ${default_action}" \
        || _auto_xdp_warn "Failed to set slot default_action"

    local enabled_json="[]"
    if command -v "$py_bin" &>/dev/null && [[ -f "$TOML_CONFIG" ]]; then
        enabled_json=$("$py_bin" -c "
import sys, json
try:
    import tomllib
    with open('${TOML_CONFIG}', 'rb') as f:
        cfg = tomllib.load(f)
    print(json.dumps(cfg.get('slots', {}).get('enabled', [])))
except Exception:
    print('[]')
" 2>/dev/null) || enabled_json="[]"
    fi

    [[ "$enabled_json" == "[]" ]] && return 0
    [[ -d "$handlers_dir" ]] || {
        _auto_xdp_warn "Handlers dir $handlers_dir not found; skipping slot loading."
        return 0
    }

    local slot_pin_dir="${BPF_PIN_DIR}/handlers"
    mkdir -p "$slot_pin_dir"

    "$py_bin" - "$enabled_json" "$handlers_dir" "$slot_pin_dir" \
        "${BPF_PIN_DIR}" <<'PYEOF'
import sys, json, subprocess, os

enabled = json.loads(sys.argv[1])
handlers_dir = sys.argv[2]
slot_pin_dir = sys.argv[3]
bpf_pin_dir = sys.argv[4]

BUILTIN = {"gre": (47, "gre_handler.o"),
           "esp": (50, "esp_handler.o"),
           "sctp": (132, "sctp_handler.o")}

for entry in enabled:
    if isinstance(entry, str):
        if entry not in BUILTIN:
            print(f"  [WARN] Unknown built-in handler: {entry}", file=sys.stderr)
            continue
        proto, obj_name = BUILTIN[entry]
        obj_path = os.path.join(handlers_dir, obj_name)
    elif isinstance(entry, dict):
        proto = int(entry["proto"])
        obj_path = entry["path"]
    else:
        continue

    if not os.path.exists(obj_path):
        print(f"  [WARN] Handler not found: {obj_path}", file=sys.stderr)
        continue

    pin_path = os.path.join(slot_pin_dir, f"proto_{proto}")
    ctx_map = os.path.join(bpf_pin_dir, "slot_ctx_map")
    load_cmd = [
        "bpftool", "prog", "load", obj_path, pin_path,
        "type", "xdp",
        "map", "name", "slot_ctx_map", "pinned", ctx_map,
    ]
    if proto == 132:
        sctp_whitelist = os.path.join(bpf_pin_dir, "sctp_whitelist")
        sctp_conntrack = os.path.join(bpf_pin_dir, "sctp_conntrack")
        if not (os.path.exists(sctp_whitelist) and os.path.exists(sctp_conntrack)):
            print("  [WARN] Shared SCTP maps not pinned; skipping proto 132", file=sys.stderr)
            continue
        load_cmd.extend([
            "map", "name", "sctp_whitelist", "pinned", sctp_whitelist,
            "map", "name", "sctp_conntrack", "pinned", sctp_conntrack,
        ])

    r = subprocess.run(load_cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"  [WARN] Failed to load proto {proto}: {r.stderr.strip()}", file=sys.stderr)
        continue

    k = f"{proto} 0 0 0"
    r2 = subprocess.run(
        ["bpftool", "map", "update", "pinned",
         os.path.join(bpf_pin_dir, "proto_handlers"),
         "key", *k.split(), "value", "pinned", pin_path],
        capture_output=True, text=True)
    if r2.returncode != 0:
        print(f"  [WARN] Failed to register proto {proto}: {r2.stderr.strip()}", file=sys.stderr)
        os.unlink(pin_path)
    else:
        print(f"  Loaded slot handler: proto {proto} ({obj_path})")
PYEOF
}
