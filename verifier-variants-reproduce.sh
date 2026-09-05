#!/usr/bin/env bash
# Measure verifier cost for the TCP accounting experiments.

set -Eeuo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
cd "$REPO_ROOT"

if [[ "$(uname -s)" != "Linux" ]]; then
    printf '%s\n' "[WARNING] verifier measurements require Linux" >&2
    exit 0
fi
if ! command -v clang >/dev/null 2>&1 || ! command -v bpftool >/dev/null 2>&1; then
    printf '%s\n' "[WARNING] SKIP clang or bpftool missing" >&2
    exit 0
fi
if ! command -v timeout >/dev/null 2>&1; then
    printf '%s\n' "[ERROR] timeout command is required for verifier measurements" >&2
    exit 1
fi

source "$REPO_ROOT/setup_xdp.sh"
resolve_bpf_build_env
[[ -n "${ASM_INC:-}" ]] || {
    printf '%s\n' "[ERROR] unable to resolve BPF assembly include path" >&2
    exit 1
}

output_file="${VERIFIER_VARIANTS_FILE:-verifier-variants.tsv}"
log_dir="${VERIFIER_VARIANTS_LOG_DIR:-${output_file%.tsv}-logs}"
pin_root="${BPF_VARIANT_PIN_ROOT:-/sys/fs/bpf}/auto-xdp-verifier-$$"
variant_timeout_seconds="${VERIFIER_VARIANT_TIMEOUT_SECONDS:-90}"
[[ "$variant_timeout_seconds" =~ ^[0-9]+$ && "$variant_timeout_seconds" -gt 0 ]] || {
    printf '%s\n' "[ERROR] VERIFIER_VARIANT_TIMEOUT_SECONDS must be a positive integer" >&2
    exit 1
}
work_dir=$(mktemp -d)
baseline_status=""
variant_filter="${VERIFIER_VARIANTS:-}"

cleanup() {
    rm -rf "$work_dir"
    rm -rf "$pin_root"
}
trap cleanup EXIT

mkdir -p "$(dirname "$output_file")" "$log_dir"
mkdir -p "$pin_root"

printf '# kernel\t%s\n' "$(uname -r)" >"$output_file"
printf '# clang\t%s\n' "$(clang --version | head -n 1)" >>"$output_file"
printf '# bpftool\t%s\n' "$(bpftool version | head -n 1)" >>"$output_file"
printf 'variant\tstatus\tstatic_insns\tprocessed_insns\tmax_states_per_insn\ttotal_states\tpeak_states\tverification_time_usec\tstack_depth\n' >>"$output_file"

measure_variant() {
    local variant="$1"
    local flags="$2"
    local obj="$work_dir/${variant}.o"
    local log="$log_dir/${variant}.log"
    local raw_log="$work_dir/${variant}.raw.log"
    local pin_dir="$pin_root/$variant"
    local -a base_flags=(
        -O3 -g -target bpf -mcpu=v3
        "-D__TARGET_ARCH_${TARGET_ARCH}"
        -fno-stack-protector -Wall -Wno-unused-value
        -I/usr/include "-I$ASM_INC" -I/usr/include/bpf
        "-I$REPO_ROOT/bpf/include" "-I$REPO_ROOT"
    )
    local -a variant_flags=()
    local metrics load_status summary_log

    if [[ -n "$variant_filter" ]]; then
        case ",$variant_filter," in
            *,"$variant",*) ;;
            *) return 0 ;;
        esac
    fi

    if [[ -n "${HOST_ARCH_FLAG:-}" ]]; then
        base_flags+=("$HOST_ARCH_FLAG")
    fi
    if [[ -n "$flags" ]]; then
        read -r -a variant_flags <<<"$flags"
    fi

    if ! clang "${base_flags[@]}" "${variant_flags[@]}" \
        -c "$REPO_ROOT/bpf/xdp_firewall.c" -o "$obj" >"$raw_log" 2>&1; then
        printf '%s\tcompile_failed\t\t\t\t\t\t\t\n' "$variant" >>"$output_file"
        cp "$raw_log" "$log"
        [[ "$variant" == baseline ]] && baseline_status=compile_failed
        return 0
    fi

    mkdir -p "$pin_dir"
    if timeout "${variant_timeout_seconds}s" bpftool -d prog load "$obj" "$pin_dir/prog" type xdp \
        pinmaps "$pin_dir" >>"$raw_log" 2>&1; then
        :
    else
        load_status=$?
        if [[ $load_status -eq 124 || $load_status -eq 137 ]]; then
            printf '%s\tverifier_timeout\t\t\t\t\t\t\t\n' "$variant" >>"$output_file"
            [[ "$variant" == baseline ]] && baseline_status=verifier_timeout
        else
            printf '%s\tverifier_failed\t\t\t\t\t\t\t\n' "$variant" >>"$output_file"
            [[ "$variant" == baseline ]] && baseline_status=verifier_failed
        fi
        cp "$raw_log" "$log"
        rm -rf "$pin_dir"
        return 0
    fi

    if metrics=$(bash "$REPO_ROOT/tests/bash/extract_verifier_metrics.sh" "$variant" <"$raw_log"); then
        printf '%s\tpassed\t%s\n' "$variant" "${metrics#*$'\t'}" >>"$output_file"
        [[ "$variant" == baseline ]] && baseline_status=passed
        summary_log="$work_dir/${variant}.summary"
        awk '/found program .*code size [0-9]+ insns|^verification time [0-9]+ usec$|^stack depth [0-9]+(\+[0-9]+)*$|^processed [0-9]+ insns /' \
            "$raw_log" >"$summary_log"
        mv "$summary_log" "$log"
    else
        printf '%s\tmetrics_unavailable\t\t\t\t\t\t\t\n' "$variant" >>"$output_file"
        [[ "$variant" == baseline ]] && baseline_status=metrics_unavailable
        cp "$raw_log" "$log"
    fi
    rm -rf "$pin_dir"
}

measure_variant baseline ""
measure_variant shared-inline "-DAUTO_XDP_SHARED_CONN_UPDATE_MODE=1"
measure_variant shared-static-subprog "-DAUTO_XDP_SHARED_CONN_UPDATE_MODE=2"
measure_variant shared-global-subprog "-DAUTO_XDP_SHARED_CONN_UPDATE_MODE=3"
measure_variant no-l3 "-DAUTO_XDP_TCP_ACCOUNT_L3=0"
measure_variant no-l4 "-DAUTO_XDP_TCP_ACCOUNT_L4=0"
measure_variant no-l5 "-DAUTO_XDP_TCP_ACCOUNT_L5=0"
measure_variant no-accounting "-DAUTO_XDP_TCP_ACCOUNT_L3=0 -DAUTO_XDP_TCP_ACCOUNT_L4=0 -DAUTO_XDP_TCP_ACCOUNT_L5=0"
measure_variant family-split "-DAUTO_XDP_TCP_ACCOUNT_FAMILY_SPLIT=1"
measure_variant accounting-static-subprog "-DAUTO_XDP_TCP_ACCOUNTING_MODE=1"
measure_variant accounting-global-subprog "-DAUTO_XDP_TCP_ACCOUNTING_MODE=2"

printf '%s\n' "[INFO] verifier metrics written to $output_file"
printf '%s\n' "[INFO] verifier logs written to $log_dir"
if [[ -n "$variant_filter" ]]; then
    case ",$variant_filter," in
        *,baseline,*) ;;
        *) exit 0 ;;
    esac
fi
[[ "$baseline_status" == passed ]] || {
    printf '%s\n' "[ERROR] baseline verifier measurement failed: $baseline_status" >&2
    exit 1
}
