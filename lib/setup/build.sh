# lib/setup/build.sh — BPF compilation helpers
# Sourced by setup_xdp.sh after fetch.sh and runtime_common.

ensure_bpf_helper_bootstrap() {
    local helper_path="$BPF_HELPER_SRC"
    if [[ ! -f "$helper_path" ]]; then
        helper_path=$(mktemp)
    fi
    if ! fetch_local_or_remote "$BPF_HELPER_SRC" "$BPF_HELPER_SRC" "$helper_path"; then
        warn "Failed to fetch ${BPF_HELPER_SRC}; helper-based map operations will be unavailable."
        return 1
    fi
    BPF_HELPER_BOOTSTRAP="$helper_path"
    return 0
}

bootstrap_bpf_helper_step() {
    step_begin "Fetching BPF helper script"
    if ensure_bpf_helper_bootstrap; then
        step_ok
    else
        step_warn "map operations limited"
    fi

    if ! command -v bpftool &>/dev/null || ! command -v clang &>/dev/null; then
        echo -e "  ${YELLOW}[WARN]${NC}  bpftool or clang still missing — XDP backend may be unavailable."
    fi
}

compile_bpf_object() {
    local src_path="$1"
    local obj_path="$2"

    if ! clang -O3 -g \
        -target bpf \
        -mcpu=v3 \
        "-D__TARGET_ARCH_${TARGET_ARCH}" \
        ${HOST_ARCH_FLAG:+"$HOST_ARCH_FLAG"} \
        -fno-stack-protector \
        -Wall -Wno-unused-value \
        -I/usr/include \
        -I"$ASM_INC" \
        -I/usr/include/bpf \
        -Ibpf/include \
        -I. \
        -c "$src_path" -o "$obj_path"; then
        return 1
    fi
    return 0
}

resolve_bpf_target_arch() {
    local arch
    arch=$(uname -m)

    case "$arch" in
        x86_64)
            TARGET_ARCH="x86"
            HOST_ARCH_FLAG="-D__x86_64__"
            ;;
        aarch64|arm64)
            TARGET_ARCH="arm64"
            HOST_ARCH_FLAG="-D__aarch64__"
            ;;
        armv7*|armv6*|arm)
            TARGET_ARCH="arm"
            HOST_ARCH_FLAG="-D__arm__"
            ;;
        *)
            TARGET_ARCH="$arch"
            HOST_ARCH_FLAG=""
            ;;
    esac
}

resolve_bpf_asm_include() {
    local multiarch=""
    local candidates=()

    if command -v gcc &>/dev/null; then
        multiarch=$(gcc -print-multiarch 2>/dev/null || true)
    fi

    if [[ -n "$multiarch" ]]; then
        candidates+=("/usr/include/${multiarch}")
    fi

    case "$DISTRO_FAMILY:$TARGET_ARCH" in
        debian:x86)
            candidates+=("/usr/include/x86_64-linux-gnu")
            ;;
        debian:arm64)
            candidates+=("/usr/include/aarch64-linux-gnu")
            ;;
        debian:arm)
            candidates+=("/usr/include/arm-linux-gnueabihf")
            ;;
    esac

    candidates+=(
        "/usr/src/linux-headers-$(uname -r)/arch/${TARGET_ARCH}/include/generated"
        "/usr/include"
    )

    local candidate
    for candidate in "${candidates[@]}"; do
        [[ -d "$candidate" ]] || continue
        if [[ -d "$candidate/asm" || "$candidate" == "/usr/include" ]]; then
            ASM_INC="$candidate"
            return 0
        fi
    done

    ASM_INC=""
    return 1
}

resolve_bpf_build_env() {
    resolve_bpf_target_arch
    resolve_bpf_asm_include
}

bpf_header_exists() {
    local header="$1"
    shift || true

    local include_root
    for include_root in "$@"; do
        [[ -n "$include_root" ]] || continue
        [[ -f "${include_root}/${header}" ]] && return 0
    done

    return 1
}

warn_from_log_file() {
    local log_path="$1"
    local prefix="${2:-}"
    local max_lines="${3:-8}"
    local count=0
    local line

    [[ -s "$log_path" ]] || return 0

    while IFS= read -r line; do
        warn "${prefix}${line}"
        count=$((count + 1))
        if [[ $count -ge $max_lines ]]; then
            warn "${prefix}(additional output truncated)"
            break
        fi
    done <"$log_path"
}

prepare_slot_handler_sources() {
    local _handler_artifacts=(
        "handlers/Makefile"
        "handlers/gre_handler.c"
        "handlers/esp_handler.c"
        "handlers/sctp_handler.c"
        "handlers/xdp_slot_ctx.h"
    )
    local _handler_file=""
    local _missing=()

    mkdir -p handlers
    for _handler_file in "${_handler_artifacts[@]}"; do
        if ! fetch_local_or_remote "${_handler_file}" "${_handler_file}" "${_handler_file}"; then
            _missing+=("${_handler_file}")
        fi
    done

    if [[ ${#_missing[@]} -gt 0 ]]; then
        warn "Slot handlers skipped: failed to prepare sources: ${_missing[*]}"
        return 1
    fi

    if [[ ! -f "handlers/Makefile" ]]; then
        warn "Slot handlers skipped: handlers/Makefile not found"
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

    local _bpf_headers=(common.h keys.h maps.h trust_acl.h rate_limit.h conntrack.h parse.h slots.h)
    local _hdr
    for _hdr in "${_bpf_headers[@]}"; do
        fetch_local_or_remote "bpf/include/${_hdr}" "bpf/include/${_hdr}" "bpf/include/${_hdr}" || true
    done
    local _handlers_ready=0
    if prepare_slot_handler_sources; then
        _handlers_ready=1
    fi

    if ! resolve_bpf_build_env || [[ -z "$ASM_INC" ]]; then
        warn "ASM headers not found; XDP backend will be skipped."
        return 1
    fi

    if ! compile_bpf_object "$XDP_SRC" "$XDP_OBJ"; then
        warn "Failed to compile ${XDP_SRC}; XDP backend will be skipped."
        return 1
    fi

    mkdir -p "$INSTALL_DIR"
    cp "$XDP_OBJ" "$XDP_OBJ_INSTALLED"

    if ! fetch_local_or_remote "$TC_SRC" "$TC_SRC" "$TC_SRC"; then
        warn "Unable to fetch ${TC_SRC}; TCP/UDP tc egress tracker will be skipped."
        return 0
    fi
    if ! compile_bpf_object "$TC_SRC" "$TC_OBJ"; then
        warn "Failed to compile ${TC_SRC}; TCP/UDP tc egress tracker will be skipped."
        return 0
    fi
    cp "$TC_OBJ" "$TC_OBJ_INSTALLED"

    if [[ $_handlers_ready -eq 1 && -d "handlers" ]] && command -v make &>/dev/null; then
        if ! bpf_header_exists "linux/bpf.h" "/usr/include" "$ASM_INC"; then
            warn "Slot handlers skipped: missing linux/bpf.h in /usr/include or ${ASM_INC}"
        elif ! bpf_header_exists "bpf/bpf_helpers.h" "/usr/include" "/usr/local/include"; then
            warn "Slot handlers skipped: missing bpf/bpf_helpers.h in /usr/include or /usr/local/include"
        else
            local handler_log
            handler_log=$(mktemp)
            if make -C handlers -f Makefile --no-print-directory \
                    CLANG="clang" \
                    ASM_INC="$ASM_INC" \
                    ARCH_FLAGS="-D__TARGET_ARCH_${TARGET_ARCH} ${HOST_ARCH_FLAG}" \
                    >"$handler_log" 2>&1; then
                mkdir -p "${INSTALL_DIR}/handlers"
                cp handlers/*.o "${INSTALL_DIR}/handlers/" 2>/dev/null || true
            else
                warn "Slot handler compilation failed; handlers will be unavailable"
                warn_from_log_file "$handler_log" "handler build: "
            fi
            rm -f "$handler_log"
        fi
    fi
    return 0
}

compile_bpf_objects_step() {
    step_begin "Compiling XDP and tc BPF objects" COMPILE
    if compile_xdp_program; then
        step_ok
    else
        step_warn "compile failed — nftables fallback will be used"
    fi
}

cleanup_build_artifacts_step() {
    local _f
    local _cleaned=()

    step_begin "Cleaning up build artifacts"
    for _f in "$XDP_OBJ" "$TC_OBJ"; do
        if [[ -f "$_f" ]]; then
            rm -f "$_f" && _cleaned+=("$_f")
        fi
    done

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        for _f in "$XDP_SRC" "$TC_SRC"; do
            if [[ -f "$_f" ]]; then
                rm -f "$_f" && _cleaned+=("$_f")
            fi
        done
    fi

    if [[ -n "$BPF_HELPER_BOOTSTRAP" && "$BPF_HELPER_BOOTSTRAP" != "$BPF_HELPER_SRC" && -f "$BPF_HELPER_BOOTSTRAP" ]]; then
        rm -f "$BPF_HELPER_BOOTSTRAP" && _cleaned+=("$BPF_HELPER_BOOTSTRAP")
    fi

    if [[ ${#_cleaned[@]} -gt 0 ]]; then
        step_ok "Removed: ${_cleaned[*]}"
    else
        step_ok "Nothing to remove"
    fi
}
