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

    if ! command -v clang &>/dev/null || ! _tool_present bpftool; then
        warn "bpftool or clang still missing — XDP backend may be unavailable"
    fi
}

compile_bpf_object() {
    local src_path="$1"
    local obj_path="$2"
    local include_root="${3:-.}"

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
        -I"${include_root}/bpf/include" \
        -I"$include_root" \
        -c "$src_path" -o "$obj_path"; then
        return 1
    fi
    return 0
}

generate_xdp_map_abi() {
    local source_root="$1"
    local header="${source_root}/bpf/include/map_sizes.h"
    local rate4 rate6

    [[ -f "$header" ]] || return 1
    rate4=$(awk '$2 == "RATE_MAP_MAX_ENTRIES_V4" { print $3; exit }' "$header")
    rate6=$(awk '$2 == "RATE_MAP_MAX_ENTRIES_V6" { print $3; exit }' "$header")
    [[ "$rate4" =~ ^[0-9]+$ && "$rate6" =~ ^[0-9]+$ ]] || return 1

    cat >"${BUILD_STAGING_DIR}/xdp_map_abi.txt" <<EOF
# Map capacities derived from bpf/include/map_sizes.h.
hblk4 ${rate4}
hblk6 ${rate6}
udp_hv4 ${rate4}
udp_hv6 ${rate6}
synag4 ${rate4}
synag6 ${rate6}
udpag4 ${rate4}
udpag6 ${rate6}
EOF
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

ensure_build_staging_dir() {
    if [[ -n "${BUILD_STAGING_DIR:-}" && -d "$BUILD_STAGING_DIR" ]]; then
        return 0
    fi

    BUILD_STAGING_DIR=$(mktemp -d)
    return 0
}

stage_build_source() {
    local local_path="$1"
    local remote_name="$2"
    local relative_target="$3"
    local target_path=""

    ensure_build_staging_dir || return 1
    target_path="${BUILD_STAGING_DIR}/${relative_target}"
    mkdir -p "$(dirname "$target_path")"
    fetch_local_or_remote "$local_path" "$remote_name" "$target_path"
}

prepare_slot_handler_sources() {
    local _handler_file=""
    local _missing=()
    local _source_dir="${SOURCE_ROOT:-${BOOTSTRAP_LOCAL_ROOT:-.}}"

    if [[ -d "${_source_dir}/handlers" ]]; then
        while IFS= read -r _handler_file; do
            _handler_file="${_handler_file#./}"
            if ! stage_build_source "${_handler_file}" "${_handler_file}" "${_handler_file}"; then
                _missing+=("${_handler_file}")
            fi
        done < <(
            find "${_source_dir}/handlers" -maxdepth 1 -type f \
                \( -name 'Makefile' -o -name '*.c' -o -name '*.h' \) \
                | sed "s|^${_source_dir}/||" | sort
        )
    else
        for _handler_file in handlers/Makefile handlers/xdp_slot_ctx.h handlers/*_handler.c; do
            [[ -e "${_source_dir}/${_handler_file}" || $PREFER_REMOTE_SOURCES -eq 1 ]] || continue
            if ! stage_build_source "${_handler_file}" "${_handler_file}" "${_handler_file}"; then
                _missing+=("${_handler_file}")
            fi
        done
    fi

    if [[ ${#_missing[@]} -gt 0 ]]; then
        warn "Slot handlers skipped: failed to prepare sources: ${_missing[*]}"
        return 1
    fi

    if [[ ! -f "${BUILD_STAGING_DIR}/handlers/Makefile" ]]; then
        warn "Slot handlers skipped: handlers/Makefile not found"
        return 1
    fi

    return 0
}

compile_xdp_program() {
    local _source_root=""
    local _handlers_dir=""
    HANDLER_BUILD_FAILED=0

    if ! command -v clang &>/dev/null || ! _tool_present bpftool; then
        warn "clang or bpftool missing; XDP backend will be skipped."
        return 1
    fi

    if ! stage_build_source "$XDP_SRC" "$XDP_SRC" "$XDP_SRC"; then
        warn "Unable to fetch ${XDP_SRC}; XDP backend will be skipped."
        return 1
    fi
    _source_root="$BUILD_STAGING_DIR"
    _handlers_dir="${_source_root}/handlers"

    local _hdr _header_root="${SOURCE_ROOT:-.}"
    if [[ -d "${_header_root}/bpf/include" ]]; then
        for _hdr in "${_header_root}"/bpf/include/*.h; do
            [[ -f "$_hdr" ]] || continue
            _hdr="bpf/include/$(basename "$_hdr")"
            stage_build_source "$_hdr" "$_hdr" "$_hdr" || true
        done
    else
        for _hdr in bpf/include/*.h; do
            [[ -e "$_hdr" || $PREFER_REMOTE_SOURCES -eq 1 ]] || continue
            stage_build_source "$_hdr" "$_hdr" "$_hdr" || true
        done
    fi
    if ! generate_xdp_map_abi "$_source_root"; then
        warn "Unable to derive the BPF map ABI manifest; XDP backend will be skipped."
        return 1
    fi
    local _handlers_ready=0
    if prepare_slot_handler_sources; then
        _handlers_ready=1
    fi

    if ! resolve_bpf_build_env || [[ -z "$ASM_INC" ]]; then
        warn "ASM headers not found; XDP backend will be skipped."
        return 1
    fi

    if ! compile_bpf_object "${_source_root}/${XDP_SRC}" "${BUILD_STAGING_DIR}/${XDP_OBJ}" "$_source_root"; then
        warn "Failed to compile ${XDP_SRC}; XDP backend will be skipped."
        return 1
    fi

    if [[ $_handlers_ready -eq 1 && -d "$_handlers_dir" ]] && command -v make &>/dev/null; then
        if ! bpf_header_exists "linux/bpf.h" "/usr/include" "$ASM_INC"; then
            warn "Slot handlers skipped: missing linux/bpf.h in /usr/include or ${ASM_INC}"
        elif ! bpf_header_exists "bpf/bpf_helpers.h" "/usr/include" "/usr/local/include"; then
            warn "Slot handlers skipped: missing bpf/bpf_helpers.h in /usr/include or /usr/local/include"
        else
            local handler_log
            handler_log=$(mktemp)
            if make -C "$_handlers_dir" -f Makefile --no-print-directory \
                    CLANG="clang" \
                    ASM_INC="$ASM_INC" \
                    ARCH_FLAGS="-D__TARGET_ARCH_${TARGET_ARCH} ${HOST_ARCH_FLAG}" \
                    >"$handler_log" 2>&1; then
                : # compiled handler objects remain in staging until install
            else
                step_error "Slot handler compilation failed; continuing with the XDP main program without handlers."
                warn_from_log_file "$handler_log" "handler build: "
                rm -f "$handler_log"
                rm -f "${_handlers_dir}"/*.o
                HANDLER_BUILD_FAILED=1
            fi
            rm -f "$handler_log"
        fi
    fi
    if [[ ! -s "${_handlers_dir}/minecraft_handler.o" ]]; then
        step_error "Required Minecraft protection profile failed to build."
        return 1
    fi
    return 0
}

compile_sock_state_program() {
    if ! command -v clang &>/dev/null; then
        warn "clang missing; sock_state tracker will be skipped."
        return 1
    fi

    if ! stage_build_source "$SOCK_STATE_SRC" "$SOCK_STATE_SRC" "$SOCK_STATE_SRC"; then
        warn "Unable to fetch ${SOCK_STATE_SRC}; sock_state tracker will be skipped."
        return 1
    fi

    if ! resolve_bpf_build_env || [[ -z "$ASM_INC" ]]; then
        return 1
    fi

    if ! compile_bpf_object \
            "${BUILD_STAGING_DIR}/${SOCK_STATE_SRC}" \
            "${BUILD_STAGING_DIR}/${SOCK_STATE_OBJ}" \
            "$BUILD_STAGING_DIR"; then
        warn "Failed to compile ${SOCK_STATE_SRC}; sock_state tracker will be skipped."
        return 1
    fi

    return 0
}

compile_bpf_objects_step() {
    step_begin "Compiling XDP and sock_state BPF objects" COMPILE
    local ok=1
    compile_xdp_program || ok=0
    compile_sock_state_program || true
    if [[ $ok -eq 1 ]]; then
        if [[ ${HANDLER_BUILD_FAILED:-0} -eq 1 ]]; then
            step_ok "XDP compiled; slot handlers unavailable"
        else
            step_ok
        fi
    else
        XDP_FALLBACK_REASON="BPF object compilation failed"
        step_warn "XDP unavailable, continuing with nftables backend"
    fi
}

restore_compiled_slot_handlers() {
    local staged_handlers=""

    [[ -n "${BUILD_STAGING_DIR:-}" && -d "$BUILD_STAGING_DIR" ]] || return 0
    staged_handlers="${BUILD_STAGING_DIR}/handlers"
    [[ -d "$staged_handlers" ]] || return 0

    if ! find "$staged_handlers" -maxdepth 1 -type f -name '*.o' | grep -q .; then
        return 0
    fi

    priv_mkdir "${INSTALL_DIR}/handlers"
    local _ho
    for _ho in "$staged_handlers"/*.o; do
        [[ -e "$_ho" ]] || continue
        place_file "$_ho" "${INSTALL_DIR}/handlers/$(basename "$_ho")"
    done
}

cleanup_build_artifacts_step() {
    local _f
    local _cleaned=()

    step_begin "Cleaning up build artifacts"
    for _f in "$XDP_OBJ" "$SOCK_STATE_OBJ"; do
        if [[ -f "$_f" ]]; then
            rm -f "$_f" && _cleaned+=("$_f")
        fi
    done

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        for _f in "$XDP_SRC"; do
            if [[ -f "$_f" ]]; then
                rm -f "$_f" && _cleaned+=("$_f")
            fi
        done
    fi

    if [[ -n "$BPF_HELPER_BOOTSTRAP" && "$BPF_HELPER_BOOTSTRAP" != "$BPF_HELPER_SRC" && -f "$BPF_HELPER_BOOTSTRAP" ]]; then
        rm -f "$BPF_HELPER_BOOTSTRAP" && _cleaned+=("$BPF_HELPER_BOOTSTRAP")
    fi

    if [[ -n "${BUILD_STAGING_DIR:-}" && -d "$BUILD_STAGING_DIR" ]]; then
        rm -rf "$BUILD_STAGING_DIR" && _cleaned+=("$BUILD_STAGING_DIR")
        BUILD_STAGING_DIR=""
    fi

    if [[ ${#_cleaned[@]} -gt 0 ]]; then
        step_ok "Removed: ${_cleaned[*]}"
    else
        step_ok "Nothing to remove"
    fi
}
