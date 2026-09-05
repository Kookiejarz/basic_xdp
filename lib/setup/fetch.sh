sha256_of_file() {
    python3 -c "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" "$1"
}

prepare_source_tree() {
    if [[ -n "${SOURCE_ROOT:-}" && -d "$SOURCE_ROOT" ]]; then
        local existing_path
        for existing_path in setup_xdp.sh config.toml auto_xdp bpf lib runtime; do
            [[ -e "${SOURCE_ROOT}/${existing_path}" ]] || return 1
        done
        return 0
    fi

    ensure_build_staging_dir || return 1
    SOURCE_ROOT="${BUILD_STAGING_DIR}/source"
    mkdir -p "$SOURCE_ROOT"

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        local archive extract_root
        if [[ "$AUTO_XDP_SOURCE_REF" =~ ^[0-9a-fA-F]{40}$ ]]; then
            SOURCE_REVISION="${AUTO_XDP_SOURCE_REF,,}"
        else
            local encoded_ref response
            encoded_ref=$("${PYTHON3_BIN:-python3}" -c \
                'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' \
                "$AUTO_XDP_SOURCE_REF")
            response=$(curl -fsSL \
                "https://api.github.com/repos/Kookiejarz/Auto_XDP/commits/${encoded_ref}") \
                || return 1
            SOURCE_REVISION=$(printf '%s' "$response" | "${PYTHON3_BIN:-python3}" -c '
import json, re, sys
value = json.load(sys.stdin).get("sha", "")
if not re.fullmatch(r"[0-9a-fA-F]{40}", value):
    raise SystemExit(1)
print(value.lower())
') || return 1
        fi
        archive="${BUILD_STAGING_DIR}/source.tar.gz"
        extract_root="${BUILD_STAGING_DIR}/archive"
        mkdir -p "$extract_root"
        info "Downloading one source archive for ${AUTO_XDP_SOURCE_REF}..."
        curl -fsSL \
            "https://codeload.github.com/Kookiejarz/Auto_XDP/tar.gz/${SOURCE_REVISION}" \
            -o "$archive" || return 1
        tar -xzf "$archive" -C "$extract_root" || return 1
        local unpacked=""
        unpacked=$(find "$extract_root" -mindepth 1 -maxdepth 1 -type d | head -n 1)
        [[ -n "$unpacked" ]] || return 1
        cp -R "$unpacked"/. "$SOURCE_ROOT"/ || return 1
    else
        local repo_root
        repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
        SOURCE_REVISION=$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)
        [[ "$SOURCE_REVISION" =~ ^[0-9a-fA-F]{40}$ ]] || SOURCE_REVISION="local"
        local path
        local required=(
            setup_xdp.sh axdp config.toml xdp_port_sync.py pkt_relay.py
            auto_xdp_bpf_helpers.py auto_xdp bpf handlers
            lib runtime
        )
        for path in "${required[@]}"; do
            [[ -e "${repo_root}/${path}" ]] || {
                warn "Source snapshot is missing required path: $path"
                return 1
            }
            cp -R "${repo_root}/${path}" "$SOURCE_ROOT"/ || return 1
        done
    fi

    for path in setup_xdp.sh config.toml auto_xdp bpf lib runtime; do
        [[ -e "${SOURCE_ROOT}/${path}" ]] || {
            warn "Source archive failed manifest validation: $path missing"
            return 1
        }
    done
    SOURCE_VERSION="${SOURCE_REVISION:0:12}"
    return 0
}

prepare_source_tree_step() {
    step_begin "Staging one complete source tree"
    if prepare_source_tree; then
        step_ok "${AUTO_XDP_SOURCE_REF}"
    else
        die "Could not stage a complete source tree. Current installation was not changed."
    fi
}

# Download URL into TARGET, escalating only when TARGET is a system path. The
# download itself runs unprivileged into a user temp, then place_file installs
# it (with sudo if needed).
_curl_to_target() {
    local url="$1" target="$2" tmp
    tmp=$(mktemp)
    _SETUP_TMPFILES+=("$tmp")
    if ! curl -fsSL "$url" -o "$tmp"; then
        rm -f "$tmp"
        return 1
    fi
    place_file "$tmp" "$target"
    rm -f "$tmp"
}

confirm_yes_no() {
    local prompt="$1"
    local no_tty_mode="${2:-deny}"
    local reply=""

    if [[ $FORCE -eq 1 ]]; then
        info "Force mode enabled; proceeding without confirmation."
        return 0
    fi

    if [[ -r /dev/tty ]] && exec 3<>/dev/tty 2>/dev/null; then
        printf "%s" "$prompt" >&3
        read -r reply <&3
        exec 3>&-
    elif [[ -t 0 ]]; then
        read -r -p "$prompt" reply
    else
        case "$no_tty_mode" in
            abort)
                return 2
                ;;
            *)
                return 1
                ;;
        esac
    fi

    case "$reply" in
        y|Y|yes|YES|Yes)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

prompt_pull_github() {
    local remote_name="$1"
    local local_hash="$2"
    local remote_hash="$3"

    warn "${remote_name} differs from GitHub."
    warn "  local : ${local_hash}"
    warn "  github: ${remote_hash}"

    if confirm_yes_no "Pull GitHub version for ${remote_name}? [y/N] "; then
        return 0
    fi

    warn "Keeping local ${remote_name}."
    return 1
}

_check_update_candidate_files() {
    local path
    local fixed_files=(
        "setup_xdp.sh"
        "axdp"
        "config.toml"
        "xdp_port_sync.py"
        "pkt_relay.py"
        "auto_xdp_bpf_helpers.py"
    )

    for path in "${fixed_files[@]}"; do
        [[ -f "$path" ]] && printf '%s\n' "$path"
    done

    for path in lib/setup/*.sh runtime/*.sh bpf/*.c bpf/include/*.h handlers/Makefile handlers/*.c handlers/*.h auto_xdp/*.py auto_xdp/admin/*.py auto_xdp/backends/*.py auto_xdp/bpf/*.py auto_xdp/default_config.toml auto_xdp/xdp_required_maps.txt auto_xdp/xdp_map_abi.txt; do
        [[ -f "$path" ]] && printf '%s\n' "$path"
    done | sort -u
}

check_github_updates_once() {
    [[ $CHECK_UPDATES -eq 1 ]] || return 0
    [[ $PREFER_REMOTE_SOURCES -eq 0 ]] || return 0

    local -a changed_files=()
    local -a changed_tmp_files=()
    local -a failed_files=()
    local rel tmp_file local_hash remote_hash

    info "Scanning local files for GitHub updates..."

    while IFS= read -r rel; do
        [[ -n "$rel" ]] || continue
        tmp_file=$(mktemp)
        _SETUP_TMPFILES+=("$tmp_file")
        if ! curl -fsSL "${RAW_URL}/${rel}" -o "$tmp_file"; then
            failed_files+=("$rel")
            continue
        fi

        local_hash=$(sha256_of_file "$rel")
        remote_hash=$(sha256_of_file "$tmp_file")
        if [[ "$local_hash" != "$remote_hash" ]]; then
            changed_files+=("$rel")
            changed_tmp_files+=("$tmp_file")
        fi
    done < <(_check_update_candidate_files)

    if [[ ${#failed_files[@]} -gt 0 ]]; then
        warn "Could not check these files against GitHub:"
        for rel in "${failed_files[@]}"; do
            warn "  ${rel}"
        done
    fi

    if [[ ${#changed_files[@]} -eq 0 ]]; then
        info "All checked local files match GitHub."
        CHECK_UPDATES=0
        return 0
    fi

    warn "The following local files differ from GitHub:"
    for rel in "${changed_files[@]}"; do
        warn "  ${rel}"
    done

    if confirm_yes_no "Pull GitHub versions for all listed files? [y/N] "; then
        local i
        for i in "${!changed_files[@]}"; do
            cp "${changed_tmp_files[$i]}" "${changed_files[$i]}"
            info "Updated local ${changed_files[$i]} from GitHub."
        done
    else
        warn "Keeping local files."
    fi

    CHECK_UPDATES=0
    return 0
}

fetch_local_or_remote() {
    local local_path="$1"
    local remote_name="$2"
    local target_path="$3"
    local tmp_file=""
    local local_hash=""
    local remote_hash=""

    if [[ -n "${SOURCE_ROOT:-}" && -f "${SOURCE_ROOT}/${local_path}" ]]; then
        if [[ "${SOURCE_ROOT}/${local_path}" != "$target_path" ]]; then
            place_file "${SOURCE_ROOT}/${local_path}" "$target_path"
        fi
        info "Using staged ${remote_name}"
        return 0
    fi

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        info "Installer is running from stdin; fetching ${remote_name} from GitHub..."
        _curl_to_target "${RAW_URL}/${remote_name}" "$target_path" || return 1
        return 0
    fi

    if [[ -f "$local_path" ]]; then
        if [[ $CHECK_UPDATES -eq 1 ]]; then
            tmp_file=$(mktemp)
            info "Checking GitHub version of ${remote_name}..."
            if ! curl -fsSL "${RAW_URL}/${remote_name}" -o "$tmp_file"; then
                warn "Could not fetch ${remote_name} from GitHub for comparison; keeping local copy."
                rm -f "$tmp_file"
                if [[ "$local_path" != "$target_path" ]]; then
                    place_file "$local_path" "$target_path"
                fi
                return 0
            fi

            local_hash=$(sha256_of_file "$local_path")
            remote_hash=$(sha256_of_file "$tmp_file")

            if [[ "$local_hash" == "$remote_hash" ]]; then
                info "Local ${remote_name} matches GitHub."
                rm -f "$tmp_file"
                if [[ "$local_path" != "$target_path" ]]; then
                    place_file "$local_path" "$target_path"
                fi
                return 0
            fi

            if prompt_pull_github "$remote_name" "$local_hash" "$remote_hash"; then
                cp "$tmp_file" "$local_path"
                info "Updated local ${remote_name} from GitHub."
            else
                info "Keeping local ${remote_name}."
            fi

            rm -f "$tmp_file"
        fi

        if [[ "$local_path" != "$target_path" ]]; then
            place_file "$local_path" "$target_path"
        fi
        info "Using local ${remote_name}"
        return 0
    fi

    if [[ $CHECK_UPDATES -eq 1 && -f "$target_path" ]]; then
        tmp_file=$(mktemp)
        info "Checking GitHub version of ${remote_name}..."
        if ! curl -fsSL "${RAW_URL}/${remote_name}" -o "$tmp_file"; then
            warn "Could not fetch ${remote_name} from GitHub; keeping installed copy."
            rm -f "$tmp_file"
            return 0
        fi
        local_hash=$(sha256_of_file "$target_path")
        remote_hash=$(sha256_of_file "$tmp_file")
        if [[ "$local_hash" == "$remote_hash" ]]; then
            info "Installed ${remote_name} matches GitHub."
            rm -f "$tmp_file"
            return 0
        fi
        if prompt_pull_github "$remote_name" "$local_hash" "$remote_hash"; then
            place_file "$tmp_file" "$target_path"
            info "Updated ${remote_name}."
        else
            info "Keeping installed ${remote_name}."
        fi
        rm -f "$tmp_file"
        return 0
    fi

    info "Fetching ${remote_name} from GitHub..."
    _curl_to_target "${RAW_URL}/${remote_name}" "$target_path"
}
