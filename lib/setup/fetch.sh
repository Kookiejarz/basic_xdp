sha256_of_file() {
    python3 -c "import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" "$1"
}

confirm_yes_no() {
    local prompt="$1"
    local no_tty_mode="${2:-deny}"
    local reply=""

    if [[ $FORCE -eq 1 ]]; then
        info "Force mode enabled; proceeding without confirmation."
        return 0
    fi

    if [[ -r /dev/tty ]]; then
        printf "%s" "$prompt" > /dev/tty
        read -r reply < /dev/tty
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

fetch_local_or_remote() {
    local local_path="$1"
    local remote_name="$2"
    local target_path="$3"
    local tmp_file=""
    local local_hash=""
    local remote_hash=""

    if [[ $PREFER_REMOTE_SOURCES -eq 1 ]]; then
        info "Installer is running from stdin; fetching ${remote_name} from GitHub..."
        curl -fsSL "${RAW_URL}/${remote_name}" -o "$target_path"
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
                    cp "$local_path" "$target_path"
                fi
                return 0
            fi

            local_hash=$(sha256_of_file "$local_path")
            remote_hash=$(sha256_of_file "$tmp_file")

            if [[ "$local_hash" == "$remote_hash" ]]; then
                info "Local ${remote_name} matches GitHub."
                rm -f "$tmp_file"
                if [[ "$local_path" != "$target_path" ]]; then
                    cp "$local_path" "$target_path"
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
            cp "$local_path" "$target_path"
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
            cp "$tmp_file" "$target_path"
            info "Updated ${remote_name}."
        else
            info "Keeping installed ${remote_name}."
        fi
        rm -f "$tmp_file"
        return 0
    fi

    info "Fetching ${remote_name} from GitHub..."
    curl -fsSL "${RAW_URL}/${remote_name}" -o "$target_path"
}
