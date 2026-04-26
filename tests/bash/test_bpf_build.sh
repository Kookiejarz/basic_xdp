#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]:-}")/../.." && pwd)
cd "$REPO_ROOT"

if ! command -v clang >/dev/null 2>&1 || ! command -v bpftool >/dev/null 2>&1; then
    echo "skip: clang or bpftool missing"
    exit 0
fi

source "$REPO_ROOT/setup_xdp.sh"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

INSTALL_DIR="$tmpdir/install"
XDP_OBJ_INSTALLED="$INSTALL_DIR/xdp_firewall.o"
TC_OBJ_INSTALLED="$INSTALL_DIR/tc_flow_track.o"
PREFER_REMOTE_SOURCES=0
CHECK_UPDATES=0

fetch_local_or_remote() {
    return 0
}

set +e
compile_xdp_program
status=$?
set -e
if [[ $status -ne 0 ]]; then
    echo "compile_xdp_program failed"
    exit 1
fi

[[ -s "$XDP_OBJ_INSTALLED" ]] || {
    echo "missing compiled XDP object: $XDP_OBJ_INSTALLED"
    exit 1
}

[[ -s "$TC_OBJ_INSTALLED" ]] || {
    echo "missing compiled tc object: $TC_OBJ_INSTALLED"
    exit 1
}

resolve_bpf_build_env || {
    echo "failed to resolve native BPF build environment"
    exit 1
}

make -C handlers clean >/dev/null 2>&1 || true
make -C handlers -f Makefile --no-print-directory \
    CLANG="clang" \
    ASM_INC="$ASM_INC" \
    ARCH_FLAGS="-D__TARGET_ARCH_${TARGET_ARCH} ${HOST_ARCH_FLAG}"

for handler_obj in handlers/gre_handler.o handlers/esp_handler.o handlers/sctp_handler.o; do
    [[ -s "$handler_obj" ]] || {
        echo "missing compiled handler object: $handler_obj"
        exit 1
    }
done

echo "native distro build succeeded"
