#!/bin/bash
# =============================================================
# setup_xdp.sh — One-click compilation / loading of XDP firewall + port-sync daemon
# Usage: sudo bash setup_xdp.sh [interface]
#        sudo bash setup_xdp.sh eth0
#        If no interface is given, the default-route interface is detected automatically.
# =============================================================
set -euo pipefail

# ── Coloured output ───────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }

# ── Spinner ───────────────────────────────────────────────────────────
spinner() {
    local pid=$1 delay=0.1 spinstr='|/-\\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

run_with_spinner() {
    local msg="$1"; shift
    info "$msg"
    "$@" > /tmp/xdp_install.log 2>&1 &
    local pid=$!
    spinner $pid
    wait $pid
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        echo -e "${RED}[FAIL]${NC}"
        die "Command failed: $*\nSee /tmp/xdp_install.log for details."
    fi
    echo -e "${GREEN}[DONE]${NC}"
}

# ── Settings ──────────────────────────────────────────────────────────
IFACE="${1:-}"
XDP_SRC="xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SYNC_SCRIPT="/usr/local/bin/xdp-sync-ports.py"
SERVICE_NAME="xdp-port-sync"
SYNC_INTERVAL=30
RAW_URL="https://raw.githubusercontent.com/Kookiejarz/basic_xdp/main"

# ── 1. Root check ─────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Please run this script with sudo."

# ── 2. Interface detection ────────────────────────────────────────────
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    [[ -n "$IFACE" ]] || die "Cannot detect default interface. Specify manually: sudo bash $0 eth0"
    info "Detected interface: $IFACE"
fi
ip link show "$IFACE" &>/dev/null || die "Interface $IFACE does not exist."

# ── 3. Dependency check & install ────────────────────────────────────
info "Checking dependencies..."
MISSING=()
for cmd in clang bpftool python3; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
[[ -d /usr/include/linux ]] || MISSING+=("linux-headers")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing: ${MISSING[*]} — installing..."
    export DEBIAN_FRONTEND=noninteractive
    APT_OPTS="-y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

    run_with_spinner "Updating package lists..." \
        apt-get update -qq

    run_with_spinner "Installing build tools (clang, llvm, libbpf-dev ...)..." \
        apt-get install $APT_OPTS clang llvm libbpf-dev build-essential iproute2 \
                        python3 python3-pip gcc-multilib

    run_with_spinner "Installing bpftool & kernel headers..." \
        apt-get install $APT_OPTS linux-tools-common linux-tools-generic \
                        "linux-tools-$(uname -r)" "linux-headers-$(uname -r)"

    # Ensure pip is available for the psutil install below
    run_with_spinner "Installing python3-pip..." \
        apt-get install $APT_OPTS python3-pip

    if ! command -v bpftool &>/dev/null; then
        REAL_BPFTOOL=$(find /usr/lib/linux-tools -name bpftool -type f -executable \
                       -print -quit 2>/dev/null || true)
        if [[ -n "$REAL_BPFTOOL" ]]; then
            ln -sf "$REAL_BPFTOOL" /usr/local/bin/bpftool
            ok "Symlinked bpftool from $REAL_BPFTOOL"
        fi
    fi
    unset DEBIAN_FRONTEND
fi

# Always ensure psutil is available.
# Prefer apt (respects the system-managed Python env); fall back to pip only if needed.
if ! python3 -c "import psutil" 2>/dev/null; then
    apt-get install -y -qq python3-psutil 2>/dev/null \
        || python3 -m pip install --quiet --break-system-packages psutil
fi

command -v bpftool &>/dev/null || die "bpftool not found. Run: apt install linux-tools-generic"
ok "All dependencies satisfied."

# ── 4. Fetch source ───────────────────────────────────────────────────
info "Fetching $XDP_SRC from GitHub..."
curl -fsSL "${RAW_URL}/${XDP_SRC}" -o "$XDP_SRC" || die "Failed to download $XDP_SRC"
ok "Downloaded $XDP_SRC"

# ── 5. Compile XDP program ────────────────────────────────────────────
info "Compiling $XDP_SRC..."
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ASM_INC="/usr/include/x86_64-linux-gnu";   TARGET_ARCH="x86"   ;;
    aarch64) ASM_INC="/usr/include/aarch64-linux-gnu";   TARGET_ARCH="arm64" ;;
    armv7*)  ASM_INC="/usr/include/arm-linux-gnueabihf"; TARGET_ARCH="arm"   ;;
    *)       ASM_INC="/usr/include/${ARCH}-linux-gnu";   TARGET_ARCH="$ARCH" ;;
esac

if [[ ! -d "$ASM_INC" ]]; then
    ASM_INC="/usr/src/linux-headers-$(uname -r)/arch/${TARGET_ARCH}/include/generated"
fi
if [[ ! -d "$ASM_INC" && -d "/usr/include/asm" ]]; then
    ASM_INC="/usr/include"
fi
if [[ ! -d "$ASM_INC" ]]; then
    ASM_INC=$(find /usr/src -name "asm" -type d -print -quit \
              | xargs dirname 2>/dev/null || echo "")
fi
[[ -d "$ASM_INC" ]] || die "ASM headers not found. Try: apt install gcc-multilib"
info "Using ASM headers: $ASM_INC"

clang -O3 -g \
    -target bpf \
    -mcpu=v3 \
    "-D__TARGET_ARCH_${TARGET_ARCH}" \
    -fno-stack-protector \
    -Wall -Wno-unused-value \
    -I/usr/include \
    -I"$ASM_INC" \
    -I/usr/include/bpf \
    -c "$XDP_SRC" -o "$XDP_OBJ"
ok "Compiled → $XDP_OBJ"

# ── 6. Mount bpffs ────────────────────────────────────────────────────
if ! mount | grep -q 'type bpf'; then
    info "Mounting bpffs on /sys/fs/bpf..."
    mount -t bpf bpf /sys/fs/bpf || die "bpffs mount failed."
fi

# ── 7. Remove old XDP program (if any) ───────────────────────────────
if ip link show "$IFACE" | grep -q "xdp"; then
    warn "Existing XDP program detected — removing..."
    ip link set dev "$IFACE" xdp off
fi
if [[ -d "$BPF_PIN_DIR" ]]; then
    warn "Removing old pin directory $BPF_PIN_DIR..."
    rm -rf "$BPF_PIN_DIR"
fi
mkdir -p "$BPF_PIN_DIR"

# ── 8. Load XDP program ───────────────────────────────────────────────
info "Loading XDP program onto $IFACE..."
bpftool prog load "$XDP_OBJ" "$BPF_PIN_DIR/prog"

PROG_ID=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" \
          | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
info "Loaded program ID: $PROG_ID"

# Pin all maps used by the program
bpftool -j prog show id "$PROG_ID" | python3 -c "
import json, subprocess, sys, os
prog    = json.load(sys.stdin)
pin_dir = os.environ['BPF_PIN_DIR']
for map_id in prog.get('map_ids', []):
    info     = json.loads(subprocess.check_output(['bpftool','-j','map','show','id',str(map_id)]))
    name     = info.get('name', f'map_{map_id}')
    pin_path = f'{pin_dir}/{name}'
    subprocess.check_call(['bpftool','map','pin','id',str(map_id), pin_path])
    print(f'  pinned [{name}] → {pin_path}')
" || die "Map pinning failed."

# Attach — prefer native mode, fall back to generic
if ip link set dev "$IFACE" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
    ok "XDP attached in native mode on $IFACE"
else
    warn "Native mode unsupported — falling back to generic mode..."
    ip link set dev "$IFACE" xdp generic pinned "$BPF_PIN_DIR/prog"
    ok "XDP attached in generic mode on $IFACE"
fi
ip link show "$IFACE" | grep -q "xdp" || die "XDP failed to attach to $IFACE"

info "Pinned BPF maps:"
ls "$BPF_PIN_DIR/"
echo ""

# ── 9. Deploy sync daemon ─────────────────────────────────────────────
info "Deploying daemon → $SYNC_SCRIPT..."
cat > "$SYNC_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""XDP Port Whitelist Auto-Sync Daemon

Port discovery  : psutil  (reads /proc directly, no subprocesses)
Map operations  : bpf(2) syscall via ctypes  (no bpftool)
Event trigger   : Linux Netlink Process Connector (EXEC/EXIT)
Fallback        : periodic poll every --interval seconds (default 30)
"""
from __future__ import annotations
import argparse, ctypes, ctypes.util, logging, os, platform
import select, socket, struct, sys, time
from dataclasses import dataclass, field

try:
    import psutil
except ImportError:
    sys.exit("psutil not installed. Run: pip3 install psutil")

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"

# Always-whitelisted ports (e.g. SSH emergency fallback)
TCP_PERMANENT: dict[int, str] = {22: "SSH-fallback"}
UDP_PERMANENT: dict[int, str] = {}

# Wait this long after an EXEC/EXIT event before scanning,
# giving the new process time to call bind().
DEBOUNCE_S = 0.3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# psutil 6.0 renamed net_connections() → connections()
_net_connections = getattr(psutil, "connections", psutil.net_connections)

# ── BPF syscall layer ─────────────────────────────────────────────────
_libc   = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_NR_BPF: int = {
    "x86_64":  321,
    "aarch64": 280,
    "armv7l":  386,
    "armv6l":  386,
}.get(platform.machine(), 321)

_BPF_MAP_LOOKUP_ELEM = 1
_BPF_MAP_UPDATE_ELEM = 2
_BPF_OBJ_GET         = 7


def _bpf(cmd: int, attr: ctypes.Array) -> int:
    ret = _libc.syscall(_NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def _obj_get(path: str) -> int:
    """Open a pinned BPF object; return its fd."""
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr   = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return _bpf(_BPF_OBJ_GET, attr)


class BpfArrayMap:
    """Pinned BPF ARRAY map (key = __u32 port, value = __u32 0/1).

    Write-through in-memory cache — sync_once() only issues syscalls for
    ports that actually changed.  Cache starts empty; the first sync_once()
    call populates it.  Any stale entries from a previous daemon run are
    cleaned up on the first sync cycle.

    bpf_attr layout for MAP_LOOKUP / MAP_UPDATE:
      offset  0 : map_fd  (u32)
      offset  4 : pad     (4 bytes)
      offset  8 : key ptr (u64)
      offset 16 : val ptr (u64)
      offset 24 : flags   (u64)
    """

    def __init__(self, path: str) -> None:
        self.path  = path
        self.fd    = _obj_get(path)
        self._cache: set[int] = set()

        # Pre-allocate reusable ctypes buffers (avoids per-call allocation)
        self._key  = ctypes.create_string_buffer(4)
        self._val  = ctypes.create_string_buffer(4)
        self._attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._attr, 0, self.fd, k_ptr, v_ptr, 0)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _update(self, port: int, val: int) -> None:
        struct.pack_into("=I", self._key, 0, port)
        struct.pack_into("=I", self._val, 0, val)
        _bpf(_BPF_MAP_UPDATE_ELEM, self._attr)  # flags=0 → BPF_ANY

    def active_ports(self) -> set[int]:
        return set(self._cache)

    def set(self, port: int, val: int, dry_run: bool = False) -> bool:
        """Write val (0 or 1) for port; update the cache on success."""
        if dry_run:
            log.info("[DRY] %s port %d → %d", self.path, port, val)
            self._cache.add(port) if val else self._cache.discard(port)
            return True
        try:
            self._update(port, val)
            self._cache.add(port) if val else self._cache.discard(port)
            return True
        except OSError as exc:
            log.warning("BPF update failed port=%d: %s", port, exc)
            return False


# ── Port discovery ────────────────────────────────────────────────────
@dataclass
class PortState:
    tcp: set = field(default_factory=set)
    udp: set = field(default_factory=set)


def get_listening_ports() -> PortState:
    """Read listening TCP/UDP ports via psutil (no subprocess)."""
    state = PortState()
    for conn in _net_connections(kind="inet"):
        if not (conn.laddr and conn.laddr.port):
            continue
        if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
            state.tcp.add(conn.laddr.port)
        elif conn.type == socket.SOCK_DGRAM:
            state.udp.add(conn.laddr.port)
    return state


# ── Sync ──────────────────────────────────────────────────────────────
def sync_once(tcp_map: BpfArrayMap, udp_map: BpfArrayMap, dry_run: bool) -> None:
    current    = get_listening_ports()
    tcp_target = current.tcp | set(TCP_PERMANENT)
    udp_target = current.udp | set(UDP_PERMANENT)
    changed    = False

    for port in sorted(tcp_target - tcp_map.active_ports()):
        tag = f" [{TCP_PERMANENT[port]}]" if port in TCP_PERMANENT else ""
        if tcp_map.set(port, 1, dry_run):
            log.info("TCP +%d%s", port, tag)
            changed = True

    for port in sorted(tcp_map.active_ports() - tcp_target - set(TCP_PERMANENT)):
        if tcp_map.set(port, 0, dry_run):
            log.info("TCP -%d  (stopped)", port)
            changed = True

    for port in sorted(udp_target - udp_map.active_ports()):
        tag = f" [{UDP_PERMANENT[port]}]" if port in UDP_PERMANENT else ""
        if udp_map.set(port, 1, dry_run):
            log.info("UDP +%d%s", port, tag)
            changed = True

    for port in sorted(udp_map.active_ports() - udp_target - set(UDP_PERMANENT)):
        if udp_map.set(port, 0, dry_run):
            log.info("UDP -%d  (stopped)", port)
            changed = True

    if not changed:
        log.debug("Whitelist up-to-date.")


# ── Netlink Process Connector ─────────────────────────────────────────
_NETLINK_CONNECTOR    = 11
_CN_IDX_PROC          = 1
_NLMSG_HDRLEN         = 16
_CN_MSG_HDRLEN        = 20   # idx(4)+val(4)+seq(4)+ack(4)+len(2)+flags(2)
_NLMSG_MIN_TYPE       = 0x10
_PROC_CN_MCAST_LISTEN = 1
_PROC_EVENT_EXEC      = 0x00000002
_PROC_EVENT_EXIT      = 0x80000000


def _make_subscribe_msg(pid: int) -> bytes:
    op  = struct.pack("I", _PROC_CN_MCAST_LISTEN)
    cn  = struct.pack("IIIIHH", _CN_IDX_PROC, 1, 0, 0, len(op), 0) + op
    hdr = struct.pack("IHHII", _NLMSG_HDRLEN + len(cn), _NLMSG_MIN_TYPE, 0, 0, pid)
    return hdr + cn


def open_proc_connector():
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_CONNECTOR)
        sock.bind((os.getpid(), _CN_IDX_PROC))
        sock.send(_make_subscribe_msg(os.getpid()))
        log.info("Netlink proc connector active — event-driven mode.")
        return sock
    except OSError as exc:
        log.warning("Netlink unavailable (%s); falling back to poll-only mode.", exc)
        return None


def drain_proc_events(sock: socket.socket) -> bool:
    """Drain buffered netlink messages; return True if any EXEC/EXIT seen."""
    triggered = False
    while True:
        try:
            rdy, _, _ = select.select([sock], [], [], 0)
            if not rdy:
                break
            data = sock.recv(4096)
        except OSError:
            break
        offset = 0
        while offset + _NLMSG_HDRLEN <= len(data):
            nl_len = struct.unpack_from("I", data, offset)[0]
            if nl_len < _NLMSG_HDRLEN:
                break
            cn_off = offset + _NLMSG_HDRLEN
            if cn_off + _CN_MSG_HDRLEN <= offset + nl_len:
                idx     = struct.unpack_from("I", data, cn_off)[0]
                cn_data = cn_off + _CN_MSG_HDRLEN
                if idx == _CN_IDX_PROC and cn_data + 4 <= offset + nl_len:
                    what = struct.unpack_from("I", data, cn_data)[0]
                    if what in (_PROC_EVENT_EXEC, _PROC_EVENT_EXIT):
                        triggered = True
            offset += (nl_len + 3) & ~3  # NLMSG_ALIGN
    return triggered


# ── Watch loop ────────────────────────────────────────────────────────
def watch(interval: int, dry_run: bool) -> None:
    tcp_map = BpfArrayMap(TCP_MAP_PATH)
    udp_map = BpfArrayMap(UDP_MAP_PATH)
    nl      = open_proc_connector()

    sync_once(tcp_map, udp_map, dry_run)
    last_sync_t  = time.monotonic()
    last_event_t = 0.0

    try:
        while True:
            now       = time.monotonic()
            poll_due  = last_sync_t + interval
            deb_due   = (last_event_t + DEBOUNCE_S) if last_event_t else float("inf")
            sleep_for = max(0.05, min(poll_due, deb_due) - now)

            try:
                if nl and not last_event_t:
                    # Do NOT select while already debouncing — prevents spinning
                    # when EXEC/EXIT events arrive continuously (cron, logrotate).
                    rdy, _, _ = select.select([nl], [], [], sleep_for)
                    if rdy and drain_proc_events(nl):
                        log.debug("Proc event — debounce armed.")
                        last_event_t = time.monotonic()
                else:
                    time.sleep(sleep_for)
            except OSError as exc:
                log.warning("Netlink error (%s); switching to poll-only mode.", exc)
                if nl:
                    nl.close()
                nl = None
                continue

            now            = time.monotonic()
            debounce_fired = bool(last_event_t) and (now - last_event_t >= DEBOUNCE_S)
            fallback_fired = (now - last_sync_t >= interval)

            if debounce_fired or fallback_fired:
                # Flush events that piled up during debounce/poll window
                # to prevent self-triggering on our own psutil /proc reads.
                if nl:
                    drain_proc_events(nl)
                log.debug("Sync triggered by %s.", "event" if debounce_fired else "poll")
                try:
                    sync_once(tcp_map, udp_map, dry_run)
                except Exception as exc:
                    log.error("Sync error: %s", exc)
                last_sync_t  = time.monotonic()
                last_event_t = 0.0

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        tcp_map.close()
        udp_map.close()


# ── Entry point ───────────────────────────────────────────────────────
def main() -> None:
    p = argparse.ArgumentParser(description="XDP port-whitelist sync daemon")
    p.add_argument("--watch",    action="store_true",
                   help="Run as a daemon (event-driven + fallback poll)")
    p.add_argument("--interval", type=int, default=30,
                   help="Fallback poll interval in seconds (default: 30)")
    p.add_argument("--dry-run",  action="store_true",
                   help="Print operations without executing them")
    args = p.parse_args()

    if args.watch:
        watch(args.interval, args.dry_run)
    else:
        tcp_map = BpfArrayMap(TCP_MAP_PATH)
        udp_map = BpfArrayMap(UDP_MAP_PATH)
        try:
            sync_once(tcp_map, udp_map, args.dry_run)
            log.info("Sync completed.")
        finally:
            tcp_map.close()
            udp_map.close()


if __name__ == "__main__":
    main()
PYEOF
chmod +x "$SYNC_SCRIPT"
ok "Daemon deployed: $SYNC_SCRIPT"

# ── 10. Enable systemd service ────────────────────────────────────────
info "Creating systemd service: $SERVICE_NAME..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=XDP BPF Port Whitelist Auto-Sync
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 ${SYNC_SCRIPT} --watch --interval ${SYNC_INTERVAL}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"
ok "Service enabled: $SERVICE_NAME"

# ── 11. Initial sync ──────────────────────────────────────────────────
info "Running initial sync..."
python3 "$SYNC_SCRIPT"

# ── 12. Summary ───────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment Complete!                  ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Interface : $IFACE"
echo "  BPF maps  : $BPF_PIN_DIR/"
echo "  Service   : systemctl status $SERVICE_NAME"
echo ""
echo "  Whitelisted TCP ports:"
bpftool -j map dump pinned "${BPF_PIN_DIR}/tcp_whitelist" 2>/dev/null \
  | python3 -c "
import json, sys
try:
    for e in json.load(sys.stdin):
        if not isinstance(e, dict):
            continue
        v = e.get('value', 0)
        val = v if isinstance(v, int) else \
              (int(v[0], 16) if isinstance(v, list) and v else 0)
        if not val:
            continue
        k = e.get('key')
        if isinstance(k, int):
            print(f'    → TCP {k}')
        elif isinstance(k, list) and len(k) >= 2:
            b0 = int(k[0], 16) if isinstance(k[0], str) else k[0]
            b1 = int(k[1], 16) if isinstance(k[1], str) else k[1]
            print(f'    → TCP {b0 | (b1 << 8)}')
except Exception:
    pass
" || echo "    (none)"
echo ""
echo "  Uninstall : ip link set dev $IFACE xdp off"
echo ""
