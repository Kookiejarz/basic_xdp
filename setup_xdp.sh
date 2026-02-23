#!/bin/bash
# =============================================================
# setup_xdp.sh — One-click compilation / loading of XDP firewall + startup port synchronization daemon
# Usage: sudo bash setup_xdp.sh [interface]
#       sudo bash setup_xdp.sh eth0
#       If no parameters are provided, the default route network interface will be detected automatically.
# =============================================================
set -euo pipefail

# ── Colorful output ─────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()   { echo -e "${RED}[ERR ]${NC}  $*" >&2; exit 1; }

# ── Settings ─────────────────────────────────────────────────────
IFACE="${1:-}"
XDP_SRC="xdp_firewall.c"
XDP_OBJ="xdp_firewall.o"
export BPF_PIN_DIR="/sys/fs/bpf/xdp_fw"
SYNC_SCRIPT="/usr/local/bin/xdp-sync-ports.py"
SERVICE_NAME="xdp-port-sync"
SYNC_INTERVAL=5
RAW_URL="https://raw.githubusercontent.com/Kookiejarz/basic_xdp/main"

# ── 1. Check root ──────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "Please run this script with sudo."

# ── 2. Interface Detection ───────────────────────────────────────────
if [[ -z "$IFACE" ]]; then
    IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
    [[ -n "$IFACE" ]] || die "Unable to automatically detect the default network adapter. Please manually specify it: sudo bash $0 eth0"
    info "Network Interface detected: $IFACE"
fi
ip link show "$IFACE" &>/dev/null || die "Interface $IFACE does not exist"

# ── 3. Check and install dependencies ─────────────────────────────────────────
info "Cheching dependencies..."
MISSING=()
for cmd in clang llc bpftool python3; do
    command -v "$cmd" &>/dev/null || MISSING+=("$cmd")
done
[[ -d /usr/include/linux ]] || MISSING+=("linux-headers")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Missing dependency: ${MISSING[*]}, Installing..."
    apt-get update -qq

    apt-get install -y clang llvm libbpf-dev build-essential iproute2 python3 gcc-multilib || true

    info "Installing specific kernel tools..."
    apt-get install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r) linux-headers-$(uname -r) || true

    if ! command -v bpftool &>/dev/null; then
        REAL_BPFTOOL=$(find /usr/lib/linux-tools -name bpftool -type f -executable -print -quit 2>/dev/null || true)
        if [[ -n "$REAL_BPFTOOL" ]]; then
            ln -sf "$REAL_BPFTOOL" /usr/local/bin/bpftool
            ok "Found bpftool at $REAL_BPFTOOL and created symlink."
        fi
    fi

    # 4. Last Check
    command -v bpftool &>/dev/null || die "bpftool installation failed. Please run: apt install linux-tools-generic"
fi
ok "Dependency check completed"

# ── 4. Getting Source Code ───────────────────────────────────────────
if [[ ! -f "$XDP_SRC" ]]; then
    echo -e "\033[0;36m[INFO]\033[0m Retrieving core source code from GitHub..."
    curl -fsSL "${RAW_URL}/${XDP_SRC}" -o "$XDP_SRC" || { 
        echo "Download failed"; exit 1; 
    }
fi

# ── 5. Compile XDP ──────────────────────────────────────────
info "Compiling $XDP_SRC ..."
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ASM_INC="/usr/include/x86_64-linux-gnu" ;;
    aarch64) ASM_INC="/usr/include/aarch64-linux-gnu" ;;
    armv7*)  ASM_INC="/usr/include/arm-linux-gnueabihf" ;;
    *)       ASM_INC="/usr/include/${ARCH}-linux-gnu" ;;
esac
if [[ ! -d "$ASM_INC" ]]; then
    ASM_INC="/usr/src/linux-headers-$(uname -r)/arch/x86/include/generated"
elif [[ -d "/usr/include/asm" ]]; then
    ASM_INC="/usr/include"
else
    ASM_INC=$(find /usr/src -name "asm" -type d -print -quit | xargs dirname 2>/dev/null || echo "")
fi
[[ -d "$ASM_INC" ]] || die "The asm header file directory cannot be found: apt install gcc-multilib"
info "Using the ASM header file directory: $ASM_INC"

clang -O2 -g \
    -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include \
    -I"$ASM_INC" \
    -I/usr/include/bpf \
    -c "$XDP_SRC" -o "$XDP_OBJ"
ok "Compilation successful → $XDP_OBJ"

# ── 6. Ensure BPFFs are mounted ────────────────────────────────────
if ! mount | grep -q 'type bpf'; then
    info "mounting bpffs to /sys/fs/bpf ..."
    mount -t bpf bpf /sys/fs/bpf || die "bpffs mount failed"
fi

# ── 7. Uninstall the old XDP program and rebuild the directory. ──────────────────────────────
if ip link show "$IFACE" | grep -q "xdp"; then
    warn "An XDP program has been detected. Uninstall it first...."
    ip link set dev "$IFACE" xdp off
fi
if [[ -d "$BPF_PIN_DIR" ]]; then
    warn "Cleaning $BPF_PIN_DIR ..."
    rm -rf "$BPF_PIN_DIR"
fi
mkdir -p "$BPF_PIN_DIR"

# ── 8. Loading XDP  ──────────────────────────────────────────
info "Loading XDP to $IFACE ..."

bpftool prog load "$XDP_OBJ" "$BPF_PIN_DIR/prog"

# Locate the ID of the newly loaded program, then pin all the maps it uses.
PROG_ID=$(bpftool -j prog show pinned "$BPF_PIN_DIR/prog" | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")
info "Program ID: $PROG_ID"


bpftool -j prog show id "$PROG_ID" | python3 -c "
import json, sys, subprocess, os
prog = json.load(sys.stdin)
pin_dir = os.environ['BPF_PIN_DIR']
for map_id in prog.get('map_ids', []):
    info = json.loads(subprocess.check_output(['bpftool','-j','map','show','id',str(map_id)]))
    name = info.get('name', f'map_{map_id}')
    pin_path = f'{pin_dir}/{name}'
    subprocess.check_call(['bpftool','map','pin','id',str(map_id), pin_path])
    print(f'  pinned map [{name}] → {pin_path}')
" || die "map pin faild"

# attach to interface, try native mode first, fallback to generic if it fails
if ip link set dev "$IFACE" xdp pinned "$BPF_PIN_DIR/prog" 2>/dev/null; then
    ok "XDP using native mode $IFACE"
else
    warn "does not support native mode, falling back to generic mode..."
    ip link set dev "$IFACE" xdp generic pinned "$BPF_PIN_DIR/prog"
    ok "XDP using generic mode $IFACE"
fi
ip link show "$IFACE" | grep -q "xdp" || die "XDP program failed to attach to $IFACE"

info "BPF maps is pinned to :"
ls "$BPF_PIN_DIR/"
echo ""

# ── 8. Deploy Daemon ───────────────────────────────────
info "Deploying Daemon → $SYNC_SCRIPT ..."
cat > "$SYNC_SCRIPT" << 'PYEOF'
#!/usr/bin/env python3
"""XDP Port Whitelist Auto-Sync Daemon"""
import subprocess, argparse, time, logging, sys, json
from dataclasses import dataclass, field

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"

# In case you have some critical services that must always be allowed, even if their processes are not currently listening (e.g. for port knocking), you can add them here:
TCP_PERMANENT = {22: "SSH-fallback"}
UDP_PERMANENT = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

@dataclass
class PortState:
    tcp: set = field(default_factory=set)
    udp: set = field(default_factory=set)

def get_listening_ports() -> PortState:
    state = PortState()
    try:
        out = subprocess.check_output(
            ["ss", "-lnH", "-t", "-u"], text=True, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        log.error("The `ss` command is not found. Please install iproute2.")
        sys.exit(1)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        try:
            port = int(local.rsplit(":", 1)[-1])
        except ValueError:
            continue
        if proto == "tcp":
            state.tcp.add(port)
        elif proto == "udp":
            state.udp.add(port)
    return state

def port_to_key(port: int):
    hi = (port >> 8) & 0xFF
    lo = port & 0xFF
    return [f"0x{hi:02x}", f"0x{lo:02x}"]

def map_update(map_path, port, dry_run):
    import struct
    hi = (port >> 8) & 0xFF
    lo = port & 0xFF
    key_hex = f"{hi:02x}{lo:02x}"
    
    cmd = ["bpftool", "map", "update", "pinned", map_path,
           "key", f"0x{hi:02x}", f"0x{lo:02x}", 
           "value", "0x01", "0x00", "0x00", "0x00"]

    if dry_run:
        log.info(f"[DRY] {' '.join(cmd)}")
        return True
    try:
        subprocess.check_call(cmd, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        log.warning(f"update failed port={port}: {e}")
        return False

def map_delete(map_path, port, dry_run):
    cmd = ["bpftool", "map", "delete", "pinned", map_path,
           "key", *port_to_key(port)]
    if dry_run:
        log.info(f"[DRY] {' '.join(cmd)}")
        return True
    try:
        subprocess.check_call(cmd, stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        return False

def map_dump_ports(map_path) -> set:
    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", map_path],
            text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return set()
    try:
        entries = json.loads(out)
        ports = set()
        for e in entries:
            k = e.get("key")
            if isinstance(k, list) and len(k) == 2:
                hi = int(k[0], 16)
                lo = int(k[1], 16)
                ports.add((hi << 8) | lo)
        return ports
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        return set()

def sync_once(dry_run: bool):
    current    = get_listening_ports()
    tcp_target = current.tcp | set(TCP_PERMANENT)
    udp_target = current.udp | set(UDP_PERMANENT)
    tcp_in_map = map_dump_ports(TCP_MAP_PATH)
    udp_in_map = map_dump_ports(UDP_MAP_PATH)

    changed = False
    for port in sorted(tcp_target - tcp_in_map):
        tag = f" [{TCP_PERMANENT[port]}]" if port in TCP_PERMANENT else ""
        if map_update(TCP_MAP_PATH, port, dry_run):
            log.info(f"TCP Whitelist +{port}{tag}")
            changed = True

    for port in sorted(tcp_in_map - tcp_target - set(TCP_PERMANENT)):
        if map_delete(TCP_MAP_PATH, port, dry_run):
            log.info(f"TCP Whitelist -{port}  (Stopped)")
            changed = True

    for port in sorted(udp_target - udp_in_map):
        tag = f" [{UDP_PERMANENT[port]}]" if port in UDP_PERMANENT else ""
        if map_update(UDP_MAP_PATH, port, dry_run):
            log.info(f"UDP Whitelist +{port}{tag}")
            changed = True

    for port in sorted(udp_in_map - udp_target - set(UDP_PERMANENT)):
        if map_delete(UDP_MAP_PATH, port, dry_run):
            log.info(f"UDP Whitelist -{port}  (Stopped)")
            changed = True

    if not changed:
        log.debug("Port whitelist is up-to-date")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch",    action="store_true")
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--dry-run",  action="store_true")
    args = parser.parse_args()
    if args.watch:
        log.info(f"Daemon started with interval {args.interval}s")
        while True:
            try:
                sync_once(args.dry_run)
                time.sleep(args.interval)
            except KeyboardInterrupt:
                log.info("exiting...")
                break
    else:
        sync_once(args.dry_run)
        log.info("Sync completed")

if __name__ == "__main__":
    main()
PYEOF
chmod +x "$SYNC_SCRIPT"
ok "Script deployed: $SYNC_SCRIPT"

# ── 9. Enable systemd ────────────────────────────────
info "Enabling systemd: $SERVICE_NAME ..."
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
ok "Deamon enabled: $SERVICE_NAME"

# ── 10. Start test ──────────────────────────────────────
info "Syncing..."
python3 "$SYNC_SCRIPT"

# ── 11. Done ────────────────────────────────────────
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Deployment Completed! ${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Interface:     $IFACE"
echo "  BPF maps: $BPF_PIN_DIR/"
echo "  Deamon: systemctl status $SERVICE_NAME"
echo ""
echo "  Current whitelisted TCP:"
bpftool -j map dump pinned "${BPF_PIN_DIR}/tcp_whitelist" 2>/dev/null \
  | python3 -c "
import json,sys
try:
    data = json.load(sys.stdin)
    items = data if isinstance(data, list) else data.get('items', [])
    for e in items:
        if isinstance(e, dict):
            k = e.get('key', [])
            if len(k) >= 2:
                h = int(k[0], 16) if isinstance(k[0], str) else k[0]
                l = int(k[1], 16) if isinstance(k[1], str) else k[1]
                print(f'    → TCP {(h << 8) | l}')
except:
    pass
" || echo "    (NULL)"
echo ""
echo "  Uninstall command: ip link set dev $IFACE xdp off"
echo ""
