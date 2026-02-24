### Basic XDP

A lightweight, high-performance XDP/eBPF-based rule for Linux that provides **automatic port whitelisting** and **basic DDoS protection** for personal cloud instances.

---

## Overview

### What is XDP?

**XDP (eXpress Data Path)** is an eBPF-based, high-performance packet processing path that runs **before packets enter the Linux networking stack** (at the NIC driver level). This makes it significantly faster than traditional `iptables`/`nftables` filtering.

---

## How It Works

```
Incoming Packet
      │
      ▼
┌─────────────┐
│  NIC Driver │  ← XDP hooks here (before kernel stack)
└──────┬──────┘
       │
       ▼
┌──────────────────────────────┐
│       xdp_port_whitelist     │
│                              │
│  ETH → IPv4/IPv6 → TCP/UDP   │
│                              │
│  TCP SYN?  → check map       │
│  TCP ACK?  → PASS (reply)    │
│  UDP?      → check map       │
│  ICMP/ARP? → PASS            │
│                              │
│  Not in whitelist → DROP     │
└──────────────────────────────┘
       │
       ▼
  XDP_PASS / XDP_DROP
```

---

## Components

1. **`xdp_firewall.c`** — eBPF/XDP kernel program that filters packets at wire speed   
2. **`setup_xdp.sh`** — one-click deployment script that compiles, loads, and sets up an auto-sync daemon 

---

## Key Features

- **Wire-speed filtering** via XDP (bypasses kernel network stack) 
- **Auto-sync whitelist**: daemon watches `ss` output and updates BPF maps in real time 
- **TCP SYN filtering**: only new connections to whitelisted ports are allowed; established connections (ACK) pass 
- **IPv6 support**, including extension header traversal to prevent bypasses 
- **UDP whitelist**, plus allow rules for DNS (53), NTP (123), DHCP (67), QUIC (443) responses 
- **Pinned BPF maps** that survive reloads and can be updated at runtime 
- **ICMP/ICMPv6/ARP passthrough** (ping + IPv6 NDP still work) 
- **Systemd daemon**: starts on boot, syncs every 5 seconds
- **Native + generic XDP**: falls back to generic mode if native isn’t supported 

---

## Requirements

- Linux kernel **≥ 4.18** (BPF map pinning support)
- Debian/Ubuntu-based distro (auto-installs dependencies) 
- Root (sudo) privileges 

### Dependencies (auto-installed)
- `clang`, `llvm` — compile BPF 
- `libbpf-dev` — BPF headers 
- `bpftool` — manage BPF maps 
- `iproute2` — attach XDP via `ip link` 
- `python3` — sync daemon runtime 

---

## Quick Start

```bash
curl -fsSL https://raw.githubusercontent.com/Kookiejarz/basic_xdp/refs/heads/main/setup_xdp.sh | sudo bash
```

---

## Install From Source

```bash
git clone https://github.com/Kookiejarz/basic_xdp.git
cd basic_xdp

# Auto-detect interface
sudo bash setup_xdp.sh

# Or specify interface
sudo bash setup_xdp.sh eth0
```

---

## What `setup_xdp.sh` Does (Step-by-Step)

1. Checks for root privileges 
2. Auto-detects default network interface
3. Installs missing dependencies via `apt` 
4. Fetches/updates `xdp_firewall.c` from GitHub (keeps newer local version)   
5. Compiles the BPF program with `clang` targeting BPF architecture 
6. Mounts `bpffs` at `/sys/fs/bpf` if needed 
7. Detaches existing XDP program and removes old pinned maps   
8. Loads + pins XDP program and maps to `/sys/fs/bpf/xdp_fw/` 
9. Installs port-sync daemon to `/usr/local/bin/xdp-sync-ports.py`   
10. Registers and starts systemd service `xdp-port-sync` 
11. Runs an initial port sync 

---

## BPF Maps

Pinned directory: `/sys/fs/bpf/xdp_fw/` 

| Map | Type | Max Entries | Key | Value |
|---|---|---:|---|---|
| `tcp_whitelist` | HASH | 64 | `__u16` port (host byte order) | `__u32` (1 = allow) |
| `udp_whitelist` | HASH | 16 | `__u16` port (host byte order) | `__u32` (1 = allow) |

### Manually Add / Remove a Port

```bash
# Allow TCP port 8080
bpftool map update pinned /sys/fs/bpf/xdp_fw/tcp_whitelist \
    key 0x90 0x1f value 0x01 0x00 0x00 0x00

# Remove TCP port 8080
bpftool map delete pinned /sys/fs/bpf/xdp_fw/tcp_whitelist \
    key 0x90 0x1f

# View current TCP whitelist
bpftool map dump pinned /sys/fs/bpf/xdp_fw/tcp_whitelist
```

Key encoding note: port is little-endian (host byte order). Example: `8080` = `0x1F90` → bytes `0x90 0x1f` [1]

---

## Auto-Sync Daemon

The daemon `xdp-sync-ports.py` runs as a systemd service and loops every **5 seconds**:

1. Reads listening ports via `ss -lnH -t -u`
2. Compares with current BPF map entries
3. Adds newly listening ports 
4. Removes ports no longer listening 

### Permanent Ports

Edit constants in the daemon to always allow specific ports:

```python
TCP_PERMANENT = {22: "SSH-fallback"}   # Always allow SSH
UDP_PERMANENT = {}
```

### Daemon Management

```bash
systemctl status xdp-port-sync
journalctl -u xdp-port-sync -f

python3 /usr/local/bin/xdp-sync-ports.py
python3 /usr/local/bin/xdp-sync-ports.py --dry-run
```

---

## Packet Filtering Logic

### TCP
- If **ACK** is set → **PASS** (established connection traffic) 
- Else if packet is a **pure SYN**:
  - destination port in `tcp_whitelist` → **PASS** 
  - otherwise → **DROP** 

### UDP
- If source port in `{53, 123, 67, 443}` → **PASS** (common response traffic)
- Else if destination port in `udp_whitelist` → **PASS** 
- Otherwise → **DROP** 

### IPv6 Extension Headers

Traverses IPv6 extension headers up to **6 levels deep** to locate the transport protocol and prevent crafted-header bypass attacks .

---

## Uninstall

```bash
# Detach XDP
ip link set dev eth0 xdp off

# Remove pinned maps
rm -rf /sys/fs/bpf/xdp_fw

# Stop and disable daemon + remove files
systemctl disable --now xdp-port-sync
rm /usr/local/bin/xdp-sync-ports.py
rm /etc/systemd/system/xdp-port-sync.service
systemctl daemon-reload
```



---

## License

MIT License (see [`LICENSE`](./LICENSE))
