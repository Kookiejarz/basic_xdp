## **⚡ Basic XDP**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE) [![Kernel](https://img.shields.io/badge/Kernel-%E2%89%A54.18-blue)](https://www.kernel.org/) [![Platform](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu-orange)](https://ubuntu.com/) [![XDP](https://img.shields.io/badge/Tech-eBPF%2FXDP-brightgreen)](https://ebpf.io/)

A lightweight, high-performance XDP/eBPF-based rule for Linux that provides **automatic port whitelisting** and **basic DDoS protection** for personal cloud instances.

Although there are some XDP firewall solutions available, Basic XDP provides users with automatic port whitelisting, which makes maintenance easier.

***⚠️ XDP only filters traffic that reaches your NIC. If your upstream bandwidth is already saturated by a volumetric attack, this tool cannot help. For large-scale DDoS mitigation, consider upstream scrubbing services or a DDoS-protected hosting provider.***

---

## Overview

### What is XDP?

**XDP (eXpress Data Path)** is an eBPF-based, high-performance packet processing path that runs **before packets enter the Linux networking stack** (at the NIC driver level). This makes it significantly faster than traditional `iptables`/`nftables` filtering.

### Why Basic XDP?

Personal cloud instances are constantly scanned and probed. Traditional firewalls like `iptables` work, but they process packets *after* the kernel networking stack — adding latency and CPU overhead.

**Basic XDP** hooks in **at the NIC driver level**, before any kernel processing. And unlike other XDP solutions, it **manages the port whitelist for you**: a daemon watches which ports are actually open on your system and keeps the BPF maps in sync automatically. You never need to manually update firewall rules when you start or stop a service. 😎

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
- **~40–65 ns per-packet latency** measured on real hardware (see [Benchmarks](#benchmarks))
- **Auto-sync whitelist**: daemon watches `ss` output and updates BPF maps in real time 
- **TCP SYN filtering**: only new connections to whitelisted ports are allowed; established connections (ACK) pass 
- **IPv6 support**, including extension header traversal to prevent bypasses 
- **UDP whitelist**, plus allow rules for DNS (53), NTP (123), DHCP (67), QUIC (443) responses 
- **Pinned BPF maps** that survive reloads and can be updated at runtime 
- **ICMP/ICMPv6/ARP passthrough** (ping + IPv6 NDP still work) 
- **Systemd daemon**: starts on boot, auto sync open ports
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
5. Compiles the BPF program with `clang -mcpu=v3` 
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
|:-:|:-:|:--:|:-:|:-:|
| `tcp_whitelist` | ARRAY | 65536 | `__u32` port (host byte order) | `__u32` (1 = allow) |
| `udp_whitelist` | ARRAY | 65536 | `__u32` port (host byte order) | `__u32` (1 = allow) |

### Manually Add / Remove a Port

```bash
# Allow TCP port 8080
bpftool map update pinned /sys/fs/bpf/xdp_fw/tcp_whitelist \
    key 0x90 0x1f 0x00 0x00 value 0x01 0x00 0x00 0x00

# Remove TCP port 8080
bpftool map delete pinned /sys/fs/bpf/xdp_fw/tcp_whitelist \
    key 0x90 0x1f 0x00 0x00

# View current TCP whitelist
bpftool map dump pinned /sys/fs/bpf/xdp_fw/tcp_whitelist
```

Key encoding note: the map type is now **ARRAY** (`BPF_MAP_TYPE_ARRAY`), so the key is a 4-byte little-endian `__u32` port number (host byte order). Example: `8080` = `0x00001F90` → bytes `0x90 0x1f 0x00 0x00`

---

## Why ARRAY instead of HASH?

Originally, this project used **BPF_MAP_TYPE_HASH** for the whitelist. We transitioned to **BPF_MAP_TYPE_ARRAY** for several critical reasons:

- **O(1) Lookup Time**: An Array map provides constant-time lookup ($O(1)$) by directly indexing into memory using the port number. A Hash map averages O(1) but degrades under hash collisions, whereas an Array map guarantees O(1) by direct index access with no collision possible. :))))
- **Zero Hash Collisions**: With 65,536 entries (one for every possible port), there is no possibility of hash collisions. In a Hash map with a small max_entries (e.g., 64), collisions frequently occur during high-volume scans, causing latency spikes.
- **CPU Cache Efficiency**: Because the Array is a contiguous block of memory, the CPU's prefetcher can handle it much more efficiently than the pointer-chasing required by Hash map buckets.

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
TCP_PERMANENT = {22: "SSH-fallback"}   # Always allow SSH in case you block yourself out
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

## Benchmarks

Measured with `bpftool prog run ... repeat N data_in <packet>` against the JIT-compiled XDP program. Return value `2` = `XDP_DROP` (fast-path hit).

| Host | CPU | vCPUs | Packet input | Repeat | Avg latency |
|:----:|:---:|:-----:|:------------:|:------:|:-----------:|
| VPS A | Intel Xeon Platinum 8160M @ 2.10 GHz (KVM) | 2 | synthetic (no `data_in`) | 100 000 000 | **65 ns** |
| VPS B | AMD Ryzen 9 3900X @ 2.0 GHz (KVM) | 1 | 30-byte IPv4 pkt (`data_in`) | 1 000 000 000 | **40 ns** |
| VPS C | AMD EPYC 7Y43 @ 2.55GHz (KVM) | 1 | 30-byte IPv4 pkt (`data_in`) | 1 000 000 000 | **34 ns** |

> **Note — `data_in` matters.**  
> Without `data_in` the runner feeds a zero-length buffer; the BPF program returns immediately at the first bounds check (`data_end` == `data`), so the measurement reflects JIT dispatch overhead more than real packet-processing logic.  
> The 40ns and 34 ns figure (VPS B and VPS C, with a real IPv4 frame) are the more representative numbers.

### Theoretical throughput (single core, `XDP_DROP` fast path)

| Avg latency | Packets / second |
|:-----------:|:----------------:|
| 65 ns | ≈ **15.4 Mpps** |
| 40 ns | ≈ **25.0 Mpps** |
| 34 ns | ≈ **29.4 Mpps** |

> Real-world NIC throughput will be the practical ceiling; the XDP program itself is not the bottleneck.

### How to reproduce

```bash
# Build a minimal IPv4 packet (Ethernet header + IPv4 header, no payload)
python3 -c 'print("00"*14 + "45000028" + "00"*16)' | xxd -r -p > /tmp/pkt.bin

# Get the program ID
PROG_ID=$(bpftool -j prog show pinned /sys/fs/bpf/xdp_fw/prog \
          | python3 -c "import json,sys; print(json.load(sys.stdin)['id'])")

# Run 100 M iterations with a real packet
sudo bpftool prog run id "$PROG_ID" repeat 100000000 data_in /tmp/pkt.bin
```

---

##  📁 Project Structure

basic_xdp/
├── xdp_firewall.c      # eBPF/XDP kernel program (packet filtering logic)
├── setup_xdp.sh        # One-click deploy: compile, load, and start daemon
└── README.md


## 🤝 **Contributing**

Contributions are welcome! If you have a bug fix, performance improvement, or new feature in mind: 

1. Fork the repository 
2. Create a feature branch (`git checkout -b feature/my-improvement`) 
3. Commit your changes
4. Open a pull request For bugs or questions, please [open an issue](https://github.com/Kookiejarz/basic_xdp/issues).

---

## 📄 License

[MIT](./LICENSE) © 2026 Yunheng Liu

