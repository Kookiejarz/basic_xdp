# Auto XDP

> 🚩 The Mission: Making high-performance eBPF security accessible to everyone—without needing a PhD in Linux kernel networking.

**A lightweight XDP/eBPF firewall for automatic port whitelisting and DDoS protection on Linux hosts.**

<p align="center">
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square" alt="License"></a>
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <a href="https://www.kernel.org/"><img src="https://img.shields.io/badge/Kernel-%E2%89%A54.18-blue.svg?style=flat-square" alt="Kernel >= 4.18"></a>
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <a href="https://github.com/Kookiejarz/Auto_XDP/actions/workflows/distro-check.yml"><img src="https://github.com/Kookiejarz/Auto_XDP/actions/workflows/distro-check.yml/badge.svg" alt="Distro Checks"></a>
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/Init-systemd%20%7C%20OpenRC-555555.svg?style=flat-square" alt="systemd and OpenRC">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <a href="https://ebpf.io/"><img src="https://img.shields.io/badge/Tech-eBPF%2FXDP-brightgreen.svg?style=flat-square" alt="eBPF/XDP"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Debian%2FUbuntu-supported-A81D33.svg?style=flat-square" alt="Debian/Ubuntu supported">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/Fedora%2FRHEL-supported-294172.svg?style=flat-square" alt="Fedora/RHEL supported">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/openSUSE-supported-73BA25.svg?style=flat-square" alt="openSUSE supported">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/Arch-supported-1793D1.svg?style=flat-square" alt="Arch supported">
  <img width="3" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">
  <img src="https://img.shields.io/badge/Alpine-supported-0D597F.svg?style=flat-square" alt="Alpine supported">
</p>
Although there are some other XDP firewall solutions available, Auto XDP provides users with automatic port whitelisting, which makes maintenance significantly easier. Zero config, effortless management.

***⚠️ XDP only filters traffic that reaches your NIC. If your upstream bandwidth is already saturated by a volumetric attack, this tool cannot help. For large-scale DDoS mitigation, consider upstream scrubbing services or a DDoS-protected hosting provider.***

---

## Overview

### What is XDP?

**XDP (eXpress Data Path)** is an eBPF-based, high-performance packet processing path that runs **before packets enter the Linux networking stack** (at the NIC driver level). This makes it significantly faster than traditional `iptables`/`nftables` filtering.

### Why Auto XDP?

Personal cloud instances are constantly scanned and probed. Traditional firewalls like `iptables` work, but they process packets *after* the kernel networking stack — adding latency and CPU overhead. They also require manual firewall configurations and port controls, making host management to be more complicated.

**Auto XDP** hooks in **at the NIC driver level**, before any kernel processing. And unlike other XDP solutions, it **manages the port whitelist for you**: a daemon watches which ports are actually open on your system and keeps the active backend in sync automatically. When a host cannot run XDP, it can fall back to an `nftables` ruleset instead of failing outright.

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
│  IPv4 TCP SYN? → whitelist + │
│                  conntrack   │
│  IPv4 TCP ACK? → conntrack   │
│  IPv4 UDP?     → ct/port/IP  │
│  ICMP/ICMPv6? → rate-limit   │
│  ARP/NDP?   → PASS           │
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
2. **`tc_flow_track.c`** — eBPF `tc` egress helper that records outbound IPv4/IPv6 TCP SYN packets and UDP reply tuples
3. **`xdp_port_sync.py`** — userspace daemon that syncs TCP/UDP listening ports and trusted IPv4 source IPs
4. **`axdp`** — operator CLI for statistics, sync, service control, and daemon log level
5. **`setup_xdp.sh`** — installer that compiles the BPF objects, installs the runtime launcher, and sets up boot-time auto-sync

---

## Key Features

- **Wire-speed filtering** via XDP (bypasses kernel network stack)
- **~40–65 ns per-packet latency** measured on real hardware (see [Benchmarks](#-real-world-performance-benchmark))
- **Auto-sync whitelist**: daemon watches listening sockets and updates the active backend in real time
- **IPv4 + IPv6 TCP conntrack hardening**: pure SYN creates temporary state; unsolicited ACK packets are dropped
- **Kernel-side outbound state tracking**: a `tc` egress program records host-initiated IPv4/IPv6 TCP SYN packets and UDP reply tuples so return traffic can be matched at XDP without reopening the old bypasses
- **IPv4 + IPv6 UDP hardening**: inbound server ports use `udp_whitelist`, reply traffic can be matched by `udp_conntrack`, and explicitly trusted IPv4/IPv6 sources or CIDR ranges can be allowed via `trusted_src_ips4`/`trusted_src_ips6`
- **IPv6 support**, including extension header traversal on both XDP and tc egress, plus explicit non-initial fragment drops
- **Periodic conntrack sync (seeding established flows)**: the daemon now periodically seeds existing IPv4/IPv6 TCP sessions into `tcp_conntrack`, which helps preserve active sessions after re-attaching XDP or manual map clears.
- **Reload-safe XDP attach**: the installer also pre-seeds existing sessions before initial attach.
- **Pinned BPF maps** that survive reloads and can be updated at runtime 
- **ICMP token-bucket rate limiter**: XDP-level protection against ICMP/ICMPv6 ping floods; 100 pps burst cap with per-second token refill, while ARP and IPv6 NDP control traffic (RS/RA/NS/NA) are always passed
- **Per-IP SYN rate limiting (anti-brute-force)**: configurable per-port SYN rate limit tracked per source IP in a 1-second fixed window; stricter defaults for SSH/MySQL, higher for mail services
- **Boot-time loader**: restores protection on reboot instead of only syncing userspace state
- **Systemd + OpenRC support**: installs the service automatically when either init system is present
- **Configurable daemon verbosity**: `axdp log-level debug|info|warning|error` updates the installed service config and restarts it
- **Native + generic XDP**: tries native first, then generic
- **nftables fallback**: if both XDP attach modes fail, keeps automatic port whitelisting with a dynamic `nftables` ruleset

---

## Requirements

- Linux kernel **≥ 4.18** for the XDP backend
- Popular Linux distro with a supported package manager: Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, or Alpine
- Root (sudo) privileges 
- `nftables` support is used automatically as the compatibility fallback when XDP cannot be attached

### Dependencies (auto-installed)
- `clang`, `llvm` — compile BPF 
- `libbpf` or `libbpf-dev` / `libbpf-devel` — BPF headers, depending on distro 
- `bpftool` — manage BPF maps 
- `iproute2` or `iproute` — provides both `ip` and `tc` for XDP attach and UDP egress tracking
- `python3` — sync daemon runtime 
- `nftables` — compatibility fallback backend 

---

## Quick Start

```bash
curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/Kookiejarz/Auto_XDP/refs/heads/main/setup_xdp.sh | sudo bash
```

### Install a Specific Release

```bash
curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/Kookiejarz/Auto_XDP/refs/tags/v26.4.19a/setup_xdp.sh | sudo bash
```

Using a tag gives you a reproducible installer version instead of tracking the latest `main` branch.

When the installer is executed from `stdin` (`curl | bash`), it prefers the matching GitHub source files instead of stale local files from the current working directory.

## Automated Distro Checks

The repository includes a GitHub Actions matrix that installs basic runtime tools in supported Linux container images and runs a non-destructive `setup_xdp.sh --dry-run` smoke test.

The installer reads `/etc/os-release` to classify the distro family before choosing the matching package-manager and dependency set.

You can also run the non-destructive smoke test locally:

```bash
bash setup_xdp.sh --dry-run
```

If you only want the package-manager and init-system probe, use:

```bash
bash setup_xdp.sh --check-env
```

---

## Install From Source

```bash
git clone https://github.com/Kookiejarz/Auto_XDP.git
cd auto_xdp

# Auto-detect interface
sudo bash setup_xdp.sh

# Or specify interface
sudo bash setup_xdp.sh eth0

# Compare local files with GitHub first, then decide interactively
sudo bash setup_xdp.sh --check-update

# Non-interactive mode for CI / automation
sudo bash setup_xdp.sh --check-update --force
```

---

## What `setup_xdp.sh` Does (Step-by-Step)

1. Checks for root privileges 
2. Auto-detects default network interface
3. Installs missing dependencies via the detected package manager 
4. Uses local `xdp_firewall.c` / `tc_flow_track.c` / `xdp_port_sync.py` / `axdp` by default from a local checkout; when run from `stdin`, it prefers the matching GitHub copies
5. Compiles the XDP and tc BPF objects when the host has the required toolchain
6. Pre-seeds current IPv4/IPv6 established TCP sessions into `tcp_conntrack` before attaching XDP
7. Loads and attaches a `tc clsact egress` program that records outbound TCP SYN and UDP reply tuples
8. Tries to attach XDP in native mode, then generic mode
9. Falls back to `nftables` automatically if XDP cannot be attached
10. Installs the runtime launcher at `/usr/local/bin/auto_xdp_start.sh`
11. Installs the sync daemon at `/usr/local/bin/xdp_port_sync.py`
12. Runs an initial port sync using the selected backend
13. Registers and starts `xdp-port-sync` on `systemd` or `OpenRC` when available

---

## BPF Maps

Pinned directory: `/sys/fs/bpf/xdp_fw/` 

| Map | Type | Max Entries | Key | Value |
|:-:|:-:|:--:|:-:|:-:|
| `tcp_whitelist` | ARRAY | 65536 | `__u32` port (host byte order) | `__u32` (1 = allow) |
| `udp_whitelist` | ARRAY | 65536 | `__u32` port (host byte order) | `__u32` (1 = allow) |
| `tcp_conntrack` | LRU_HASH | 65536 | `struct ct_key { family, sport, dport, saddr[4], daddr[4] }` | `__u64` ktime_ns |
| `udp_conntrack` | LRU_HASH | 65536 | `struct ct_key { family, sport, dport, saddr[4], daddr[4] }` | `__u64` ktime_ns |
| `trusted_ipv4` | LPM_TRIE | 256 | `struct trusted_v4_key { prefixlen, addr }` (IPv4 CIDR) | `__u32` (1 = trusted) |
| `trusted_ipv6` | LPM_TRIE | 256 | `struct trusted_v6_key { prefixlen, addr[16] }` (IPv6 CIDR) | `__u32` (1 = trusted) |
| `pkt_counters` | PERCPU_ARRAY | 22 | `__u32` counter index | `__u64` packet count |
| `icmp_tb` | ARRAY | 1 | `__u32` (0) | `struct icmp_token_bucket { last_ns, tokens }` |
| `syn_rate_ports` | HASH | 64 | `__u32` dest port | `struct syn_rate_port_cfg { rate_max }` |
| `syn_rate_map` | LRU_HASH | 65536 | `struct syn_rate_key { dest_port, saddr[4] }` | `struct syn_rate_val { window_start_ns, count }` |
| `udp_rate_ports` | HASH | 64 | `__u32` dest port | `struct syn_rate_port_cfg { rate_max }` |
| `udp_rate_map` | LRU_HASH | 65536 | `struct syn_rate_key { dest_port, saddr[4] }` | `struct syn_rate_val { window_start_ns, count }` |
| `udp_global_rl` | ARRAY | 1 | `__u32` (0) | `struct udp_global_tb { lock, rate_max, window_start_ns, prev_count, curr_count }` |

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

Originally, this project used **BPF_MAP_TYPE_HASH** for the whitelist. It transitioned to **BPF_MAP_TYPE_ARRAY** for several critical reasons:

- **O(1) Lookup Time**: An Array map provides constant-time lookup ($O(1)$) by directly indexing into memory using the port number. A Hash map averages O(1) but degrades under hash collisions, whereas an Array map guarantees O(1) by direct index access with no collision possible. :))))
- **Zero Hash Collisions**: With 65,536 entries (one for every possible port), there is no possibility of hash collisions. In a Hash map with a small max_entries (e.g., 64), collisions frequently occur during high-volume scans, causing latency spikes.
- **CPU Cache Efficiency**: Because the Array is a contiguous block of memory, the CPU's prefetcher can handle it much more efficiently than the pointer-chasing required by Hash map buckets.

---

## Auto-Sync Daemon

The daemon `xdp_port_sync.py` runs behind the launcher `/usr/local/bin/auto_xdp_start.sh` and provides **real-time updates** for either backend:

1. **Event-driven**: Uses Linux **Netlink Process Connector** to detect `exec()` and `exit()` events immediately.
2. **Efficient Discovery**: Uses `psutil` to read `/proc` directly for listening ports (no slow `ss` or `netstat` subprocesses, yeahhh).
3. **Safety Fallback**: Performs a full sync every **30 seconds** to ensure consistency.
4. **Backend Sync**: Updates either pinned BPF maps or `nftables` sets, depending on what the host supports.
5. **UDP Discovery Rule**: Because UDP has no `LISTEN` state, the daemon syncs unconnected bound UDP sockets (no remote peer) into `udp_whitelist`, which is a practical approximation of server-style UDP ports.
6. **Trusted Source IPs/CIDRs**: Optional IPv4/IPv6 addresses or CIDR ranges can be synced into the XDP-side `trusted_src_ips4`/`trusted_src_ips6` LPM trie maps for reply-style UDP traffic such as DNS or NTP.
7. **Backend Guard Rails**: In `auto` mode, the daemon only selects XDP when the required pinned maps are present; otherwise it falls back to `nftables` instead of crashing.

Outbound TCP/UDP reply tracking is kernel-side: a `tc` egress program records reverse reply tuples into `tcp_conntrack` and `udp_conntrack`, and the XDP ingress path checks those maps before falling back to `tcp_whitelist`, `udp_whitelist`, or `trusted_src_ips4`/`trusted_src_ips6`.

### Permanent Ports

Edit `xdp_port_sync.py` to always allow specific ports:

```python
TCP_PERMANENT = {22: "SSH-fallback"}   # Optional: add ports you never want blocked
UDP_PERMANENT = {50000: "custom-udp-service"}  # Use this for real high-port UDP services
TRUSTED_SRC_IPS = {"1.1.1.1/32": "cloudflare-dns", "2606:4700:4700::1111/128": "cloudflare-dns-v6", "10.0.0.0/8": "internal-net"}
```

If a real UDP server uses a high port, add it to `UDP_PERMANENT` explicitly so it remains whitelisted even when the daemon's socket heuristics cannot distinguish it cleanly from transient client traffic.

You can also add trusted IPv4/IPv6 sources and CIDR ranges at runtime:

```bash
# Single IPv4 host
python3 /usr/local/bin/xdp_port_sync.py --backend auto \
  --trusted-ip 1.1.1.1 cloudflare-dns

# IPv4 subnet — host bits are masked automatically (203.23.2.5/24 → 203.23.2.0/24)
python3 /usr/local/bin/xdp_port_sync.py --backend auto \
  --trusted-ip 203.23.2.0/24 office-net

# IPv6 single host
python3 /usr/local/bin/xdp_port_sync.py --backend auto \
  --trusted-ip 2606:4700:4700::1111 cloudflare-dns-v6

# IPv6 prefix
python3 /usr/local/bin/xdp_port_sync.py --backend auto \
  --trusted-ip 2001:db8::/32 example-v6-net

# Mix of IPv4, IPv4 CIDR, IPv6 host, IPv6 prefix — all in one invocation
python3 /usr/local/bin/xdp_port_sync.py --backend auto \
  --trusted-ip 1.1.1.1          cloudflare-dns \
  --trusted-ip 10.0.0.0/8       internal-net \
  --trusted-ip 2606:4700:4700::1111 cloudflare-dns-v6 \
  --trusted-ip fd00::/8         ula-net \
  --dry-run
```

`--trusted-ip` is synced to both backends: XDP writes to the `trusted_ipv4`/`trusted_ipv6` LPM trie maps; `nftables` writes to equivalent `trusted_v4`/`trusted_v6` sets in the `auto_xdp` table.

### Daemon Management

```bash
# systemd
systemctl status xdp-port-sync
journalctl -u xdp-port-sync -f

# OpenRC
rc-service xdp-port-sync status

# Manual foreground run
/usr/local/bin/auto_xdp_start.sh

# One-shot sync with automatic backend selection
python3 /usr/local/bin/xdp_port_sync.py --backend auto
python3 /usr/local/bin/xdp_port_sync.py --backend auto --dry-run

# Increase foreground verbosity temporarily
python3 /usr/local/bin/xdp_port_sync.py --backend auto --log-level debug
```

## Statistics

Auto XDP installs a convenience command `/usr/local/bin/axdp`. Statistics are now built directly into `axdp`, so you only need one operational command after installation.

```bash
# Single snapshot
sudo axdp

# Real-time refresh
sudo axdp watch

# Show delta rates (pps / bps)
sudo axdp stats --rates

# Combine both
sudo axdp stats --watch --rates --interval 2

# Run one manual sync
sudo axdp sync

# Inspect currently allowed TCP/UDP ports (with per-IP SYN rate stats)
sudo axdp ports
sudo axdp ports --tcp
sudo axdp ports --udp

# View or change daemon log level
sudo axdp log-level
sudo axdp log-level debug

# Service control
sudo axdp start
sudo axdp stop
sudo axdp restart
sudo axdp status
```

What it shows:

1. `xdp` backend: per-category packet counters from `/sys/fs/bpf/xdp_fw/pkt_counters`, plus interface RX totals
2. `nftables` backend: current drop counter from the `inet auto_xdp input` chain, plus interface RX totals
3. `--rates`: packet deltas for XDP counters, and packet/bit deltas where byte counters are available

Counter labels in `axdp` are intentionally human-readable:

1. `TCP_NEW_ALLOW` — pure SYN packets admitted by `tcp_whitelist` or trusted source
2. `TCP_ESTABLISHED` — TCP packets admitted by `tcp_conntrack`
3. `TCP_DROP` — TCP packets dropped
4. `UDP_PASS` — UDP packets passed
5. `UDP_DROP` — UDP packets dropped
6. `IPv4_OTHER` — IPv4 non-TCP/UDP (ICMP, GRE, etc.) passed
7. `IPv6_ICMP` — ICMPv6 and other non-TCP/UDP IPv6 traffic passed
8. `FRAG_DROP` — fragmented packets dropped (IPv4 MF/offset set, or non-initial IPv6 fragments)
9. `ARP_NON_IP` — ARP and other non-IP Ethernet traffic passed
10. `TCP_CT_MISS` — TCP ACK packets dropped because no conntrack entry existed
11. `ICMP_DROP` — ICMP/ICMPv6 echo packets dropped by the token-bucket rate limiter
12. `SYN_RATE_DROP` — TCP SYN packets dropped by the per-IP SYN rate limiter
13. `UDP_RATE_DROP` — UDP packets dropped by the per-source-IP rate limiter
14. `UDP_GBL_DROP` — UDP packets dropped by the global sliding-window rate limiter
15. `TCP_NULL` — TCP NULL scan (all flags zero)
16. `TCP_XMAS` — TCP XMAS scan (FIN+URG+PSH)
17. `TCP_SYN_FIN` — TCP SYN+FIN contradictory flags
18. `TCP_SYN_RST` — TCP SYN+RST contradictory flags
19. `TCP_RST_FIN` — TCP RST+FIN contradictory flags
20. `TCP_BAD_DOFF` — TCP invalid data offset (`doff < 5`, `doff > 15`, or truncated header)
21. `TCP_PORT0` — TCP src or dst port is 0
22. `VLAN_DROP` — VLAN nesting depth exceeds limit (possible bypass attempt)

## Post-Install Quick Commands

After installation, these are the main commands you will actually use:

```bash
# Help
sudo axdp help

# Current statistics snapshot
sudo axdp

# Live statistics
sudo axdp watch

# Delta rates
sudo axdp stats --rates

# Live delta rates
sudo axdp stats --watch --rates --interval 2

# Run one manual sync
sudo axdp sync

# Inspect currently allowed ports
sudo axdp ports
sudo axdp ports --tcp
sudo axdp ports --udp

# Change daemon log verbosity and restart the service
sudo axdp log-level
sudo axdp log-level debug
sudo axdp log-level info

# Service control
sudo axdp start
sudo axdp stop
sudo axdp status
sudo axdp restart
```

### Source Update Check

When you run the installer from a cloned repo, local source files win by default. If you want the script to compare your local copies with GitHub first, use:

```bash
sudo bash setup_xdp.sh --check-update
```

In `--check-update` mode, the installer:

1. Downloads the GitHub version of `xdp_firewall.c`, `tc_flow_track.c`, `xdp_port_sync.py`, and `axdp` to temporary files
2. Compares the local and GitHub SHA-256 hashes
3. Prompts you when they differ
4. Pulls the GitHub copy only if you confirm

### Non-Interactive Mode

For CI or automated deployment, use:

```bash
sudo bash setup_xdp.sh --force
```

Or combine it with source comparison:

```bash
sudo bash setup_xdp.sh --check-update --force
```

In `--force` mode, the installer skips confirmation prompts and:

1. Pulls the GitHub copy automatically when `--check-update` finds a hash mismatch
2. Unloads any existing XDP program automatically before reinstalling

---

## Packet Filtering Logic

### TCP
- **IPv4 + IPv6 stateful path**:
  - If packet is a **pure SYN** and source matches `trusted_ipv4`/`trusted_ipv6` → insert flow key into `tcp_conntrack` and **PASS** (whitelist and SYN rate limit bypassed)
  - If packet is a **pure SYN** and destination port is in `tcp_whitelist` → insert flow key into `tcp_conntrack` and **PASS**
  - If **ACK** is set and the flow key exists in `tcp_conntrack` → **PASS**
  - If **ACK** is set and no conntrack entry exists → count `CNT_TCP_CT_MISS` and **DROP**
  - Otherwise → **DROP**
- **Kernel assist**: a `tc` egress program records host-initiated IPv4/IPv6 TCP SYN packets immediately, closing the race where a very short outbound connection could receive SYN-ACK before conntrack state existed.
- **Reload assist**: `setup_xdp.sh` pre-seeds existing IPv4/IPv6 TCP sessions into `tcp_conntrack` before re-attaching XDP, which helps preserve active sessions during reinstall/restart.

### TCP Malformed Packet Detection

Structural validity is checked **before** conntrack lookup and before the RST fast-path. Each violation increments a dedicated counter in `pkt_counters`.

| Check | DROP condition |
|---|---|
| Invalid data offset | `doff < 5` or `doff > 15`, or declared header extends past packet end |
| Port zero | `src port == 0` or `dst port == 0` |
| NULL scan | All control bits zero |
| SYN+FIN | Both bits set simultaneously |
| SYN+RST | Both bits set simultaneously |
| RST+FIN | Both bits set simultaneously |
| XMAS scan | FIN+URG+PSH all set |

#### Why malformed checks run before the RST fast-path

The conntrack path contains an RST fast-path that evicts the conntrack entry and immediately passes the packet to the kernel (so the kernel can deliver `ECONNRESET` to the application). This is the correct behavior for a **legitimate RST**.

RFC 793 §3.4 defines RST processing only for structurally valid packets — valid `doff`, valid ports, and no contradictory flag combinations. A packet with RST set alongside SYN or FIN, or with `doff < 5`, is not a legitimate RST: it cannot have originated from any RFC 793-conforming implementation. Letting it reach the RST fast-path would:

1. **Silently evict conntrack state** for an active connection — a trivially exploitable denial-of-service: an attacker sends a single spoofed RST+SYN to tear down any tracked session without completing the SYN handshake.
2. **Forward a structurally invalid packet to the kernel** — the kernel may discard it, but the conntrack slot is already gone.

Running the structural check first ensures that only RFC 793-conforming packets reach RST handling. The cost is one additional inline function call per TCP packet, which the BPF verifier eliminates entirely via `__always_inline`.

### UDP
- **IPv4 stateful path**:
  - If the inbound flow key exists in `udp_conntrack` → **PASS**
  - If source IPv4 address/prefix matches `trusted_ipv4` → **PASS** (whitelist and rate limits bypassed)
  - If destination port is in `udp_whitelist` → **PASS**
  - Otherwise → **DROP**
- **IPv6 stateful path**:
  - If the inbound flow key exists in `udp_conntrack` → **PASS**
  - If source IPv6 address/prefix matches `trusted_ipv6` → **PASS** (whitelist and rate limits bypassed)
  - If destination port is in `udp_whitelist` → **PASS**
  - Otherwise → **DROP**
- **Trusted source priority**: trusted sources bypass port whitelist and all rate limits (per-source, per-port, global). Fragment drops and malformed-packet checks still apply.
- **Userspace assist**: trusted IPv4/IPv6 source addresses and CIDR ranges are synced into `trusted_ipv4`/`trusted_ipv6` LPM trie maps by the daemon; the `nftables` fallback maintains equivalent `trusted_v4`/`trusted_v6` sets.

### IPv6 Extension Headers

Traverses IPv6 extension headers up to **6 levels deep** to locate the transport protocol and prevent crafted-header bypass attacks. This logic now exists on both the XDP ingress path and the `tc` egress tracker, so IPv6 reply-state tracking is not limited to the simplest `nexthdr` cases. Non-initial IPv6 fragments are explicitly counted and dropped before the transport parser, so they cannot slip through on a failed bounds check.

---

## Uninstall

```bash
# Detach XDP if it is attached
ip link set dev eth0 xdp off

# Remove the TCP/UDP reply tracker
tc filter del dev eth0 egress pref 49152 2>/dev/null || true

# Remove pinned maps and nftables fallback table
rm -rf /sys/fs/bpf/xdp_fw
nft delete table inet auto_xdp 2>/dev/null || true

# systemd
systemctl disable --now xdp-port-sync 2>/dev/null || true
rm /etc/systemd/system/xdp-port-sync.service
systemctl daemon-reload 2>/dev/null || true

# OpenRC
rc-service xdp-port-sync stop 2>/dev/null || true
rc-update del xdp-port-sync default 2>/dev/null || true
rm /etc/init.d/xdp-port-sync

# Remove installed runtime files
rm /usr/local/bin/xdp_port_sync.py
rm /usr/local/bin/axdp
rm /usr/local/bin/auto_xdp_start.sh
rm -rf /usr/local/lib/auto_xdp
rm -rf /etc/auto_xdp
```

---

## **📊 Real-World Performance Benchmark**

This benchmark simulates a volumetric UDP flood attack. We used a high-performance **AMD EPYC™ 7Y43** server as the "Attacker" to stress-test a **1 vCPU AMD Ryzen 9 3900X** instance protected by Auto XDP.

### **Test Environment**

+ 🇭🇰 **Attacker**: AMD EPYC™ 7Y43 @ 2.55GHz (Generating ~367k PPS / 188 Mbps)
+ 🇺🇸 **Target (Receiver)**: AMD Ryzen 9 3900X @ 2.0GHz (1 vCPU, 1GB RAM) 
+ **Tool**: `pktgen` (Linux Kernel Packet Generator)
+ **Attacker and target connected over *<u>public internet</u>***

### **Comparative Results**

| Metric                     | Auto XDP **OFF**         | Auto XDP **ON**        | Improvement        |
| -------------------------- | ------------------------- | ----------------------- | ------------------ |
| **Softirq (si) CPU Usage** | **85.9%**                 | **3.0%**                | **~28x Reduction** |
| **System Responsiveness**  | Extremely Laggy           | **Smooth**              | Significant        |
| **Packet Handling**        | Processed by Kernel Stack | Dropped at Driver Level | -                  |

> When XDP is off, the kernel networking stack processes every incoming packet, consuming nearly all CPU via soft interrupts. With XDP on, packets are dropped at the NIC driver level before reaching the stack — the same 367k PPS flood only uses 3% CPU, and the machine stays fully responsive.

**XDP OFF** — softirq at 85.9% under flood:

![XDP OFF](https://s3.liuu.org/blog/uPic/Screenshot%202026-02-27%20at%205.35.30%E2%80%AFPM.png)

**XDP ON** — same flood, CPU drops to 3.0%:

![XDP ON](https://s3.liuu.org/blog/uPic/Screenshot%202026-02-27%20at%205.37.43%E2%80%AFPM.png)

**XDP ON** — before attack:

![XDP ON, before attack](https://s3.liuu.org/blog/uPic/Screenshot%202026-02-27%20at%205.38.05%E2%80%AFPM.png)

**XDP ON** — after attack:

![XDP ON, After attack](https://s3.liuu.org/blog/uPic/Screenshot%202026-02-27%20at%205.38.14%E2%80%AFPM.png)

---

### How to reproduce

```bash
# Load the kernel module
modprobe pktgen

# Configure the device (replace enp3s0 with your interface name)
PGDEV=/proc/net/pktgen/INTERFACE

echo "rem_device_all" > /proc/net/pktgen/kpktgend_0
echo "add_device INTERFACE" > /proc/net/pktgen/kpktgend_0

# Set attack parameters
echo "count 10000000" > $PGDEV             # Send 10 million packets
echo "pkt_size 64" > $PGDEV                # Small packets put more stress on the CPU
echo "dst TARGET_IP" > $PGDEV         # Target IP
echo "dst_mac TARGET_MAC" > $PGDEV  # Target MAC
echo "clone_skb 100" > $PGDEV              # Speed up packet generation
```

## 🤝 **Contributing**

Contributions are welcome! Please read our [Contributing Guide](./CONTRIBUTING.md) for details on our process for submitting pull requests and how to set up your development environment.

If you have a bug fix, performance improvement, or new feature in mind:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Commit your changes
4. Open a pull request

For bugs or questions, please [open an issue](https://github.com/Kookiejarz/Auto_XDP/issues).

---

## Star History

<a href="https://www.star-history.com/?repos=Kookiejarz%2Fauto_xdp&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/image?repos=Kookiejarz/Auto_XDP&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/image?repos=Kookiejarz/Auto_XDP&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/image?repos=Kookiejarz/Auto_XDP&type=date&legend=top-left" />
 </picture>
</a>

## 📄 License

[MIT](./LICENSE) © 2026 Yunheng Liu
