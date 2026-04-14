# Changelog

All notable changes to this project are documented in this file.


## v26.4.14 - 2026-04-14

### Changed
- **Project renamed from `basic_xdp` to `auto_xdp`**: all paths, configs, nftables tables, and service names updated accordingly.
- **CLI tool renamed from `bxdp` to `axdp`**: installed at `/usr/local/bin/axdp`.
- **Helper module renamed** from `basic_xdp_bpf_helpers.py` to `auto_xdp_bpf_helpers.py`.
- Updated all installation paths: `/etc/auto_xdp/`, `/usr/local/lib/auto_xdp/`, `/run/auto_xdp/`.
- nftables table is now `inet auto_xdp` (was `inet basic_xdp`).

---

## v26.4.13 - 2026-04-13

### Added
- ICMP Token-Bucket Rate Limiter: High-performance XDP-level protection against ICMP/Ping flood attacks.
- Smart IPv6 NDP Awareness: The rate limiter specifically targets Echo Requests while automatically whitelisting critical Neighbor Discovery Protocol (NDP) traffic (RS/RA/NS/NA) to ensure IPv6 connectivity.
- New `CNT_ICMP_DROP` counter for monitoring dropped ICMP packets via global packet counters.

### Improved
- Concurrency safety for rate limiting using `bpf_spin_lock` in XDP maps.
- Precision token refill logic using nanosecond-level time deltas to prevent over-accumulation.

## v26.4.7a - 2026-04-07

### Added
- `axdp ports` subcommand to inspect currently allowed TCP/UDP ports.
- Daemon log-level support (`--log-level`) and `axdp log-level` management command.
- Multi-distro environment checks and dry-run validation flow in installer.

### Improved
- Installer package-manager/init-system detection across Debian/Ubuntu, Fedora/RHEL, openSUSE, Arch, and Alpine.
- Runtime fallback behavior between XDP and `nftables` backends.
- Conntrack seeding and flow-tracking integration for smoother XDP reload behavior.

### Notes
- This is the first date-based public release tag for Auto XDP.
