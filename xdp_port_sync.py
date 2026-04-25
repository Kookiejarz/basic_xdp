#!/usr/bin/env python3
"""Port whitelist auto-sync daemon.

Port discovery  : psutil  (reads /proc directly, no subprocesses)
XDP backend     : bpf(2) syscall via ctypes  (no bpftool)
Fallback        : nftables dynamic sets
Event trigger   : Linux Netlink Process Connector (EXEC/EXIT)
Fallback poll   : periodic scan every --interval seconds (default 30)
"""
from __future__ import annotations

import argparse
import logging
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

from auto_xdp import config as cfg
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.bpf.maps import (
    BpfAclMaps,
    BpfArrayMap,
    BpfConntrackMap,
    BpfSynRatePortsMap,
    BpfTrustedMaps,
    render_nft_addrs as _render_nft_addrs,
    render_nft_ports as _render_nft_ports,
    run_nft as _run_nft,
)
from auto_xdp.discovery import (
    PortState,
    get_listening_ports,
    _listening_port_processes,
    _net_connections,
)
from auto_xdp.policy import (
    _port_rate_limit,
    _syn_aggregate_rate_limit,
    _tcp_conn_limit,
    _udp_port_rate_limit,
    _udp_aggregate_byte_limit,
)

TOML_CONFIG_PATH = cfg.TOML_CONFIG_PATH
TCP_MAP_PATH = cfg.TCP_MAP_PATH
UDP_MAP_PATH = cfg.UDP_MAP_PATH
SCTP_MAP_PATH = cfg.SCTP_MAP_PATH
TCP_CONNTRACK_MAP_PATH = cfg.TCP_CONNTRACK_MAP_PATH
TRUSTED_IPS_MAP_PATH4 = cfg.TRUSTED_IPS_MAP_PATH4
TRUSTED_IPS_MAP_PATH6 = cfg.TRUSTED_IPS_MAP_PATH6
SYN_RATE_MAP_PATH = cfg.SYN_RATE_MAP_PATH
UDP_RATE_MAP_PATH = cfg.UDP_RATE_MAP_PATH
SYN_AGG_RATE_MAP_PATH = cfg.SYN_AGG_RATE_MAP_PATH
TCP_CONN_LIMIT_MAP_PATH = cfg.TCP_CONN_LIMIT_MAP_PATH
UDP_AGG_RATE_MAP_PATH = cfg.UDP_AGG_RATE_MAP_PATH
UDP_GLOBAL_RL_MAP_PATH = cfg.UDP_GLOBAL_RL_MAP_PATH
BOGON_CFG_MAP_PATH = cfg.BOGON_CFG_MAP_PATH
TCP_ACL_MAP_PATH4 = cfg.TCP_ACL_MAP_PATH4
TCP_ACL_MAP_PATH6 = cfg.TCP_ACL_MAP_PATH6
UDP_ACL_MAP_PATH4 = cfg.UDP_ACL_MAP_PATH4
UDP_ACL_MAP_PATH6 = cfg.UDP_ACL_MAP_PATH6
REQUIRED_XDP_MAP_PATHS = cfg.REQUIRED_XDP_MAP_PATHS
NFT_FAMILY = cfg.NFT_FAMILY
NFT_TABLE = cfg.NFT_TABLE
NFT_TCP_SET = cfg.NFT_TCP_SET
NFT_UDP_SET = cfg.NFT_UDP_SET
NFT_SCTP_SET = cfg.NFT_SCTP_SET
NFT_TRUSTED_SET4 = cfg.NFT_TRUSTED_SET4
NFT_TRUSTED_SET6 = cfg.NFT_TRUSTED_SET6
BACKEND_AUTO = cfg.BACKEND_AUTO
BACKEND_XDP = cfg.BACKEND_XDP
BACKEND_NFTABLES = cfg.BACKEND_NFTABLES
TCP_PERMANENT = cfg.TCP_PERMANENT
UDP_PERMANENT = cfg.UDP_PERMANENT
SCTP_PERMANENT = cfg.SCTP_PERMANENT
TRUSTED_SRC_IPS = cfg.TRUSTED_SRC_IPS
ACL_RULES = cfg.ACL_RULES
_SYN_RATE_BY_PROC = cfg._SYN_RATE_BY_PROC
_SYN_RATE_BY_SERVICE = cfg._SYN_RATE_BY_SERVICE
_SYN_AGG_RATE_BY_PROC = cfg._SYN_AGG_RATE_BY_PROC
_SYN_AGG_RATE_BY_SERVICE = cfg._SYN_AGG_RATE_BY_SERVICE
_TCP_CONN_BY_PROC = cfg._TCP_CONN_BY_PROC
_TCP_CONN_BY_SERVICE = cfg._TCP_CONN_BY_SERVICE
_UDP_RATE_BY_PROC = cfg._UDP_RATE_BY_PROC
_UDP_RATE_BY_SERVICE = cfg._UDP_RATE_BY_SERVICE
_UDP_AGG_BYTES_BY_PROC = cfg._UDP_AGG_BYTES_BY_PROC
_UDP_AGG_BYTES_BY_SERVICE = cfg._UDP_AGG_BYTES_BY_SERVICE
DISCOVERY_EXCLUDE_BIND_CIDRS = cfg.DISCOVERY_EXCLUDE_BIND_CIDRS
_ACL_MAX_PORTS = cfg.ACL_MAX_PORTS


# Wait this long after an EXEC/EXIT event before scanning,
# giving the new process time to call bind().
DEBOUNCE_S = 0.4

DEFAULT_LOG_LEVEL = os.environ.get("BASIC_XDP_LOG_LEVEL", "WARNING").upper()

logging.basicConfig(
    level=getattr(logging, DEFAULT_LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


class PortBackend:
    name = "backend"

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        sctp_target: set[int],
        trusted_target: set[str],
        conntrack_target: set[bytes],
        dry_run: bool,
        cached_conns=None,
    ) -> None:
        raise NotImplementedError

    def close(self) -> None:
        return None


class XdpBackend(PortBackend):
    name = BACKEND_XDP

    def __init__(self) -> None:
        self.tcp_map = BpfArrayMap(TCP_MAP_PATH)
        self.udp_map = BpfArrayMap(UDP_MAP_PATH)
        self.trusted_map = BpfTrustedMaps(TRUSTED_IPS_MAP_PATH4, TRUSTED_IPS_MAP_PATH6)
        self.conntrack_map = BpfConntrackMap(TCP_CONNTRACK_MAP_PATH)
        self.syn_rate_map: BpfSynRatePortsMap | None = None
        self.syn_agg_rate_map: BpfSynRatePortsMap | None = None
        self.tcp_conn_limit_map: BpfSynRatePortsMap | None = None
        self.udp_rate_map: BpfSynRatePortsMap | None = None
        self.udp_agg_rate_map: BpfSynRatePortsMap | None = None
        self.acl_maps: BpfAclMaps | None = None
        self.bogon_cfg_map: BpfArrayMap | None = None
        self.sctp_map: BpfArrayMap | None = None
        try:
            self.syn_rate_map = BpfSynRatePortsMap(SYN_RATE_MAP_PATH)
            log.debug("syn_rate_ports map opened; per-service SYN rate limiting active.")
        except OSError as exc:
            log.debug("syn_rate_ports map unavailable (%s); SYN rate limiting inactive.", exc)
        try:
            self.syn_agg_rate_map = BpfSynRatePortsMap(SYN_AGG_RATE_MAP_PATH)
            log.debug("syn_agg_rate_ports map opened; per-prefix SYN aggregate limiting active.")
        except OSError as exc:
            log.debug("syn_agg_rate_ports map unavailable (%s); per-prefix SYN aggregate limiting inactive.", exc)
        try:
            self.tcp_conn_limit_map = BpfSynRatePortsMap(TCP_CONN_LIMIT_MAP_PATH)
            log.debug("tcp_conn_limit_ports map opened; per-source TCP concurrency limits active.")
        except OSError as exc:
            log.debug("tcp_conn_limit_ports map unavailable (%s); TCP concurrency limits inactive.", exc)
        try:
            self.udp_rate_map = BpfSynRatePortsMap(UDP_RATE_MAP_PATH)
            log.debug("udp_rate_ports map opened; per-source UDP rate limiting active.")
        except OSError as exc:
            log.debug("udp_rate_ports map unavailable (%s); UDP rate limiting inactive.", exc)
        try:
            self.udp_agg_rate_map = BpfSynRatePortsMap(UDP_AGG_RATE_MAP_PATH)
            log.debug("udp_agg_rate_ports map opened; byte-based UDP aggregate limiting active.")
        except OSError as exc:
            log.debug("udp_agg_rate_ports map unavailable (%s); byte-based UDP aggregate limiting inactive.", exc)
        try:
            self.acl_maps = BpfAclMaps(
                TCP_ACL_MAP_PATH4, TCP_ACL_MAP_PATH6,
                UDP_ACL_MAP_PATH4, UDP_ACL_MAP_PATH6,
            )
            log.debug("ACL maps opened; per-CIDR port ACL active.")
        except OSError as exc:
            log.debug("ACL maps unavailable (%s); per-CIDR ACL inactive.", exc)
        try:
            self.bogon_cfg_map = BpfArrayMap(BOGON_CFG_MAP_PATH)
        except OSError as exc:
            log.debug("bogon_cfg map unavailable (%s); bogon filter toggle inactive.", exc)
        try:
            self.sctp_map = BpfArrayMap(SCTP_MAP_PATH)
            log.debug("sctp_whitelist map opened; SCTP whitelist sync active.")
        except OSError as exc:
            log.debug("sctp_whitelist map unavailable (%s); SCTP whitelist sync inactive.", exc)

    def close(self) -> None:
        self.tcp_map.close()
        self.udp_map.close()
        self.trusted_map.close()
        self.conntrack_map.close()
        if self.syn_rate_map is not None:
            self.syn_rate_map.close()
        if self.syn_agg_rate_map is not None:
            self.syn_agg_rate_map.close()
        if self.tcp_conn_limit_map is not None:
            self.tcp_conn_limit_map.close()
        if self.udp_rate_map is not None:
            self.udp_rate_map.close()
        if self.udp_agg_rate_map is not None:
            self.udp_agg_rate_map.close()
        if self.acl_maps is not None:
            self.acl_maps.close()
        if self.bogon_cfg_map is not None:
            self.bogon_cfg_map.close()
        if self.sctp_map is not None:
            self.sctp_map.close()

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        sctp_target: set[int],
        trusted_target: set[str],
        conntrack_target: set[bytes],
        dry_run: bool,
        cached_conns=None,
    ) -> None:
        changed = False
        tcp_permanent = set(TCP_PERMANENT)
        udp_permanent = set(UDP_PERMANENT)
        sctp_permanent = set(SCTP_PERMANENT)
        trusted_permanent = set(TRUSTED_SRC_IPS)
        active_tcp = self.tcp_map.active_ports()
        active_udp = self.udp_map.active_ports()
        active_sctp = self.sctp_map.active_ports() if self.sctp_map is not None else set()
        active_trusted = self.trusted_map.active_keys()
        _ = conntrack_target

        for port in sorted(tcp_target - active_tcp):
            tag = f" [{TCP_PERMANENT[port]}]" if port in TCP_PERMANENT else ""
            if self.tcp_map.set(port, 1, dry_run):
                log.debug("TCP +%d%s", port, tag)
                changed = True

        for port in sorted(active_tcp - tcp_target - tcp_permanent):
            if self.tcp_map.set(port, 0, dry_run):
                log.debug("TCP -%d  (stopped)", port)
                changed = True

        for port in sorted(udp_target - active_udp):
            tag = f" [{UDP_PERMANENT[port]}]" if port in UDP_PERMANENT else ""
            if self.udp_map.set(port, 1, dry_run):
                log.debug("UDP +%d%s", port, tag)
                changed = True

        for port in sorted(active_udp - udp_target - udp_permanent):
            if self.udp_map.set(port, 0, dry_run):
                log.debug("UDP -%d  (stopped)", port)
                changed = True

        if self.sctp_map is not None:
            for port in sorted(sctp_target - active_sctp):
                tag = f" [{SCTP_PERMANENT[port]}]" if port in SCTP_PERMANENT else ""
                if self.sctp_map.set(port, 1, dry_run):
                    log.info("SCTP +%d%s", port, tag)
                    changed = True

            for port in sorted(active_sctp - sctp_target - sctp_permanent):
                if self.sctp_map.set(port, 0, dry_run):
                    log.info("SCTP -%d  (stopped)", port)
                    changed = True

        # HASH maps need delete, not write-zero, when trust entries disappear.
        for ip_str in sorted(trusted_target - active_trusted):
            tag = f" [{TRUSTED_SRC_IPS[ip_str]}]" if ip_str in TRUSTED_SRC_IPS else ""
            if self.trusted_map.set(ip_str, 1, dry_run):
                log.info("TRUST +%s%s", ip_str, tag)
                changed = True

        for ip_str in sorted(active_trusted - trusted_target - trusted_permanent):
            if self.trusted_map.delete(ip_str, dry_run):
                log.info("TRUST -%s  (removed)", ip_str)
                changed = True

        if not changed:
            log.debug("Whitelist up-to-date.")

        # Sync per-port SYN rate limits based on detected service types.
        if self.syn_rate_map is not None:
            self._sync_syn_rate(tcp_target, dry_run, cached_conns)

        if self.syn_agg_rate_map is not None:
            self._sync_syn_agg_rate(tcp_target, dry_run, cached_conns)

        if self.tcp_conn_limit_map is not None:
            self._sync_tcp_conn_limit(tcp_target, dry_run, cached_conns)

        if self.udp_rate_map is not None:
            self._sync_udp_rate(udp_target, dry_run, cached_conns)

        if self.udp_agg_rate_map is not None:
            self._sync_udp_agg_rate(udp_target, dry_run, cached_conns)

        if self.acl_maps is not None:
            self._sync_acl(dry_run)

        if self.bogon_cfg_map is not None:
            self.bogon_cfg_map.set(0, 1 if cfg.BOGON_FILTER_ENABLED else 0, dry_run)

    def _sync_acl(self, dry_run: bool) -> None:
        if self.acl_maps is None:
            return
        desired: dict[tuple[str, str], frozenset[int]] = {}
        for rule in ACL_RULES:
            proto = rule["proto"]
            cidr = rule["cidr"]
            ports = rule["ports"]
            if not ports:
                continue
            key = (proto, cidr)
            desired[key] = frozenset(ports)

        active = self.acl_maps.active_entries()

        for (proto, cidr), ports in desired.items():
            if active.get((proto, cidr)) != ports:
                if self.acl_maps.set(proto, cidr, sorted(ports), dry_run):
                    log.info("ACL %s %s ports %s", proto.upper(), cidr, sorted(ports))

        for (proto, cidr) in set(active) - set(desired):
            if self.acl_maps.delete(proto, cidr, dry_run):
                log.info("ACL %s %s removed", proto.upper(), cidr)

    def _sync_syn_rate(self, tcp_ports: set[int], dry_run: bool, cached_conns=None) -> None:
        """Update syn_rate_ports to match the current set of whitelisted TCP ports."""
        active = self.syn_rate_map.active()  # type: ignore[union-attr]
        port_procs = _listening_port_processes(tcp_ports, socket.SOCK_STREAM, cached_conns)

        # Desired state: port → rate_max (skip ports where rate=0, i.e. web).
        desired: dict[int, int] = {}
        for port in tcp_ports:
            rate = _port_rate_limit(port, port_procs.get(port, ""))
            if rate > 0:
                desired[port] = rate

        for port, rate_max in desired.items():
            if active.get(port) != rate_max:
                if self.syn_rate_map.set(port, rate_max, dry_run):  # type: ignore[union-attr]
                    svc: str = port_procs.get(port, "")
                    if not svc:
                        try:
                            svc = socket.getservbyport(port, "tcp")
                        except OSError:
                            svc = "unknown"
                    log.info("SYN rate port %d (%s) rate_max=%d/s", port, svc, rate_max)

        for port in set(active) - set(desired):
            if self.syn_rate_map.delete(port, dry_run):  # type: ignore[union-attr]
                log.info("SYN rate port %d removed (port no longer whitelisted)", port)

    def _sync_syn_agg_rate(self, tcp_ports: set[int], dry_run: bool, cached_conns=None) -> None:
        active = self.syn_agg_rate_map.active()  # type: ignore[union-attr]
        port_procs = _listening_port_processes(tcp_ports, socket.SOCK_STREAM, cached_conns)
        desired: dict[int, int] = {}
        for port in tcp_ports:
            limit = _syn_aggregate_rate_limit(port, port_procs.get(port, ""))
            if limit > 0:
                desired[port] = limit

        for port, limit in desired.items():
            if active.get(port) != limit:
                if self.syn_agg_rate_map.set(port, limit, dry_run):  # type: ignore[union-attr]
                    log.info("SYN aggregate port %d rate_max=%d/s", port, limit)

        for port in set(active) - set(desired):
            if self.syn_agg_rate_map.delete(port, dry_run):  # type: ignore[union-attr]
                log.info("SYN aggregate port %d removed", port)

    def _sync_tcp_conn_limit(self, tcp_ports: set[int], dry_run: bool, cached_conns=None) -> None:
        active = self.tcp_conn_limit_map.active()  # type: ignore[union-attr]
        port_procs = _listening_port_processes(tcp_ports, socket.SOCK_STREAM, cached_conns)
        desired: dict[int, int] = {}
        for port in tcp_ports:
            limit = _tcp_conn_limit(port, port_procs.get(port, ""))
            if limit > 0:
                desired[port] = limit

        for port, limit in desired.items():
            if active.get(port) != limit:
                if self.tcp_conn_limit_map.set(port, limit, dry_run):  # type: ignore[union-attr]
                    log.info("TCP conn limit port %d conn_max=%d", port, limit)

        for port in set(active) - set(desired):
            if self.tcp_conn_limit_map.delete(port, dry_run):  # type: ignore[union-attr]
                log.info("TCP conn limit port %d removed", port)

    def _sync_udp_rate(self, udp_ports: set[int], dry_run: bool, cached_conns=None) -> None:
        """Update udp_rate_ports to match the current set of whitelisted UDP ports."""
        active = self.udp_rate_map.active()  # type: ignore[union-attr]
        port_procs = _listening_port_processes(udp_ports, socket.SOCK_DGRAM, cached_conns)

        desired: dict[int, int] = {}
        for port in udp_ports:
            rate = _udp_port_rate_limit(port, port_procs.get(port, ""))
            if rate > 0:
                desired[port] = rate

        for port, rate_max in desired.items():
            if active.get(port) != rate_max:
                if self.udp_rate_map.set(port, rate_max, dry_run):  # type: ignore[union-attr]
                    try:
                        svc = socket.getservbyport(port, "udp")
                    except OSError:
                        svc = "unknown"
                    log.info("UDP rate port %d (%s) rate_max=%d/s", port, svc, rate_max)

        for port in set(active) - set(desired):
            if self.udp_rate_map.delete(port, dry_run):  # type: ignore[union-attr]
                log.info("UDP rate port %d removed (port no longer whitelisted)", port)

    def _sync_udp_agg_rate(self, udp_ports: set[int], dry_run: bool, cached_conns=None) -> None:
        active = self.udp_agg_rate_map.active()  # type: ignore[union-attr]
        port_procs = _listening_port_processes(udp_ports, socket.SOCK_DGRAM, cached_conns)

        desired: dict[int, int] = {}
        for port in udp_ports:
            limit = _udp_aggregate_byte_limit(port, port_procs.get(port, ""))
            if limit > 0:
                desired[port] = limit

        for port, limit in desired.items():
            if active.get(port) != limit:
                if self.udp_agg_rate_map.set(port, limit, dry_run):  # type: ignore[union-attr]
                    log.info("UDP aggregate port %d byte_rate_max=%d/s", port, limit)

        for port in set(active) - set(desired):
            if self.udp_agg_rate_map.delete(port, dry_run):  # type: ignore[union-attr]
                log.info("UDP aggregate port %d removed", port)


class NftablesBackend(PortBackend):
    name = BACKEND_NFTABLES

    def __init__(self) -> None:
        if shutil.which("nft") is None:
            raise RuntimeError("nft command not found")
        self._tcp_cache: set[int] = set()
        self._udp_cache: set[int] = set()
        self._sctp_cache: set[int] = set()
        self._trusted_cache: set[str] = set()
        self._ensure_ruleset()

    def _ensure_ruleset(self) -> None:
        result = _run_nft(["list", "table", NFT_FAMILY, NFT_TABLE], check=False)
        if result.returncode == 0:
            body = result.stdout
            if all(marker in body for marker in (
                f"set {NFT_TCP_SET}", f"set {NFT_UDP_SET}", f"set {NFT_SCTP_SET}",
                f"set {NFT_TRUSTED_SET4}", "chain input",
            )):
                return
            _run_nft(["delete", "table", NFT_FAMILY, NFT_TABLE], check=True)

        script = f"""table {NFT_FAMILY} {NFT_TABLE} {{
    set {NFT_TCP_SET} {{
        type inet_service
    }}

    set {NFT_UDP_SET} {{
        type inet_service
    }}

    set {NFT_SCTP_SET} {{
        type inet_service
    }}

    set {NFT_TRUSTED_SET4} {{
        type ipv4_addr
        flags interval
    }}

    set {NFT_TRUSTED_SET6} {{
        type ipv6_addr
        flags interval
    }}

    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "lo" accept
        ct state established,related accept
        ip saddr @{NFT_TRUSTED_SET4} accept
        ip6 saddr @{NFT_TRUSTED_SET6} accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        tcp flags & (ack | rst | fin) != 0 accept
        tcp flags & (syn | ack) == syn tcp dport @{NFT_TCP_SET} accept
        udp sport {{ 53, 67, 123, 443, 547 }} accept
        udp dport @{NFT_UDP_SET} accept
        sctp dport @{NFT_SCTP_SET} accept
        counter drop
    }}
}}
"""
        _run_nft(["-f", "-"], input_text=script, check=True)

    def _apply_targets(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        sctp_target: set[int],
        dry_run: bool,
    ) -> None:
        lines = [
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_TCP_SET}",
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_UDP_SET}",
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_SCTP_SET}",
        ]
        if tcp_target:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_TCP_SET} {_render_nft_ports(tcp_target)}"
            )
        if udp_target:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_UDP_SET} {_render_nft_ports(udp_target)}"
            )
        if sctp_target:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_SCTP_SET} {_render_nft_ports(sctp_target)}"
            )
        script = "\n".join(lines) + "\n"

        if dry_run:
            for line in lines:
                log.info("[DRY] nft %s", line)
            return

        try:
            _run_nft(["-f", "-"], input_text=script, check=True)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else str(exc)
            raise RuntimeError(f"nftables update failed: {stderr}") from exc

    def _apply_trusted(self, trusted_target: set[str], dry_run: bool) -> None:
        v4 = {a for a in trusted_target if ":" not in a}
        v6 = {a for a in trusted_target if ":" in a}
        lines = [
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_TRUSTED_SET4}",
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_TRUSTED_SET6}",
        ]
        if v4:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_TRUSTED_SET4} {_render_nft_addrs(v4)}"
            )
        if v6:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_TRUSTED_SET6} {_render_nft_addrs(v6)}"
            )
        script = "\n".join(lines) + "\n"
        if dry_run:
            for line in lines:
                log.info("[DRY] nft %s", line)
            return
        try:
            _run_nft(["-f", "-"], input_text=script, check=True)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else str(exc)
            raise RuntimeError(f"nftables trusted-ip update failed: {stderr}") from exc

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        sctp_target: set[int],
        trusted_target: set[str],
        conntrack_target: set[bytes],
        dry_run: bool,
        cached_conns=None,
    ) -> None:
        changed = False
        _ = conntrack_target  # kernel conntrack handles established flows natively

        for ip_str in sorted(trusted_target - self._trusted_cache):
            tag = f" [{TRUSTED_SRC_IPS[ip_str]}]" if ip_str in TRUSTED_SRC_IPS else ""
            log.info("TRUST +%s%s", ip_str, tag)
            changed = True
        for ip_str in sorted(self._trusted_cache - trusted_target):
            log.info("TRUST -%s  (removed)", ip_str)
            changed = True

        for port in sorted(tcp_target - self._tcp_cache):
            tag = f" [{TCP_PERMANENT[port]}]" if port in TCP_PERMANENT else ""
            log.info("TCP +%d%s", port, tag)
            changed = True
        for port in sorted(self._tcp_cache - tcp_target - set(TCP_PERMANENT)):
            log.info("TCP -%d  (stopped)", port)
            changed = True

        for port in sorted(udp_target - self._udp_cache):
            tag = f" [{UDP_PERMANENT[port]}]" if port in UDP_PERMANENT else ""
            log.info("UDP +%d%s", port, tag)
            changed = True
        for port in sorted(self._udp_cache - udp_target - set(UDP_PERMANENT)):
            log.info("UDP -%d  (stopped)", port)
            changed = True

        for port in sorted(sctp_target - self._sctp_cache):
            tag = f" [{SCTP_PERMANENT[port]}]" if port in SCTP_PERMANENT else ""
            log.info("SCTP +%d%s", port, tag)
            changed = True
        for port in sorted(self._sctp_cache - sctp_target - set(SCTP_PERMANENT)):
            log.info("SCTP -%d  (stopped)", port)
            changed = True

        self._apply_targets(tcp_target, udp_target, sctp_target, dry_run)
        self._apply_trusted(trusted_target, dry_run)
        self._tcp_cache = set(tcp_target)
        self._udp_cache = set(udp_target)
        self._sctp_cache = set(sctp_target)
        self._trusted_cache = set(trusted_target)

        if not changed:
            log.debug("Whitelist up-to-date.")


def sync_once(backend: PortBackend, dry_run: bool) -> None:
    try:
        all_conns = _net_connections(kind="inet") if (_net_connections is not None) else []
    except Exception:
        all_conns = []
    current = get_listening_ports(cached_conns=all_conns)
    tcp_target = current.tcp | set(TCP_PERMANENT)
    udp_target = current.udp | set(UDP_PERMANENT)
    sctp_target = current.sctp | set(SCTP_PERMANENT)
    trusted_target = set(TRUSTED_SRC_IPS)
    conntrack_target: set[bytes] = set()
    backend.sync_ports(tcp_target, udp_target, sctp_target, trusted_target, conntrack_target, dry_run, cached_conns=all_conns)


_NETLINK_CONNECTOR = 11
_CN_IDX_PROC = 1
_NLMSG_HDRLEN = 16
_CN_MSG_HDRLEN = 20
_NLMSG_MIN_TYPE = 0x10
_PROC_CN_MCAST_LISTEN = 1
_PROC_EVENT_EXEC = 0x00000002
_PROC_EVENT_EXIT = 0x80000000


def _make_subscribe_msg(pid: int) -> bytes:
    op = struct.pack("I", _PROC_CN_MCAST_LISTEN)
    cn = struct.pack("IIIIHH", _CN_IDX_PROC, 1, 0, 0, len(op), 0) + op
    hdr = struct.pack("IHHII", _NLMSG_HDRLEN + len(cn), _NLMSG_MIN_TYPE, 0, 0, pid)
    return hdr + cn


def open_proc_connector():
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_CONNECTOR)
        sock.bind((os.getpid(), _CN_IDX_PROC))
        sock.send(_make_subscribe_msg(os.getpid()))
        log.info("Netlink proc connector active -> event-driven mode.")
        return sock
    except OSError as exc:
        log.warning("Netlink unavailable (%s); falling back to poll-only mode.", exc)
        return None


def drain_proc_events(sock: socket.socket) -> bool:
    """Drain buffered netlink messages; return True if any EXEC/EXIT was seen."""
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
                idx = struct.unpack_from("I", data, cn_off)[0]
                cn_data = cn_off + _CN_MSG_HDRLEN
                if idx == _CN_IDX_PROC and cn_data + 4 <= offset + nl_len:
                    what = struct.unpack_from("I", data, cn_data)[0]
                    if what in (_PROC_EVENT_EXEC, _PROC_EVENT_EXIT):
                        triggered = True
            offset += (nl_len + 3) & ~3
    return triggered


def open_backend(name: str) -> PortBackend:
    missing_xdp_maps = [path for path in REQUIRED_XDP_MAP_PATHS if not os.path.exists(path)]

    if name == BACKEND_XDP:
        if missing_xdp_maps:
            raise RuntimeError(f"required XDP maps missing: {', '.join(missing_xdp_maps)}")
        return XdpBackend()
    if name == BACKEND_NFTABLES:
        return NftablesBackend()
    if name != BACKEND_AUTO:
        raise RuntimeError(f"Unsupported backend: {name}")

    if not missing_xdp_maps:
        try:
            backend = XdpBackend()
            log.info("Backend selected: xdp")
            return backend
        except OSError as exc:
            log.warning("XDP backend unavailable (%s); trying nftables.", exc)
    elif missing_xdp_maps:
        log.warning("XDP maps incomplete (%s); trying nftables.", ", ".join(missing_xdp_maps))

    backend = NftablesBackend()
    log.info("Backend selected: nftables")
    return backend


def watch(interval: int, dry_run: bool, backend_name: str, config_path: str = TOML_CONFIG_PATH, cli_trusted_ips: dict[str, str] | None = None, cli_log_level: str | None = None) -> None:
    backend = None
    nl = None

    last_sync_t = 0.0
    last_event_t = 0.0
    reload_requested = False

    def _on_sighup(signum: int, frame: object) -> None:
        nonlocal reload_requested
        reload_requested = True

    signal.signal(signal.SIGHUP, _on_sighup)

    try:
        while True:
            # Re-initialize backend if needed
            if backend is None:
                try:
                    backend = open_backend(backend_name)
                    log.info("Backend initialized.")
                    # Force a sync after (re)initialization
                    sync_once(backend, dry_run)
                    last_sync_t = time.monotonic()
                    last_event_t = 0.0
                except Exception as exc:
                    log.error("Failed to open backend: %s. Retrying in 5s...", exc)
                    time.sleep(5)
                    continue

            # Re-subscribe to netlink if needed
            if nl is None:
                nl = open_proc_connector()

            now = time.monotonic()
            poll_due = last_sync_t + interval
            deb_due = (last_event_t + DEBOUNCE_S) if last_event_t else float("inf")
            sleep_for = max(0.05, min(poll_due, deb_due) - now)

            try:
                if nl and not last_event_t:
                    rdy, _, _ = select.select([nl], [], [], sleep_for)
                    if rdy and drain_proc_events(nl):
                        log.debug("Proc event -> debounce armed.")
                        last_event_t = time.monotonic()
                else:
                    time.sleep(sleep_for)
            except OSError as exc:
                log.warning("Netlink error (%s); switching to poll-only mode.", exc)
                if nl:
                    nl.close()
                nl = None
                continue

            if reload_requested:
                reload_requested = False
                log.warning("SIGHUP received — reloading config from %s", config_path)
                apply_toml_config(load_toml_config(config_path))
                if cli_trusted_ips:
                    TRUSTED_SRC_IPS.update(cli_trusted_ips)
                if cli_log_level is None:
                    _lvl = getattr(logging, cfg.LOG_LEVEL.upper(), logging.WARNING)
                    logging.getLogger().setLevel(_lvl)
                    log.setLevel(_lvl)
                last_sync_t = 0.0  # force sync on next iteration

            now = time.monotonic()
            debounce_fired = bool(last_event_t) and (now - last_event_t >= DEBOUNCE_S)
            fallback_fired = now - last_sync_t >= interval

            if debounce_fired or fallback_fired:
                if nl:
                    drain_proc_events(nl)
                log.debug("Sync triggered by %s.", "event" if debounce_fired else "poll")
                try:
                    sync_once(backend, dry_run)
                except Exception as exc:
                    log.error("Sync error: %s", exc)
                    # If it's a BPF/backend error, reset it for re-init
                    if isinstance(exc, (OSError, RuntimeError)):
                        log.warning("Backend may be broken; will attempt to re-initialize.")
                        backend.close()
                        backend = None

                last_sync_t = time.monotonic()
                last_event_t = 0.0

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        if backend:
            backend.close()


def main() -> None:
    def _parse_trusted_ip(ip_str: str) -> str:
        try:
            return cfg.normalize_cidr(ip_str)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"invalid IPv4/IPv6 address or CIDR: {ip_str}"
            ) from None

    p = argparse.ArgumentParser(description="Auto XDP port-whitelist sync daemon")
    p.add_argument(
        "--backend",
        choices=[BACKEND_AUTO, BACKEND_XDP, BACKEND_NFTABLES],
        default=BACKEND_AUTO,
        help="Sync backend to use (default: auto)",
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="Run as a daemon (event-driven + fallback poll)",
    )
    p.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Fallback poll interval in seconds (default: 30)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print operations without executing them",
    )
    p.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default=None,
        help="Set daemon log level (default: read from config.toml [daemon] log_level)",
    )
    p.add_argument(
        "--trusted-ip",
        action="append",
        nargs=2,
        metavar=("IP", "LABEL"),
        default=[],
        help="Add a trusted IPv4/IPv6 source IP or CIDR and label (repeatable)",
    )
    p.add_argument(
        "--config",
        default=TOML_CONFIG_PATH,
        metavar="PATH",
        help=f"TOML config file path (default: {TOML_CONFIG_PATH})",
    )
    args = p.parse_args()

    apply_toml_config(load_toml_config(args.config))

    # CLI --log-level wins; fall back to TOML [daemon] log_level.
    effective_level = (args.log_level or cfg.LOG_LEVEL).upper()
    logging.getLogger().setLevel(getattr(logging, effective_level, logging.WARNING))
    log.setLevel(getattr(logging, effective_level, logging.WARNING))

    cli_trusted_ips: dict[str, str] = {}
    try:
        for ip_str, label in args.trusted_ip:
            cidr = _parse_trusted_ip(ip_str)
            TRUSTED_SRC_IPS[cidr] = label
            cli_trusted_ips[cidr] = label
    except argparse.ArgumentTypeError as exc:
        p.error(str(exc))

    backend = None
    try:
        if args.watch:
            watch(args.interval, args.dry_run, args.backend, args.config, cli_trusted_ips, cli_log_level=args.log_level)
        else:
            backend = open_backend(args.backend)
            sync_once(backend, args.dry_run)
            log.info("Sync completed.")
    finally:
        if backend is not None:
            backend.close()


if __name__ == "__main__":
    main()
