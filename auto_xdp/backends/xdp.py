"""XDP/BPF backend — syncs port whitelist and rate-limit maps directly."""
from __future__ import annotations

import logging
import socket

from auto_xdp import config as cfg
from auto_xdp.backends.base import PortBackend
from auto_xdp.bpf.maps import (
    BpfAclMaps,
    BpfArrayMap,
    BpfConntrackMap,
    BpfSynRatePortsMap,
    BpfTrustedMaps,
)
from auto_xdp.discovery import _listening_port_processes
from auto_xdp.policy import (
    _port_rate_limit,
    _syn_aggregate_rate_limit,
    _tcp_conn_limit,
    _udp_port_rate_limit,
    _udp_aggregate_byte_limit,
)

log = logging.getLogger(__name__)


class XdpBackend(PortBackend):
    name = cfg.BACKEND_XDP

    def __init__(self) -> None:
        self.tcp_map = BpfArrayMap(cfg.TCP_MAP_PATH)
        self.udp_map = BpfArrayMap(cfg.UDP_MAP_PATH)
        self.trusted_map = BpfTrustedMaps(cfg.TRUSTED_IPS_MAP_PATH4, cfg.TRUSTED_IPS_MAP_PATH6)
        self.conntrack_map = BpfConntrackMap(cfg.TCP_CONNTRACK_MAP_PATH)
        self.syn_rate_map: BpfSynRatePortsMap | None = None
        self.syn_agg_rate_map: BpfSynRatePortsMap | None = None
        self.tcp_conn_limit_map: BpfSynRatePortsMap | None = None
        self.udp_rate_map: BpfSynRatePortsMap | None = None
        self.udp_agg_rate_map: BpfSynRatePortsMap | None = None
        self.acl_maps: BpfAclMaps | None = None
        self.bogon_cfg_map: BpfArrayMap | None = None
        self.sctp_map: BpfArrayMap | None = None
        try:
            self.syn_rate_map = BpfSynRatePortsMap(cfg.SYN_RATE_MAP_PATH)
            log.debug("syn_rate_ports map opened; per-service SYN rate limiting active.")
        except OSError as exc:
            log.debug("syn_rate_ports map unavailable (%s); SYN rate limiting inactive.", exc)
        try:
            self.syn_agg_rate_map = BpfSynRatePortsMap(cfg.SYN_AGG_RATE_MAP_PATH)
            log.debug("syn_agg_rate_ports map opened; per-prefix SYN aggregate limiting active.")
        except OSError as exc:
            log.debug("syn_agg_rate_ports map unavailable (%s); per-prefix SYN aggregate limiting inactive.", exc)
        try:
            self.tcp_conn_limit_map = BpfSynRatePortsMap(cfg.TCP_CONN_LIMIT_MAP_PATH)
            log.debug("tcp_conn_limit_ports map opened; per-source TCP concurrency limits active.")
        except OSError as exc:
            log.debug("tcp_conn_limit_ports map unavailable (%s); TCP concurrency limits inactive.", exc)
        try:
            self.udp_rate_map = BpfSynRatePortsMap(cfg.UDP_RATE_MAP_PATH)
            log.debug("udp_rate_ports map opened; per-source UDP rate limiting active.")
        except OSError as exc:
            log.debug("udp_rate_ports map unavailable (%s); UDP rate limiting inactive.", exc)
        try:
            self.udp_agg_rate_map = BpfSynRatePortsMap(cfg.UDP_AGG_RATE_MAP_PATH)
            log.debug("udp_agg_rate_ports map opened; byte-based UDP aggregate limiting active.")
        except OSError as exc:
            log.debug("udp_agg_rate_ports map unavailable (%s); byte-based UDP aggregate limiting inactive.", exc)
        try:
            self.acl_maps = BpfAclMaps(
                cfg.TCP_ACL_MAP_PATH4, cfg.TCP_ACL_MAP_PATH6,
                cfg.UDP_ACL_MAP_PATH4, cfg.UDP_ACL_MAP_PATH6,
            )
            log.debug("ACL maps opened; per-CIDR port ACL active.")
        except OSError as exc:
            log.debug("ACL maps unavailable (%s); per-CIDR ACL inactive.", exc)
        try:
            self.bogon_cfg_map = BpfArrayMap(cfg.BOGON_CFG_MAP_PATH)
        except OSError as exc:
            log.debug("bogon_cfg map unavailable (%s); bogon filter toggle inactive.", exc)
        try:
            self.sctp_map = BpfArrayMap(cfg.SCTP_MAP_PATH)
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
        tcp_permanent = set(cfg.TCP_PERMANENT)
        udp_permanent = set(cfg.UDP_PERMANENT)
        sctp_permanent = set(cfg.SCTP_PERMANENT)
        trusted_permanent = set(cfg.TRUSTED_SRC_IPS)
        active_tcp = self.tcp_map.active_ports()
        active_udp = self.udp_map.active_ports()
        active_sctp = self.sctp_map.active_ports() if self.sctp_map is not None else set()
        active_trusted = self.trusted_map.active_keys()
        _ = conntrack_target

        for port in sorted(tcp_target - active_tcp):
            tag = f" [{cfg.TCP_PERMANENT[port]}]" if port in cfg.TCP_PERMANENT else ""
            if self.tcp_map.set(port, 1, dry_run):
                log.debug("TCP +%d%s", port, tag)
                changed = True

        for port in sorted(active_tcp - tcp_target - tcp_permanent):
            if self.tcp_map.set(port, 0, dry_run):
                log.debug("TCP -%d  (stopped)", port)
                changed = True

        for port in sorted(udp_target - active_udp):
            tag = f" [{cfg.UDP_PERMANENT[port]}]" if port in cfg.UDP_PERMANENT else ""
            if self.udp_map.set(port, 1, dry_run):
                log.debug("UDP +%d%s", port, tag)
                changed = True

        for port in sorted(active_udp - udp_target - udp_permanent):
            if self.udp_map.set(port, 0, dry_run):
                log.debug("UDP -%d  (stopped)", port)
                changed = True

        if self.sctp_map is not None:
            for port in sorted(sctp_target - active_sctp):
                tag = f" [{cfg.SCTP_PERMANENT[port]}]" if port in cfg.SCTP_PERMANENT else ""
                if self.sctp_map.set(port, 1, dry_run):
                    log.info("SCTP +%d%s", port, tag)
                    changed = True

            for port in sorted(active_sctp - sctp_target - sctp_permanent):
                if self.sctp_map.set(port, 0, dry_run):
                    log.info("SCTP -%d  (stopped)", port)
                    changed = True

        # HASH maps need delete, not write-zero, when trust entries disappear.
        for ip_str in sorted(trusted_target - active_trusted):
            tag = f" [{cfg.TRUSTED_SRC_IPS[ip_str]}]" if ip_str in cfg.TRUSTED_SRC_IPS else ""
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
        for rule in cfg.ACL_RULES:
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
