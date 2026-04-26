"""XDP/BPF backend — syncs port whitelist and rate-limit maps directly."""
from __future__ import annotations

import logging
import os
import shutil

from auto_xdp import config as cfg
from auto_xdp.backends.base import BackendStatus, PortBackend
from auto_xdp.bpf.maps import (
    BpfAclMaps,
    BpfArrayMap,
    BpfConntrackMap,
    BpfSynRatePortsMap,
    BpfTrustedMaps,
)
from auto_xdp.services import service_name
from auto_xdp.state import AppliedState, DesiredState, ObservedState, ReconcilePlan

log = logging.getLogger(__name__)


class XdpBackend(PortBackend):
    name = cfg.BACKEND_XDP

    @classmethod
    def probe(cls) -> BackendStatus:
        checks: dict[str, bool] = {}
        details: dict[str, str] = {}

        bpftool_path = shutil.which("bpftool")
        checks["bpftool"] = bpftool_path is not None
        if bpftool_path is None:
            details["bpftool"] = "not found"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="bpftool not found",
                details=details,
                checks=checks,
            )

        missing_maps = [path for path in cfg.REQUIRED_XDP_MAP_PATHS if not os.path.exists(path)]
        checks["required_maps"] = not missing_maps
        if missing_maps:
            details["missing_maps"] = ", ".join(missing_maps)
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="required XDP maps missing",
                details=details,
                checks=checks,
            )

        if cfg.XDP_OBJ_PATH:
            checks["xdp_obj"] = os.path.exists(cfg.XDP_OBJ_PATH)
            if not checks["xdp_obj"]:
                details["xdp_obj_path"] = cfg.XDP_OBJ_PATH
                return BackendStatus(
                    name=cls.name,
                    available=False,
                    reason="configured XDP object file missing",
                    details=details,
                    checks=checks,
                )

        if cfg.TC_OBJ_PATH:
            checks["tc_obj"] = os.path.exists(cfg.TC_OBJ_PATH)
            if not checks["tc_obj"]:
                details["tc_obj_path"] = cfg.TC_OBJ_PATH
                return BackendStatus(
                    name=cls.name,
                    available=False,
                    reason="configured tc object file missing",
                    details=details,
                    checks=checks,
                )

        return BackendStatus(name=cls.name, available=True, checks=checks)

    def __init__(self) -> None:
        self.tcp_map = BpfArrayMap(cfg.TCP_MAP_PATH)
        self.udp_map = BpfArrayMap(cfg.UDP_MAP_PATH)
        self.trusted_map = BpfTrustedMaps(cfg.TRUSTED_IPS_MAP_PATH4, cfg.TRUSTED_IPS_MAP_PATH6)
        self.conntrack_map = BpfConntrackMap(cfg.TCP_CONNTRACK_MAP_PATH)
        self.udp_conntrack_map = BpfConntrackMap(cfg.UDP_CONNTRACK_MAP_PATH)
        self._conntrack_stale_rounds: dict[bytes, int] = {}
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
        udp_conntrack_map = getattr(self, "udp_conntrack_map", None)
        if udp_conntrack_map is not None:
            udp_conntrack_map.close()
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

    def get_applied_state(self) -> AppliedState:
        bogon_enabled = None
        if self.bogon_cfg_map is not None:
            bogon_enabled = bool(self.bogon_cfg_map.get(0))
        return AppliedState(
            tcp_ports=self.tcp_map.active_ports(),
            udp_ports=self.udp_map.active_ports(),
            sctp_ports=self.sctp_map.active_ports() if self.sctp_map is not None else set(),
            trusted_cidrs=self.trusted_map.active_keys(),
            conntrack_entries=self.conntrack_map.active_keys(),
            tcp_syn_rate_limits=self.syn_rate_map.active() if self.syn_rate_map is not None else {},
            tcp_syn_agg_rate_limits=self.syn_agg_rate_map.active() if self.syn_agg_rate_map is not None else {},
            tcp_conn_limits=self.tcp_conn_limit_map.active() if self.tcp_conn_limit_map is not None else {},
            udp_rate_limits=self.udp_rate_map.active() if self.udp_rate_map is not None else {},
            udp_agg_rate_limits=self.udp_agg_rate_map.active() if self.udp_agg_rate_map is not None else {},
            acl_rules=self.acl_maps.active_entries() if self.acl_maps is not None else {},
            bogon_filter_enabled=bogon_enabled,
        )

    def build_reconcile_plan(
        self,
        desired_state: DesiredState,
        applied_state: AppliedState,
    ) -> ReconcilePlan:
        if not hasattr(self, "_conntrack_stale_rounds"):
            self._conntrack_stale_rounds = {}
        plan = super().build_reconcile_plan(desired_state, applied_state)
        present_desired = self.conntrack_map.existing_keys(desired_state.conntrack_entries)
        plan.conntrack_entries_to_add = desired_state.conntrack_entries - present_desired

        for key in desired_state.conntrack_entries:
            self._conntrack_stale_rounds.pop(key, None)

        stale_ready: set[bytes] = set()
        for key in plan.conntrack_entries_to_remove:
            rounds = self._conntrack_stale_rounds.get(key, 0) + 1
            self._conntrack_stale_rounds[key] = rounds
            if rounds >= cfg.XDP_CONNTRACK_STALE_RECONCILES:
                stale_ready.add(key)

        for key in set(self._conntrack_stale_rounds) - plan.conntrack_entries_to_remove:
            self._conntrack_stale_rounds.pop(key, None)

        plan.conntrack_entries_to_remove = stale_ready
        return plan

    def apply_reconcile_plan(
        self,
        plan: ReconcilePlan,
        dry_run: bool,
        desired_state: DesiredState,
        observed_state: ObservedState | None = None,
    ) -> None:
        changed = False
        trusted_permanent = set(cfg.TRUSTED_SRC_IPS)

        for port in sorted(plan.tcp_ports_to_add):
            tag = f" [{cfg.TCP_PERMANENT[port]}]" if port in cfg.TCP_PERMANENT else ""
            if self.tcp_map.set(port, 1, dry_run):
                log.debug("TCP +%d%s", port, tag)
                changed = True

        for port in sorted(plan.tcp_ports_to_remove):
            if self.tcp_map.set(port, 0, dry_run):
                log.debug("TCP -%d  (stopped)", port)
                changed = True

        if plan.tcp_ports_to_remove:
            deleted = self.conntrack_map.delete_dest_ports(plan.tcp_ports_to_remove, dry_run)
            if deleted:
                log.info(
                    "TCP conntrack -%d entr%s for closed port(s): %s",
                    deleted,
                    "y" if deleted == 1 else "ies",
                    ", ".join(str(port) for port in sorted(plan.tcp_ports_to_remove)),
                )

        for key in plan.conntrack_entries_to_add:
            if self.conntrack_map.set(key, dry_run):
                self._conntrack_stale_rounds.pop(key, None)
                changed = True

        if plan.conntrack_entries_to_add:
            log.info("TCP conntrack +%d entr%s seeded from observed established flows.", len(plan.conntrack_entries_to_add), "y" if len(plan.conntrack_entries_to_add) == 1 else "ies")

        removed_conntrack = 0
        for key in plan.conntrack_entries_to_remove:
            if self.conntrack_map.delete(key, dry_run):
                self._conntrack_stale_rounds.pop(key, None)
                removed_conntrack += 1
                changed = True

        if removed_conntrack:
            log.info(
                "TCP conntrack -%d stale entr%s removed after repeated misses.",
                removed_conntrack,
                "y" if removed_conntrack == 1 else "ies",
            )

        for port in sorted(plan.udp_ports_to_add):
            tag = f" [{cfg.UDP_PERMANENT[port]}]" if port in cfg.UDP_PERMANENT else ""
            if self.udp_map.set(port, 1, dry_run):
                log.debug("UDP +%d%s", port, tag)
                changed = True

        for port in sorted(plan.udp_ports_to_remove):
            if self.udp_map.set(port, 0, dry_run):
                log.debug("UDP -%d  (stopped)", port)
                changed = True

        if plan.udp_ports_to_remove:
            deleted = self.udp_conntrack_map.delete_dest_ports(plan.udp_ports_to_remove, dry_run)
            if deleted:
                log.info(
                    "UDP conntrack -%d entr%s for closed port(s): %s",
                    deleted,
                    "y" if deleted == 1 else "ies",
                    ", ".join(str(port) for port in sorted(plan.udp_ports_to_remove)),
                )

        if self.sctp_map is not None:
            for port in sorted(plan.sctp_ports_to_add):
                tag = f" [{cfg.SCTP_PERMANENT[port]}]" if port in cfg.SCTP_PERMANENT else ""
                if self.sctp_map.set(port, 1, dry_run):
                    log.info("SCTP +%d%s", port, tag)
                    changed = True

            for port in sorted(plan.sctp_ports_to_remove):
                if self.sctp_map.set(port, 0, dry_run):
                    log.info("SCTP -%d  (stopped)", port)
                    changed = True

        # HASH maps need delete, not write-zero, when trust entries disappear.
        for ip_str in sorted(plan.trusted_cidrs_to_add):
            tag = f" [{cfg.TRUSTED_SRC_IPS[ip_str]}]" if ip_str in cfg.TRUSTED_SRC_IPS else ""
            if self.trusted_map.set(ip_str, 1, dry_run):
                log.info("TRUST +%s%s", ip_str, tag)
                changed = True

        for ip_str in sorted(plan.trusted_cidrs_to_remove - trusted_permanent):
            if self.trusted_map.delete(ip_str, dry_run):
                log.info("TRUST -%s  (removed)", ip_str)
                changed = True

        if not changed:
            log.debug("Whitelist up-to-date.")

        if self.syn_rate_map is not None:
            self._apply_rate_map_delta(
                self.syn_rate_map,
                plan.tcp_syn_rate_limits_to_upsert,
                plan.tcp_syn_rate_limits_to_remove,
                dry_run,
                "tcp",
                {} if observed_state is None else observed_state.tcp_processes,
            )

        if self.syn_agg_rate_map is not None:
            self._apply_rate_map_delta(
                self.syn_agg_rate_map,
                plan.tcp_syn_agg_rate_limits_to_upsert,
                plan.tcp_syn_agg_rate_limits_to_remove,
                dry_run,
                "tcp_syn_agg",
            )

        if self.tcp_conn_limit_map is not None:
            self._apply_rate_map_delta(
                self.tcp_conn_limit_map,
                plan.tcp_conn_limits_to_upsert,
                plan.tcp_conn_limits_to_remove,
                dry_run,
                "tcp_conn_limit",
            )

        if self.udp_rate_map is not None:
            self._apply_rate_map_delta(
                self.udp_rate_map,
                plan.udp_rate_limits_to_upsert,
                plan.udp_rate_limits_to_remove,
                dry_run,
                "udp",
                {} if observed_state is None else observed_state.udp_processes,
            )

        if self.udp_agg_rate_map is not None:
            self._apply_rate_map_delta(
                self.udp_agg_rate_map,
                plan.udp_agg_rate_limits_to_upsert,
                plan.udp_agg_rate_limits_to_remove,
                dry_run,
                "udp_agg",
            )

        if self.acl_maps is not None:
            self._apply_acl_delta(plan, dry_run)

        if self.bogon_cfg_map is not None and plan.bogon_filter_update is not None:
            self.bogon_cfg_map.set(0, 1 if plan.bogon_filter_update else 0, dry_run)

    def reconcile(
        self,
        desired_state: DesiredState,
        dry_run: bool,
        observed_state: ObservedState | None = None,
    ) -> None:
        stale_rounds_snapshot = dict(getattr(self, "_conntrack_stale_rounds", {}))
        try:
            super().reconcile(desired_state, dry_run, observed_state)
        finally:
            if dry_run:
                self._conntrack_stale_rounds = stale_rounds_snapshot

    def _apply_acl_delta(self, plan: ReconcilePlan, dry_run: bool) -> None:
        if self.acl_maps is None:
            return
        for (proto, cidr), ports in plan.acl_rules_to_upsert.items():
            if self.acl_maps.set(proto, cidr, sorted(ports), dry_run):
                log.info("ACL %s %s ports %s", proto.upper(), cidr, sorted(ports))

        for (proto, cidr) in plan.acl_rules_to_remove:
            if self.acl_maps.delete(proto, cidr, dry_run):
                log.info("ACL %s %s removed", proto.upper(), cidr)

    def _apply_rate_map_delta(
        self,
        rate_map: BpfSynRatePortsMap,
        upserts: dict[int, int],
        removals: set[int],
        dry_run: bool,
        kind: str,
        port_procs: dict[int, str] | None = None,
    ) -> None:
        port_procs = {} if port_procs is None else port_procs
        for port, rate_max in upserts.items():
            if rate_map.set(port, rate_max, dry_run):
                if kind == "tcp":
                    svc = port_procs.get(port) or service_name(port, "tcp") or "unknown"
                    log.info("SYN rate port %d (%s) rate_max=%d/s", port, svc, rate_max)
                elif kind == "tcp_syn_agg":
                    log.info("SYN aggregate port %d rate_max=%d/s", port, rate_max)
                elif kind == "tcp_conn_limit":
                    log.info("TCP conn limit port %d conn_max=%d", port, rate_max)
                elif kind == "udp":
                    svc = port_procs.get(port) or service_name(port, "udp") or "unknown"
                    log.info("UDP rate port %d (%s) rate_max=%d/s", port, svc, rate_max)
                elif kind == "udp_agg":
                    log.info("UDP aggregate port %d byte_rate_max=%d/s", port, rate_max)

        for port in removals:
            if rate_map.delete(port, dry_run):
                if kind == "tcp":
                    log.info("SYN rate port %d removed (port no longer whitelisted)", port)
                elif kind == "tcp_syn_agg":
                    log.info("SYN aggregate port %d removed", port)
                elif kind == "tcp_conn_limit":
                    log.info("TCP conn limit port %d removed", port)
                elif kind == "udp":
                    log.info("UDP rate port %d removed (port no longer whitelisted)", port)
                elif kind == "udp_agg":
                    log.info("UDP aggregate port %d removed", port)
