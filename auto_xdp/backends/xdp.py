"""XDP/BPF backend — syncs port whitelist and rate-limit maps directly."""
from __future__ import annotations

import logging
import os
import socket
import shutil

from auto_xdp import config as cfg
from auto_xdp.backends.base import BackendStatus, PortBackend
from auto_xdp.abuseipdb import AbuseIPDBSyncer, BpfRiskMaps
from auto_xdp.bpf.syscall import map_id, obj_get, probe_inner_map_support
from auto_xdp.bpf.maps import (
    BpfAclMaps,
    BpfArrayMap,
    BpfGlobalRlMap,
    BpfPortPolicyMap,
    BpfPortPolicyViewMap,
    BpfRateOuterMap,
    BpfRuntimeConfigMap,
    BpfSit4EndpointsMap,
    BpfSynRatePortsMap,
    BpfTrustedMaps,
    BpfZonePortMap,
    XDP_CFG_FLAG_ABUSEIPDB_ENABLED,
    XDP_CFG_FLAG_BOGON_DISABLED,
    XDP_CFG_FLAG_DROP_EVENTS_DISABLED,
    XDP_CFG_FLAG_SLOT_DROP,
)
from auto_xdp.policy import rate_map_entries_v6
from auto_xdp.services import service_name
from auto_xdp.state import AppliedState, DesiredState, ObservedState, ReconcilePlan

log = logging.getLogger(__name__)

# A rate-limit map slot holds either the standalone SYN-rate map or a per-field
# view over the shared port-policy map; both expose active()/set()/delete().
RateLimitMap = BpfSynRatePortsMap | BpfPortPolicyViewMap


def _compute_cfg_flags(desired: DesiredState) -> int:
    flags = 0
    if not desired.bogon_filter_enabled:
        flags |= XDP_CFG_FLAG_BOGON_DISABLED
    if not desired.drop_events_enabled:
        flags |= XDP_CFG_FLAG_DROP_EVENTS_DISABLED
    if cfg.ABUSEIPDB_ENABLED:
        flags |= XDP_CFG_FLAG_ABUSEIPDB_ENABLED
    if cfg.SLOT_DEFAULT_ACTION == "drop":
        flags |= XDP_CFG_FLAG_SLOT_DROP
    return flags


def _cfg_flag_bogon(m: BpfRuntimeConfigMap | None) -> bool | None:
    if m is None:
        return None
    flags = m.get_cfg_flags()
    return None if flags is None else not bool(flags & XDP_CFG_FLAG_BOGON_DISABLED)


def _cfg_flag_drop_events(m: BpfRuntimeConfigMap | None) -> bool | None:
    if m is None:
        return None
    flags = m.get_cfg_flags()
    return None if flags is None else not bool(flags & XDP_CFG_FLAG_DROP_EVENTS_DISABLED)


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

        try:
            checks["inner_map_support"] = probe_inner_map_support()
        except PermissionError:
            checks["inner_map_support"] = False
            details["inner_map_support"] = "BPF map creation denied (EPERM)"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="insufficient privileges to create BPF maps (run as root)",
                details=details,
                checks=checks,
            )
        if not checks["inner_map_support"]:
            details["inner_map_support"] = "map-in-map probe failed"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="kernel lacks ARRAY_OF_MAPS map-in-map support (need 5.10+)",
                details=details,
                checks=checks,
            )

        return BackendStatus(name=cls.name, available=True, checks=checks)

    def __init__(self) -> None:
        self.last_apply_failures: int = 0
        self.tcp_map = BpfArrayMap(cfg.TCP_MAP_PATH)
        self.udp_map = BpfArrayMap(cfg.UDP_MAP_PATH)
        self.tcp_zone_map = BpfZonePortMap(cfg.TCP_ZONE_MAP_PATH)
        self.udp_zone_map = BpfZonePortMap(cfg.UDP_ZONE_MAP_PATH)
        self.trusted_map = BpfTrustedMaps(cfg.TRUSTED_IPS_MAP_PATH4, cfg.TRUSTED_IPS_MAP_PATH6)
        self._tcp_policy_map: BpfPortPolicyMap | None = None
        self._udp_policy_map: BpfPortPolicyMap | None = None
        self.syn_rate_map: RateLimitMap | None = None
        self.syn_agg_rate_map: RateLimitMap | None = None
        self.udp_rate_map: RateLimitMap | None = None
        self.udp_agg_rate_map: RateLimitMap | None = None
        self.acl_maps: BpfAclMaps | None = None
        self.runtime_config_map: BpfRuntimeConfigMap | None = None
        self.global_rl_map: BpfGlobalRlMap | None = None
        self.sctp_map: BpfArrayMap | None = None
        try:
            self._tcp_policy_map = BpfPortPolicyMap(cfg.TCP_PORT_POLICY_MAP_PATH)
            self.syn_rate_map = BpfPortPolicyViewMap(self._tcp_policy_map, 0, cfg.TCP_PORT_POLICY_MAP_PATH)
            self.syn_agg_rate_map = BpfPortPolicyViewMap(self._tcp_policy_map, 1, cfg.TCP_PORT_POLICY_MAP_PATH)
            log.debug("tcp_port_policies map opened; TCP per-port policy active.")
        except OSError as exc:
            log.debug("tcp_port_policies map unavailable (%s); TCP per-port policy inactive.", exc)
        try:
            self._udp_policy_map = BpfPortPolicyMap(cfg.UDP_PORT_POLICY_MAP_PATH)
            self.udp_rate_map = BpfPortPolicyViewMap(self._udp_policy_map, 0, cfg.UDP_PORT_POLICY_MAP_PATH)
            self.udp_agg_rate_map = BpfPortPolicyViewMap(self._udp_policy_map, 1, cfg.UDP_PORT_POLICY_MAP_PATH)
            log.debug("udp_port_policies map opened; UDP per-port policy active.")
        except OSError as exc:
            log.debug("udp_port_policies map unavailable (%s); UDP per-port policy inactive.", exc)
        try:
            self.acl_maps = BpfAclMaps(
                cfg.TCP_ACL_MAP_PATH4, cfg.TCP_ACL_MAP_PATH6,
                cfg.UDP_ACL_MAP_PATH4, cfg.UDP_ACL_MAP_PATH6,
            )
            log.debug("ACL maps opened; per-CIDR port ACL active.")
        except OSError as exc:
            log.debug("ACL maps unavailable (%s); per-CIDR ACL inactive.", exc)
        try:
            self.runtime_config_map = BpfRuntimeConfigMap(cfg.XDP_RUNTIME_CFG_MAP_PATH)
            log.debug("xdp_runtime_cfg map opened; runtime tuning active.")
        except OSError as exc:
            log.debug("xdp_runtime_cfg map unavailable (%s); runtime tuning inactive.", exc)
        try:
            self.global_rl_map = BpfGlobalRlMap(cfg.UDP_GLOBAL_RL_MAP_PATH)
            log.debug("udp_global_rl map opened; global UDP rate limit control active.")
        except OSError as exc:
            log.debug("udp_global_rl map unavailable (%s); global UDP rate limit inactive.", exc)
        try:
            self.sctp_map = BpfArrayMap(cfg.SCTP_MAP_PATH)
            log.debug("sctp_whitelist map opened; SCTP whitelist sync active.")
        except OSError as exc:
            log.debug("sctp_whitelist map unavailable (%s); SCTP whitelist sync inactive.", exc)
        self.sit4_map: BpfSit4EndpointsMap | None = None
        try:
            self.sit4_map = BpfSit4EndpointsMap(cfg.SIT4_ENDPOINTS_MAP_PATH)
            log.debug("sit4_endpoints map opened; 6in4 tunnel endpoint control active.")
        except OSError as exc:
            log.debug("sit4_endpoints map unavailable (%s); 6in4 tunnel endpoint sync inactive.", exc)
        self.syn4_outer: BpfRateOuterMap | None = None
        self.syn6_outer: BpfRateOuterMap | None = None
        self.udprt4_outer: BpfRateOuterMap | None = None
        self.udprt6_outer: BpfRateOuterMap | None = None
        try:
            self.syn4_outer = BpfRateOuterMap(cfg.SYN4_MAP_PATH, 4, 8, "s4_")
            self.syn6_outer = BpfRateOuterMap(cfg.SYN6_MAP_PATH, 16, 8, "s6_")
            self.udprt4_outer = BpfRateOuterMap(cfg.UDPRT4_MAP_PATH, 4, 8, "u4_")
            self.udprt6_outer = BpfRateOuterMap(cfg.UDPRT6_MAP_PATH, 16, 8, "u6_")
            log.debug("rate outer maps opened; per-port rate-limit isolation active.")
        except OSError as exc:
            log.debug("rate outer maps unavailable (%s); per-port rate-limit isolation inactive.", exc)
        self._risk_maps: BpfRiskMaps | None = None
        self._abuseipdb_syncer: AbuseIPDBSyncer | None = None
        try:
            if self.runtime_config_map is not None:
                self._risk_maps = BpfRiskMaps(
                    cfg.ABUSEIPDB_RISK_MAP_PATH4,
                    self.runtime_config_map,
                )
            if cfg.ABUSEIPDB_ENABLED and self._risk_maps is not None:
                self._abuseipdb_syncer = AbuseIPDBSyncer(
                    self._risk_maps,
                    base_url=cfg.ABUSEIPDB_BASE_URL,
                    sources=cfg.ABUSEIPDB_SOURCES,
                    refresh_seconds=cfg.ABUSEIPDB_REFRESH_SECONDS,
                )
                self._abuseipdb_syncer.start()
            log.debug("AbuseIPDB risk maps opened.")
        except OSError as exc:
            log.debug("AbuseIPDB maps unavailable (%s); AbuseIPDB blocking inactive.", exc)

    def _desired_zone_entries(self, desired: DesiredState, proto: str) -> set[tuple[int, int]]:
        ports_by_zone = desired.zone_tcp_ports if proto == "tcp" else desired.zone_udp_ports
        entries: set[tuple[int, int]] = set()
        for zone, ports in ports_by_zone.items():
            for interface in cfg.ZONES.get(zone, {}).get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    log.warning("Configured zone interface does not exist: %s", interface)
                    continue
                entries.update((ifindex, port) for port in ports)
        return entries

    def _zone_state(self, zone_map: BpfZonePortMap) -> dict[str, set[int]]:
        active = zone_map.active_entries()
        result: dict[str, set[int]] = {}
        for zone, spec in cfg.ZONES.items():
            indices = set()
            for interface in spec.get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    indices.add(socket.if_nametoindex(interface))
                except OSError:
                    continue
            ports = {port for ifindex, port in active if ifindex in indices}
            if ports:
                result[zone] = ports
        return result

    def _apply_zone_delta(
        self,
        zone_map: BpfZonePortMap,
        desired_entries: set[tuple[int, int]],
        dry_run: bool,
        additions: bool,
    ) -> int:
        failures = 0
        current = zone_map.active_entries()
        entries = (desired_entries - current) if additions else (current - desired_entries)
        for ifindex, port in sorted(entries):
            ok = zone_map.set(ifindex, port, dry_run=dry_run) if additions else zone_map.delete(ifindex, port, dry_run)
            if not ok:
                failures += 1
            elif not dry_run:
                log.debug("%s zone port %s %d", "+" if additions else "-", ifindex, port)
        return failures

    def is_stale(self) -> bool:
        """Return True if the pinned tcp_whitelist map has been replaced since init."""
        try:
            fd = obj_get(cfg.TCP_MAP_PATH)
            try:
                pinned_id = map_id(fd)
            finally:
                os.close(fd)
            return pinned_id != self.tcp_map.map_id()
        except OSError:
            return False

    def close(self) -> None:
        self.tcp_map.close()
        self.udp_map.close()
        for zone_map in (getattr(self, "tcp_zone_map", None), getattr(self, "udp_zone_map", None)):
            if zone_map is not None:
                zone_map.close()
        self.trusted_map.close()
        if self._tcp_policy_map is not None:
            self._tcp_policy_map.close()
        if self._udp_policy_map is not None:
            self._udp_policy_map.close()
        if self.acl_maps is not None:
            self.acl_maps.close()
        if self.runtime_config_map is not None:
            self.runtime_config_map.close()
        if self.global_rl_map is not None:
            self.global_rl_map.close()
        if self.sctp_map is not None:
            self.sctp_map.close()
        if self.sit4_map is not None:
            self.sit4_map.close()
        for outer in (self.syn4_outer, self.syn6_outer, self.udprt4_outer, self.udprt6_outer):
            if outer is not None:
                outer.close()
        if self._abuseipdb_syncer is not None:
            self._abuseipdb_syncer.stop()
        if self._risk_maps is not None:
            self._risk_maps.close()

    def get_applied_state(self) -> AppliedState:
        return AppliedState(
            tcp_ports=self.tcp_map.active_ports(),
            udp_ports=self.udp_map.active_ports(),
            zone_tcp_ports=self._zone_state(self.tcp_zone_map) if hasattr(self, "tcp_zone_map") else {},
            zone_udp_ports=self._zone_state(self.udp_zone_map) if hasattr(self, "udp_zone_map") else {},
            sctp_ports=self.sctp_map.active_ports() if self.sctp_map is not None else set(),
            trusted_cidrs=self.trusted_map.active_keys(),
            tcp_syn_rate_limits=self.syn_rate_map.active() if self.syn_rate_map is not None else {},
            tcp_syn_agg_rate_limits=self.syn_agg_rate_map.active() if self.syn_agg_rate_map is not None else {},
            udp_rate_limits=self.udp_rate_map.active() if self.udp_rate_map is not None else {},
            udp_agg_rate_limits=self.udp_agg_rate_map.active() if self.udp_agg_rate_map is not None else {},
            acl_rules=self.acl_maps.active_entries() if self.acl_maps is not None else {},
            bogon_filter_enabled=_cfg_flag_bogon(self.runtime_config_map),
            drop_events_enabled=_cfg_flag_drop_events(self.runtime_config_map),
            udp_global_byte_rate=self.global_rl_map.get() if self.global_rl_map is not None else None,
            xdp_runtime_config=self.runtime_config_map.get() if self.runtime_config_map is not None else None,
        )

    def build_reconcile_plan(
        self,
        desired_state: DesiredState,
        applied_state: AppliedState,
    ) -> ReconcilePlan:
        plan = super().build_reconcile_plan(desired_state, applied_state)
        return plan

    def _ok(self, result: bool) -> bool:
        if not result:
            self.last_apply_failures += 1
        return result

    def verify_kernel_state(self) -> int:
        """Re-read userspace-owned config maps from the kernel and repair caches.

        Returns the total number of discrepancies found (0 = kernel matches cache).
        """
        total = 0
        total += self.tcp_map.verify()
        total += self.udp_map.verify()
        for zone_map in (getattr(self, "tcp_zone_map", None), getattr(self, "udp_zone_map", None)):
            if zone_map is not None:
                total += zone_map.verify()
        if self.sctp_map is not None:
            total += self.sctp_map.verify()
        total += self.trusted_map.verify()
        if self._tcp_policy_map is not None:
            total += self._tcp_policy_map.verify()
        if self._udp_policy_map is not None:
            total += self._udp_policy_map.verify()
        if self.acl_maps is not None:
            total += self.acl_maps.verify()
        if self.sit4_map is not None:
            total += self.sit4_map.verify()
        for outer in (self.syn4_outer, self.syn6_outer, self.udprt4_outer, self.udprt6_outer):
            if outer is not None:
                total += outer.verify()
        if total:
            log.warning(
                "Kernel state verification found %d drifted map entr%s; caches repaired, corrective sync recommended.",
                total, "y" if total == 1 else "ies",
            )
        return total

    def apply_reconcile_plan(
        self,
        plan: ReconcilePlan,
        dry_run: bool,
        desired_state: DesiredState,
        observed_state: ObservedState | None = None,
    ) -> None:
        self.last_apply_failures = 0
        changed = False
        for port in sorted(plan.tcp_ports_to_remove):
            if self._ok(self.tcp_map.set(port, 0, dry_run)):
                log.debug("TCP -%d  (stopped)", port)
                changed = True

        for port in sorted(plan.udp_ports_to_remove):
            if self._ok(self.udp_map.set(port, 0, dry_run)):
                log.debug("UDP -%d  (stopped)", port)
                changed = True

        if self.sctp_map is not None:
            for port in sorted(plan.sctp_ports_to_add):
                if self._ok(self.sctp_map.set(port, 1, dry_run)):
                    log.info("SCTP +%d", port)
                    changed = True

            for port in sorted(plan.sctp_ports_to_remove):
                if self._ok(self.sctp_map.set(port, 0, dry_run)):
                    log.info("SCTP -%d  (stopped)", port)
                    changed = True

        # HASH maps need delete, not write-zero, when trust entries disappear.
        for ip_str in sorted(plan.trusted_cidrs_to_add):
            tag = f" [{cfg.TRUSTED_SRC_IPS[ip_str]}]" if ip_str in cfg.TRUSTED_SRC_IPS else ""
            if self._ok(self.trusted_map.set(ip_str, 1, dry_run)):
                log.info("TRUST +%s%s", ip_str, tag)
                changed = True

        for ip_str in sorted(plan.trusted_cidrs_to_remove):
            if self._ok(self.trusted_map.delete(ip_str, dry_run)):
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

        tcp_entries = desired_state.tcp_rate_map_entries
        udp_entries = desired_state.udp_rate_map_entries
        if self.syn4_outer is not None:
            self._apply_rate_outer_delta(self.syn4_outer, tcp_entries, dry_run)
        if self.syn6_outer is not None:
            self._apply_rate_outer_delta(
                self.syn6_outer,
                {p: rate_map_entries_v6(c) for p, c in tcp_entries.items()},
                dry_run,
            )
        if self.udprt4_outer is not None:
            self._apply_rate_outer_delta(self.udprt4_outer, udp_entries, dry_run)
        if self.udprt6_outer is not None:
            self._apply_rate_outer_delta(
                self.udprt6_outer,
                {p: rate_map_entries_v6(c) for p, c in udp_entries.items()},
                dry_run,
            )

        if self._tcp_policy_map is not None:
            tcp_policy_ports = (
                set(desired_state.tcp_syn_rate_limits)
                | set(desired_state.tcp_syn_agg_rate_limits)
            )
            self._tcp_policy_map.ensure_prefixes(
                tcp_policy_ports,
                desired_state.rate_limit_source_prefix_v4,
                desired_state.rate_limit_source_prefix_v6,
                dry_run,
            )

        if self._udp_policy_map is not None:
            udp_policy_ports = set(desired_state.udp_rate_limits) | set(desired_state.udp_agg_rate_limits)
            self._udp_policy_map.ensure_prefixes(
                udp_policy_ports,
                desired_state.rate_limit_source_prefix_v4,
                desired_state.rate_limit_source_prefix_v6,
                dry_run,
            )

        if self.acl_maps is not None:
            self._apply_acl_delta(plan, dry_run)

        if self.runtime_config_map is not None:
            cfg_flags = _compute_cfg_flags(desired_state)
            current = self.runtime_config_map.get()
            current_flags = self.runtime_config_map.get_cfg_flags() or 0
            if desired_state.xdp_runtime_config != current or cfg_flags != current_flags:
                self._ok(self.runtime_config_map.set(desired_state.xdp_runtime_config, cfg_flags, dry_run))

        if self.global_rl_map is not None and plan.udp_global_byte_rate_update is not None:
            rate = plan.udp_global_byte_rate_update
            if self._ok(self.global_rl_map.set(rate, dry_run)):
                if rate:
                    log.info("UDP global rate limit set to %d bytes/s", rate)
                else:
                    log.info("UDP global rate limit disabled")

        if self.sit4_map is not None:
            desired_sit4 = set(cfg.SIT4_ENDPOINTS)
            current_sit4 = self.sit4_map.active_keys()
            for ip_str in sorted(desired_sit4 - current_sit4):
                if self._ok(self.sit4_map.set(ip_str, dry_run)):
                    log.info("SIT4 +%s (6in4 tunnel endpoint added)", ip_str)
            for ip_str in sorted(current_sit4 - desired_sit4):
                if self._ok(self.sit4_map.delete(ip_str, dry_run)):
                    log.info("SIT4 -%s (6in4 tunnel endpoint removed)", ip_str)

        # BPF maps do not provide a transaction.  Prepare all protection state
        # first, then expose new TCP/UDP ports only if that preparation passed.
        # A failed map update leaves the port closed and is retried next round.
        if self.last_apply_failures:
            if plan.tcp_ports_to_add or plan.udp_ports_to_add:
                log.warning(
                    "Keeping new TCP/UDP ports closed because protection setup "
                    "failed (%d map update failure(s)).",
                    self.last_apply_failures,
                )
        else:
            for port in sorted(plan.tcp_ports_to_add):
                if self._ok(self.tcp_map.set(port, 1, dry_run)):
                    log.debug("TCP +%d", port)
                    changed = True

            for port in sorted(plan.udp_ports_to_add):
                if self._ok(self.udp_map.set(port, 1, dry_run)):
                    log.debug("UDP +%d", port)
                    changed = True

        if self.last_apply_failures and not dry_run:
            log.warning(
                "%d BPF map update%s failed this reconcile; kernel state may lag desired state.",
                self.last_apply_failures,
                "" if self.last_apply_failures == 1 else "s",
            )

    def reconcile(
        self,
        desired_state: DesiredState,
        dry_run: bool,
        observed_state: ObservedState | None = None,
    ) -> None:
        self.last_apply_failures = 0
        zone_maps = (
            (getattr(self, "tcp_zone_map", None), self._desired_zone_entries(desired_state, "tcp")),
            (getattr(self, "udp_zone_map", None), self._desired_zone_entries(desired_state, "udp")),
        )
        zone_failures = 0
        if not zone_failures:
            zone_failures += sum(
                self._apply_zone_delta(zone_map, entries, dry_run, additions=False)
                for zone_map, entries in zone_maps if zone_map is not None
            )
        super().reconcile(desired_state, dry_run, observed_state)
        if not zone_failures and not self.last_apply_failures:
            zone_failures += (
                sum(
                    self._apply_zone_delta(zone_map, entries, dry_run, additions=True)
                    for zone_map, entries in zone_maps if zone_map is not None
                )
            )
        self.last_apply_failures += zone_failures

    def _apply_acl_delta(self, plan: ReconcilePlan, dry_run: bool) -> None:
        if self.acl_maps is None:
            return
        for (proto, cidr), ports in plan.acl_rules_to_upsert.items():
            if self._ok(self.acl_maps.set(proto, cidr, sorted(ports), dry_run)):
                log.info("ACL %s %s ports %s", proto.upper(), cidr, sorted(ports))

        for (proto, cidr) in plan.acl_rules_to_remove:
            if self._ok(self.acl_maps.delete(proto, cidr, dry_run)):
                log.info("ACL %s %s removed", proto.upper(), cidr)

    def _apply_rate_outer_delta(
        self,
        outer: BpfRateOuterMap,
        desired: dict[int, int],
        dry_run: bool,
    ) -> None:
        current = outer.active()
        for port, capacity in desired.items():
            if current.get(port) != capacity:
                self._ok(outer.set(port, capacity, dry_run))
        for port in set(current) - set(desired):
            self._ok(outer.delete(port, dry_run))

    def _apply_rate_map_delta(
        self,
        rate_map: RateLimitMap,
        upserts: dict[int, int],
        removals: set[int],
        dry_run: bool,
        kind: str,
        port_procs: dict[int, str] | None = None,
    ) -> None:
        port_procs = {} if port_procs is None else port_procs
        for port, rate_max in upserts.items():
            if self._ok(rate_map.set(port, rate_max, dry_run)):
                if kind == "tcp":
                    svc = port_procs.get(port) or service_name(port, "tcp") or "unknown"
                    log.info("SYN rate port %d (%s) rate_max=%d/s", port, svc, rate_max)
                elif kind == "tcp_syn_agg":
                    log.info("SYN aggregate port %d rate_max=%d/s", port, rate_max)
                elif kind == "udp":
                    svc = port_procs.get(port) or service_name(port, "udp") or "unknown"
                    log.info("UDP rate port %d (%s) rate_max=%d/s", port, svc, rate_max)
                elif kind == "udp_agg":
                    log.info("UDP aggregate port %d byte_rate_max=%d/s", port, rate_max)

        for port in removals:
            if self._ok(rate_map.delete(port, dry_run)):
                if kind == "tcp":
                    log.info("SYN rate port %d removed (port no longer whitelisted)", port)
                elif kind == "tcp_syn_agg":
                    log.info("SYN aggregate port %d removed", port)
                elif kind == "udp":
                    log.info("UDP rate port %d removed (port no longer whitelisted)", port)
                elif kind == "udp_agg":
                    log.info("UDP aggregate port %d removed", port)
