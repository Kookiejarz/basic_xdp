"""Shared observed/desired state models for sync reconciliation."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RuntimeEndpoint:
    """A live endpoint and the evidence used to attribute it."""

    protocol: str
    host_address: str
    host_port: int
    bind_scope: str
    ingress_zone: str = "unknown"
    subject: str = ""
    attribution_state: str = "unknown"
    attribution_source: str = ""
    container_runtime: str = ""
    container_id: str = ""
    container_name: str = ""
    container_labels: dict[str, str] = field(default_factory=dict)
    # Socket inode (Linux) or pid/fd pair (fallback), used to distinguish a
    # restarted listener even when debounce hides the closed intermediate state.
    instance_id: str = ""

    @property
    def key(self) -> tuple[str, str, int, str]:
        return self.protocol, self.host_address, self.host_port, self.ingress_zone


@dataclass
class ExposureDecision:
    """Explain why one observed endpoint is or is not effective."""

    endpoint: RuntimeEndpoint
    action: str
    reason: str
    subject: str = ""
    protection_profile: str = ""


@dataclass
class ObservedState:
    """Facts discovered from the local system."""

    tcp: set[int] = field(default_factory=set)
    udp: set[int] = field(default_factory=set)
    sctp: set[int] = field(default_factory=set)
    tcp_processes: dict[int, str] = field(default_factory=dict)
    udp_processes: dict[int, str] = field(default_factory=dict)
    udp_sock_opts: dict[int, frozenset[str]] = field(default_factory=dict)
    endpoints: list[RuntimeEndpoint] = field(default_factory=list)


@dataclass
class DesiredState:
    """Policy-resolved target state to apply to the active backend."""

    tcp_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)
    sctp_ports: set[int] = field(default_factory=set)
    trusted_cidrs: set[str] = field(default_factory=set)
    tcp_syn_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    # Per-port rate-limit inner map capacities (v4 entries); only ports whose
    # tcp_syn/udp rate resolves > 0 get an entry.
    tcp_rate_map_entries: dict[int, int] = field(default_factory=dict)
    udp_rate_map_entries: dict[int, int] = field(default_factory=dict)
    acl_rules: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    bogon_filter_enabled: bool = False
    drop_events_enabled: bool = True
    rate_limit_source_prefix_v4: int = 32
    rate_limit_source_prefix_v6: int = 128
    udp_global_byte_rate: int = 0
    exposure_decisions: list[ExposureDecision] = field(default_factory=list)
    zone_tcp_ports: dict[str, set[int]] = field(default_factory=dict)
    zone_udp_ports: dict[str, set[int]] = field(default_factory=dict)
    # Endpoint protection identity is zone-scoped; a port is only transport
    # addressing and may intentionally use a different policy on another NIC.
    tcp_protection_profiles: dict[tuple[str, int], str] = field(default_factory=dict)
    xdp_runtime_config: tuple[int, int, int, int, int, int, int, int] = (
        0,
        0,
        0,
        100,
        10_000_000,
        1_000_000_000,
        1_000_000_000,
        0,
    )


@dataclass
class AppliedState:
    """Backend-observed state currently applied in the kernel/runtime."""

    tcp_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)
    sctp_ports: set[int] = field(default_factory=set)
    trusted_cidrs: set[str] = field(default_factory=set)
    tcp_syn_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    acl_rules: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    bogon_filter_enabled: bool | None = None
    drop_events_enabled: bool | None = None
    rate_limit_source_prefix_v4: int = 32
    rate_limit_source_prefix_v6: int = 128
    udp_global_byte_rate: int | None = None
    xdp_runtime_config: tuple[int, int, int, int, int, int, int, int] | None = None
    zone_tcp_ports: dict[str, set[int]] = field(default_factory=dict)
    zone_udp_ports: dict[str, set[int]] = field(default_factory=dict)


@dataclass
class ReconcilePlan:
    tcp_ports_to_add: set[int] = field(default_factory=set)
    tcp_ports_to_remove: set[int] = field(default_factory=set)
    udp_ports_to_add: set[int] = field(default_factory=set)
    udp_ports_to_remove: set[int] = field(default_factory=set)
    sctp_ports_to_add: set[int] = field(default_factory=set)
    sctp_ports_to_remove: set[int] = field(default_factory=set)
    trusted_cidrs_to_add: set[str] = field(default_factory=set)
    trusted_cidrs_to_remove: set[str] = field(default_factory=set)
    tcp_syn_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    tcp_syn_rate_limits_to_remove: set[int] = field(default_factory=set)
    tcp_syn_agg_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits_to_remove: set[int] = field(default_factory=set)
    udp_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    udp_rate_limits_to_remove: set[int] = field(default_factory=set)
    udp_agg_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits_to_remove: set[int] = field(default_factory=set)
    acl_rules_to_upsert: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    acl_rules_to_remove: set[tuple[str, str]] = field(default_factory=set)
    bogon_filter_update: bool | None = None
    drop_events_update: bool | None = None
    udp_global_byte_rate_update: int | None = None


def _dict_upserts(desired: dict[int, int], applied: dict[int, int]) -> dict[int, int]:
    return {key: value for key, value in desired.items() if applied.get(key) != value}


def _dict_removals(desired: dict[int, int], applied: dict[int, int]) -> set[int]:
    return set(applied) - set(desired)


def _acl_upserts(
    desired: dict[tuple[str, str], frozenset[int]],
    applied: dict[tuple[str, str], frozenset[int]],
) -> dict[tuple[str, str], frozenset[int]]:
    return {key: ports for key, ports in desired.items() if applied.get(key) != ports}


def compute_reconcile_plan(desired: DesiredState, applied: AppliedState) -> ReconcilePlan:
    plan = ReconcilePlan(
        tcp_ports_to_add=desired.tcp_ports - applied.tcp_ports,
        tcp_ports_to_remove=applied.tcp_ports - desired.tcp_ports,
        udp_ports_to_add=desired.udp_ports - applied.udp_ports,
        udp_ports_to_remove=applied.udp_ports - desired.udp_ports,
        sctp_ports_to_add=desired.sctp_ports - applied.sctp_ports,
        sctp_ports_to_remove=applied.sctp_ports - desired.sctp_ports,
        trusted_cidrs_to_add=desired.trusted_cidrs - applied.trusted_cidrs,
        trusted_cidrs_to_remove=applied.trusted_cidrs - desired.trusted_cidrs,
        tcp_syn_rate_limits_to_upsert=_dict_upserts(
            desired.tcp_syn_rate_limits, applied.tcp_syn_rate_limits
        ),
        tcp_syn_rate_limits_to_remove=_dict_removals(
            desired.tcp_syn_rate_limits, applied.tcp_syn_rate_limits
        ),
        tcp_syn_agg_rate_limits_to_upsert=_dict_upserts(
            desired.tcp_syn_agg_rate_limits, applied.tcp_syn_agg_rate_limits
        ),
        tcp_syn_agg_rate_limits_to_remove=_dict_removals(
            desired.tcp_syn_agg_rate_limits, applied.tcp_syn_agg_rate_limits
        ),
        udp_rate_limits_to_upsert=_dict_upserts(
            desired.udp_rate_limits, applied.udp_rate_limits
        ),
        udp_rate_limits_to_remove=_dict_removals(
            desired.udp_rate_limits, applied.udp_rate_limits
        ),
        udp_agg_rate_limits_to_upsert=_dict_upserts(
            desired.udp_agg_rate_limits, applied.udp_agg_rate_limits
        ),
        udp_agg_rate_limits_to_remove=_dict_removals(
            desired.udp_agg_rate_limits, applied.udp_agg_rate_limits
        ),
        acl_rules_to_upsert=_acl_upserts(desired.acl_rules, applied.acl_rules),
        acl_rules_to_remove=set(applied.acl_rules) - set(desired.acl_rules),
    )
    if applied.bogon_filter_enabled is None or applied.bogon_filter_enabled != desired.bogon_filter_enabled:
        plan.bogon_filter_update = desired.bogon_filter_enabled
    if applied.drop_events_enabled is None or applied.drop_events_enabled != desired.drop_events_enabled:
        plan.drop_events_update = desired.drop_events_enabled
    if applied.udp_global_byte_rate is None or applied.udp_global_byte_rate != desired.udp_global_byte_rate:
        plan.udp_global_byte_rate_update = desired.udp_global_byte_rate
    return plan
