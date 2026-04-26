"""Shared observed/desired state models for sync reconciliation."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ObservedState:
    """Facts discovered from the local system."""

    tcp: set[int] = field(default_factory=set)
    udp: set[int] = field(default_factory=set)
    sctp: set[int] = field(default_factory=set)
    established: set[bytes] = field(default_factory=set)
    tcp_processes: dict[int, str] = field(default_factory=dict)
    udp_processes: dict[int, str] = field(default_factory=dict)


@dataclass
class DesiredState:
    """Policy-resolved target state to apply to the active backend."""

    tcp_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)
    sctp_ports: set[int] = field(default_factory=set)
    trusted_cidrs: set[str] = field(default_factory=set)
    conntrack_entries: set[bytes] = field(default_factory=set)
    tcp_syn_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_conn_limits: dict[int, int] = field(default_factory=dict)
    udp_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    acl_rules: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    bogon_filter_enabled: bool = False


@dataclass
class AppliedState:
    """Backend-observed state currently applied in the kernel/runtime."""

    tcp_ports: set[int] = field(default_factory=set)
    udp_ports: set[int] = field(default_factory=set)
    sctp_ports: set[int] = field(default_factory=set)
    trusted_cidrs: set[str] = field(default_factory=set)
    conntrack_entries: set[bytes] = field(default_factory=set)
    tcp_syn_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    tcp_conn_limits: dict[int, int] = field(default_factory=dict)
    udp_rate_limits: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits: dict[int, int] = field(default_factory=dict)
    acl_rules: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    bogon_filter_enabled: bool | None = None


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
    conntrack_entries_to_add: set[bytes] = field(default_factory=set)
    conntrack_entries_to_remove: set[bytes] = field(default_factory=set)
    tcp_syn_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    tcp_syn_rate_limits_to_remove: set[int] = field(default_factory=set)
    tcp_syn_agg_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    tcp_syn_agg_rate_limits_to_remove: set[int] = field(default_factory=set)
    tcp_conn_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    tcp_conn_limits_to_remove: set[int] = field(default_factory=set)
    udp_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    udp_rate_limits_to_remove: set[int] = field(default_factory=set)
    udp_agg_rate_limits_to_upsert: dict[int, int] = field(default_factory=dict)
    udp_agg_rate_limits_to_remove: set[int] = field(default_factory=set)
    acl_rules_to_upsert: dict[tuple[str, str], frozenset[int]] = field(default_factory=dict)
    acl_rules_to_remove: set[tuple[str, str]] = field(default_factory=set)
    bogon_filter_update: bool | None = None

    def is_noop(self) -> bool:
        return not any((
            self.tcp_ports_to_add,
            self.tcp_ports_to_remove,
            self.udp_ports_to_add,
            self.udp_ports_to_remove,
            self.sctp_ports_to_add,
            self.sctp_ports_to_remove,
            self.trusted_cidrs_to_add,
            self.trusted_cidrs_to_remove,
            self.conntrack_entries_to_add,
            self.conntrack_entries_to_remove,
            self.tcp_syn_rate_limits_to_upsert,
            self.tcp_syn_rate_limits_to_remove,
            self.tcp_syn_agg_rate_limits_to_upsert,
            self.tcp_syn_agg_rate_limits_to_remove,
            self.tcp_conn_limits_to_upsert,
            self.tcp_conn_limits_to_remove,
            self.udp_rate_limits_to_upsert,
            self.udp_rate_limits_to_remove,
            self.udp_agg_rate_limits_to_upsert,
            self.udp_agg_rate_limits_to_remove,
            self.acl_rules_to_upsert,
            self.acl_rules_to_remove,
            self.bogon_filter_update is not None,
        ))


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
        conntrack_entries_to_add=desired.conntrack_entries - applied.conntrack_entries,
        conntrack_entries_to_remove=applied.conntrack_entries - desired.conntrack_entries,
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
        tcp_conn_limits_to_upsert=_dict_upserts(
            desired.tcp_conn_limits, applied.tcp_conn_limits
        ),
        tcp_conn_limits_to_remove=_dict_removals(
            desired.tcp_conn_limits, applied.tcp_conn_limits
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
    return plan
