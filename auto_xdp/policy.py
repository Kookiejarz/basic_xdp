"""Rate-limit policy resolution helpers for port sync and firewall rules."""

from auto_xdp import config as cfg
from auto_xdp.services import service_name
from auto_xdp.state import DesiredState, ObservedState


def _resolve_service_limit(
    port: int,
    proto: str,
    proc: str,
    proc_limits: dict[str, int],
    service_limits: dict[str, int],
) -> int:
    if proc:
        limit = proc_limits.get(proc)
        if limit is not None:
            return limit
    svc = service_name(port, proto)
    if not svc:
        return 0
    return service_limits.get(svc, 0)


def _port_rate_limit(port: int, proc: str = "") -> int:
    """Return the SYN rate limit for a TCP port, or 0 to skip rate limiting.

    Resolution order:
      1. Process name (_SYN_RATE_BY_PROC) — catches services on non-standard ports.
      2. IANA service name (_SYN_RATE_BY_SERVICE) — fallback for unknown processes.
      3. Anything else → 0 (no rate limit).
    """
    return _resolve_service_limit(port, "tcp", proc, cfg._SYN_RATE_BY_PROC, cfg._SYN_RATE_BY_SERVICE)


def _syn_aggregate_rate_limit(port: int, proc: str = "") -> int:
    limit = _resolve_service_limit(
        port, "tcp", proc, cfg._SYN_AGG_RATE_BY_PROC, cfg._SYN_AGG_RATE_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _port_rate_limit(port, proc)
    return base * 8 if base > 0 else 0


def _tcp_conn_limit(port: int, proc: str = "") -> int:
    limit = _resolve_service_limit(
        port, "tcp", proc, cfg._TCP_CONN_BY_PROC, cfg._TCP_CONN_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _port_rate_limit(port, proc)
    return max(16, base * 16) if base > 0 else 0


def _udp_port_rate_limit(port: int, proc: str = "") -> int:
    """Return the UDP rate limit for a port, or 0 to skip rate limiting."""
    return _resolve_service_limit(port, "udp", proc, cfg._UDP_RATE_BY_PROC, cfg._UDP_RATE_BY_SERVICE)


def _udp_aggregate_byte_limit(port: int, proc: str = "") -> int:
    limit = _resolve_service_limit(
        port, "udp", proc, cfg._UDP_AGG_BYTES_BY_PROC, cfg._UDP_AGG_BYTES_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _udp_port_rate_limit(port, proc)
    return base * 1200 if base > 0 else 0


def _resolve_port_limits(
    ports: set[int],
    process_names: dict[int, str],
    resolver,
) -> dict[int, int]:
    desired: dict[int, int] = {}
    for port in ports:
        limit = resolver(port, process_names.get(port, ""))
        if limit > 0:
            desired[port] = limit
    return desired


def _desired_acl_rules() -> dict[tuple[str, str], frozenset[int]]:
    desired: dict[tuple[str, str], frozenset[int]] = {}
    for rule in cfg.ACL_RULES:
        proto = rule["proto"]
        cidr = rule["cidr"]
        ports = rule["ports"]
        if not ports:
            continue
        desired[(proto, cidr)] = frozenset(ports)
    return desired


def resolve_desired_state(observed: ObservedState) -> DesiredState:
    tcp_ports = set(observed.tcp) | set(cfg.TCP_PERMANENT)
    udp_ports = set(observed.udp) | set(cfg.UDP_PERMANENT)
    sctp_ports = set(observed.sctp) | set(cfg.SCTP_PERMANENT)

    return DesiredState(
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        sctp_ports=sctp_ports,
        trusted_cidrs=set(cfg.TRUSTED_SRC_IPS),
        conntrack_entries=set(observed.established),
        tcp_syn_rate_limits=_resolve_port_limits(tcp_ports, observed.tcp_processes, _port_rate_limit),
        tcp_syn_agg_rate_limits=_resolve_port_limits(
            tcp_ports, observed.tcp_processes, _syn_aggregate_rate_limit
        ),
        tcp_conn_limits=_resolve_port_limits(tcp_ports, observed.tcp_processes, _tcp_conn_limit),
        udp_rate_limits=_resolve_port_limits(udp_ports, observed.udp_processes, _udp_port_rate_limit),
        udp_agg_rate_limits=_resolve_port_limits(
            udp_ports, observed.udp_processes, _udp_aggregate_byte_limit
        ),
        acl_rules=_desired_acl_rules(),
        bogon_filter_enabled=cfg.BOGON_FILTER_ENABLED,
    )
