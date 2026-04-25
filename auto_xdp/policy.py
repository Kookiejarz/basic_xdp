"""Rate-limit policy resolution helpers for port sync and firewall rules."""
import socket

from auto_xdp import config as cfg

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
    try:
        svc = socket.getservbyport(port, proto)
    except OSError:
        return 0
    return service_limits.get(svc, 0)


def _port_rate_limit(port: int, proc: str = "") -> int:
    """Return the SYN rate limit for a TCP port, or 0 to skip rate limiting.

    Resolution order:
      1. Process name (_SYN_RATE_BY_PROC) — catches services on non-standard ports.
      2. IANA service name (_SYN_RATE_BY_SERVICE) — fallback for unknown processes.
      3. Anything else → 0 (no rate limit).
    """
    return _resolve_service_limit(port, "tcp", proc, _SYN_RATE_BY_PROC, _SYN_RATE_BY_SERVICE)


def _syn_aggregate_rate_limit(port: int, proc: str = "") -> int:
    limit = _resolve_service_limit(
        port, "tcp", proc, _SYN_AGG_RATE_BY_PROC, _SYN_AGG_RATE_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _port_rate_limit(port, proc)
    return base * 8 if base > 0 else 0


def _tcp_conn_limit(port: int, proc: str = "") -> int:
    limit = _resolve_service_limit(
        port, "tcp", proc, _TCP_CONN_BY_PROC, _TCP_CONN_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _port_rate_limit(port, proc)
    return max(16, base * 16) if base > 0 else 0


def _udp_port_rate_limit(port: int, proc: str = "") -> int:
    """Return the UDP rate limit for a port, or 0 to skip rate limiting."""
    return _resolve_service_limit(port, "udp", proc, _UDP_RATE_BY_PROC, _UDP_RATE_BY_SERVICE)


def _udp_aggregate_byte_limit(port: int, proc: str = "") -> int:
    limit = _resolve_service_limit(
        port, "udp", proc, _UDP_AGG_BYTES_BY_PROC, _UDP_AGG_BYTES_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _udp_port_rate_limit(port, proc)
    return base * 1200 if base > 0 else 0
