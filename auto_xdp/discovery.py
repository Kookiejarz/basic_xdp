"""Port discovery: reads listening sockets via psutil, applies exposure filters."""
from __future__ import annotations

import ipaddress
import logging
import socket
import struct
import sys

try:
    import psutil
except ImportError:
    psutil = None

from auto_xdp import config as cfg
from auto_xdp.state import ObservedState

log = logging.getLogger(__name__)

# psutil 6.0 renamed net_connections() -> connections()
_net_connections = None
if psutil is not None:
    _net_connections = getattr(psutil, "connections", psutil.net_connections)


def _pack_tcp_conntrack_key(conn) -> bytes:
    if conn.family == socket.AF_INET:
        family = socket.AF_INET
        remote_ip = socket.inet_aton(conn.raddr.ip) + (b"\x00" * 12)
        local_ip = socket.inet_aton(conn.laddr.ip) + (b"\x00" * 12)
    else:
        family = socket.AF_INET6
        remote_ip = socket.inet_pton(socket.AF_INET6, conn.raddr.ip)
        local_ip = socket.inet_pton(socket.AF_INET6, conn.laddr.ip)
    return struct.pack("!B3xHH16s16s", family, conn.raddr.port, conn.laddr.port, remote_ip, local_ip)


def _listening_port_processes(
    ports: set[int],
    conn_type: int,
    cached_conns=None,
    pid_names: dict[int, str] | None = None,
) -> dict[int, str]:
    port_procs: dict[int, str] = {}
    pid_names = {} if pid_names is None else pid_names
    if psutil is None or _net_connections is None or not ports:
        return port_procs
    try:
        for conn in (cached_conns if cached_conns is not None else _net_connections(kind="inet")):
            if not (conn.laddr and conn.laddr.port in ports):
                continue
            if conn.type != conn_type:
                continue
            if conn_type == socket.SOCK_STREAM:
                if getattr(conn, "status", None) != psutil.CONN_LISTEN:
                    continue
            elif getattr(conn, "raddr", None):
                continue
            pid = getattr(conn, "pid", None)
            if pid is None:
                continue
            if pid not in pid_names:
                try:
                    pid_names[pid] = psutil.Process(pid).name()
                except Exception:
                    pid_names[pid] = ""
            if pid_names[pid]:
                port_procs[conn.laddr.port] = pid_names[pid]
    except Exception:
        pass
    return port_procs


def _discovery_exclude_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cfg.DISCOVERY_EXCLUDE_BIND_CIDRS:
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            log.warning("Ignoring invalid discovery exclude_bind_cidrs entry: %s", cidr)
    return tuple(nets)


def _bind_ip_is_exposed(
    ip_str: str,
    exclude_nets: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    # Wildcard binds mean "all addresses" and should be treated as externally reachable.
    if ip_str in ("0.0.0.0", "::", "*"):
        return True
    try:
        addr = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        # If the address is malformed or uses an unexpected format, fail open.
        return True
    if cfg.DISCOVERY_EXCLUDE_LOOPBACK and addr.is_loopback:
        return False
    for net in exclude_nets:
        if addr.version == net.version and addr in net:
            return False
    return True


def get_listening_ports(cached_conns=None) -> ObservedState:
    """Read externally reachable listening TCP/UDP/SCTP ports via psutil."""
    if psutil is None or _net_connections is None:
        sys.exit("psutil not installed. Run: pip3 install psutil")

    connections = cached_conns if cached_conns is not None else _net_connections(kind="inet")
    state = ObservedState()
    exclude_nets = _discovery_exclude_networks()
    for conn in connections:
        if not (conn.laddr and conn.laddr.port):
            continue

        if conn.type == socket.SOCK_STREAM:
            if conn.status == psutil.CONN_LISTEN:
                if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                    continue
                state.tcp.add(conn.laddr.port)
            elif conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                    continue
                try:
                    state.established.add(_pack_tcp_conntrack_key(conn))
                except (OSError, ValueError):
                    continue
        elif conn.type == socket.SOCK_DGRAM:
            # UDP has no LISTEN state. Keep only bound sockets without a
            # connected remote peer, which better matches server-style ports.
            if conn.raddr:
                continue
            if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                continue
            state.udp.add(conn.laddr.port)
        elif conn.type == socket.SOCK_SEQPACKET:
            # Treat SOCK_SEQPACKET listeners as config-visible SCTP-style ports.
            if conn.raddr:
                continue
            if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                continue
            state.sctp.add(conn.laddr.port)

    pid_names: dict[int, str] = {}
    state.tcp_processes = _listening_port_processes(
        state.tcp, socket.SOCK_STREAM, connections, pid_names
    )
    state.udp_processes = _listening_port_processes(
        state.udp, socket.SOCK_DGRAM, connections, pid_names
    )
    return state
