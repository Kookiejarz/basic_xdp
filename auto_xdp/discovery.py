"""Port discovery: SOCK_DIAG netlink on Linux, psutil fallback elsewhere."""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import socket
import shutil
import struct
import subprocess
import sys
import time
from dataclasses import dataclass

from auto_xdp import config as cfg
from auto_xdp.state import ObservedState, RuntimeEndpoint

log = logging.getLogger(__name__)

_IS_LINUX = sys.platform == "linux"

# psutil (non-Linux fallback)

try:
    import psutil
except ImportError:
    psutil = None

# Kept for backward-compat import by external callers.
_net_connections = None
if psutil is not None:
    _net_connections = getattr(psutil, "connections", psutil.net_connections)

# SOCK_DIAG constants & structs

_NETLINK_INET_DIAG = 4
_SOCK_DIAG_BY_FAMILY = 20
_NLMSG_DONE = 3
_NLMSG_ERROR = 2
_NLM_F_REQUEST = 0x01
_NLM_F_DUMP = 0x300  # NLM_F_ROOT | NLM_F_MATCH

_SS_LISTEN = 1 << 10
_SS_ALL = 0xFFFFFFFF

_IPPROTO_SCTP = 132

# struct nlmsghdr (16 bytes)
_NLMSGHDR = struct.Struct("=IHHII")
# struct inet_diag_req_v2 (56 bytes)
_DIAG_REQ = struct.Struct("=BBBBIHH16s16sIII")
# struct inet_diag_msg (72 bytes)
_DIAG_MSG = struct.Struct("=BBBBHH16s16sIIIIIIII")

_NLMSGHDR_SZ = _NLMSGHDR.size   # 16
_DIAG_REQ_SZ = _DIAG_REQ.size   # 56
_DIAG_MSG_SZ = _DIAG_MSG.size   # 72
_ZERO16 = bytes(16)
_RECV_BUFSZ = 1 << 16  # 64 KB
_LOCAL_ADDRESS_ZONES: dict[str, str] | None = None


class DiscoveryError(RuntimeError):
    """The socket dump did not produce a complete, trustworthy snapshot."""


@dataclass(frozen=True)
class ContainerIdentity:
    runtime: str
    container_id: str
    name: str
    labels: dict[str, str]
    host_ip: str = ""

    @property
    def subject(self) -> str:
        return f"{self.runtime}:{self.container_id[:12] or self.name}"


_CONTAINER_METADATA_TTL = 5.0
_CONTAINER_METADATA_UNTIL = 0.0
_CONTAINER_PORTS: dict[tuple[str, int], list[ContainerIdentity]] = {}
_CONTAINER_BY_ID: dict[str, ContainerIdentity] = {}
_CONTAINER_CGROUP_RE = re.compile(
    r"(?:^|/)(?:docker|libpod)[-/]([0-9a-f]{12,64})(?:\.scope)?(?:/|$)",
    re.IGNORECASE,
)


# low-level netlink helpers

def _nldiag_dump(family: int, proto: int, states: int):
    """Yield (sport_h, dport_h, src_16b, dst_16b, inode, rqueue) per matching socket.

    Ports are returned in host byte order.  Addresses are 16-byte big-endian
    buffers suitable for socket.inet_ntop / struct.pack("!...").
    """
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_INET_DIAG) as nl:
        nl.bind((0, 0))
        req = (
            _NLMSGHDR.pack(
                _NLMSGHDR_SZ + _DIAG_REQ_SZ,
                _SOCK_DIAG_BY_FAMILY,
                _NLM_F_REQUEST | _NLM_F_DUMP,
                1, 0,
            )
            + _DIAG_REQ.pack(
                family, proto, 0, 0, states,
                0, 0, _ZERO16, _ZERO16, 0, 0xFFFFFFFF, 0xFFFFFFFF,
            )
        )
        nl.sendall(req)
        buf = bytearray(_RECV_BUFSZ)
        while True:
            n = nl.recv_into(buf)
            if n == 0:
                raise DiscoveryError("SOCK_DIAG closed before NLMSG_DONE")
            offset = 0
            done = False
            while offset + _NLMSGHDR_SZ <= n:
                msg_len, msg_type, _fl, _seq, _pid = _NLMSGHDR.unpack_from(buf, offset)
                if msg_len < _NLMSGHDR_SZ:
                    raise DiscoveryError("SOCK_DIAG returned an invalid netlink message")
                if offset + msg_len > n:
                    raise DiscoveryError("SOCK_DIAG returned a truncated netlink message")
                if msg_type == _NLMSG_DONE:
                    done = True
                    break
                if msg_type == _NLMSG_ERROR:
                    if msg_len < _NLMSGHDR_SZ + 4:
                        raise DiscoveryError("SOCK_DIAG returned a truncated NLMSG_ERROR")
                    (error,) = struct.unpack_from("=i", buf, offset + _NLMSGHDR_SZ)
                    if error:
                        raise DiscoveryError(f"SOCK_DIAG dump failed with errno {-error}")
                if (
                    msg_type == _SOCK_DIAG_BY_FAMILY
                    and offset + _NLMSGHDR_SZ + _DIAG_MSG_SZ <= n
                ):
                    (
                        _fam, _st, _ti, _re,
                        sport_raw, dport_raw, src, dst,
                        _if, _c0, _c1,
                        _exp, rqueue, _wq, _uid, inode,
                    ) = _DIAG_MSG.unpack_from(buf, offset + _NLMSGHDR_SZ)
                    yield (
                        socket.ntohs(sport_raw),
                        socket.ntohs(dport_raw),
                        src, dst, inode, rqueue,
                    )
                offset += (msg_len + 3) & ~3
            if offset != n and not done:
                raise DiscoveryError("SOCK_DIAG returned trailing incomplete data")
            if done:
                break


def _build_inode_pid() -> dict[int, int]:
    """Return {socket_inode: pid} by scanning /proc/*/fd symlinks."""
    result: dict[int, int] = {}
    try:
        with os.scandir("/proc") as proc_it:
            for proc_entry in proc_it:
                if not proc_entry.name.isdigit():
                    continue
                pid = int(proc_entry.name)
                try:
                    with os.scandir(f"/proc/{pid}/fd") as fd_it:
                        for fd_entry in fd_it:
                            try:
                                link = os.readlink(fd_entry.path)
                                if link.startswith("socket:["):
                                    result[int(link[8:-1])] = pid
                            except OSError:
                                pass
                except OSError:
                    pass
    except OSError:
        pass
    return result


def _pid_comm(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/comm") as f:
            return f.read().strip()
    except OSError:
        return ""


def _container_inspect(runtime: str) -> list[dict]:
    """Read running container metadata without trusting process names."""
    if shutil.which(runtime) is None:
        return []
    try:
        listed = subprocess.run(
            [runtime, "ps", "-q"], capture_output=True, text=True, timeout=5, check=False
        )
        if listed.returncode != 0:
            return []
        ids = [item for item in listed.stdout.split() if re.fullmatch(r"[0-9a-fA-F]{12,64}", item)]
        if not ids:
            return []
        records: list[dict] = []
        for offset in range(0, len(ids), 64):
            inspected = subprocess.run(
                [runtime, "inspect", *ids[offset:offset + 64]],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if inspected.returncode != 0:
                continue
            try:
                payload = json.loads(inspected.stdout)
            except ValueError:
                continue
            if isinstance(payload, list):
                records.extend(item for item in payload if isinstance(item, dict))
        return records
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return []


def _container_port_bindings(record: dict) -> list[tuple[str, int, str]]:
    network = record.get("NetworkSettings", {})
    ports = network.get("Ports", {}) if isinstance(network, dict) else {}
    if not isinstance(ports, dict):
        ports = {}
    if not ports:
        host_config = record.get("HostConfig", {})
        ports = host_config.get("PortBindings", {}) if isinstance(host_config, dict) else {}
    bindings: list[tuple[str, int, str]] = []
    for container_port, host_bindings in ports.items():
        if not isinstance(container_port, str) or "/" not in container_port:
            continue
        raw_port, protocol = container_port.rsplit("/", 1)
        protocol = protocol.lower()
        if protocol not in {"tcp", "udp", "sctp"}:
            continue
        try:
            int(raw_port)
        except ValueError:
            continue
        if not isinstance(host_bindings, list):
            continue
        for binding in host_bindings:
            if not isinstance(binding, dict):
                continue
            try:
                host_port = int(str(binding.get("HostPort", "")))
            except ValueError:
                continue
            if not 1 <= host_port <= 65535:
                continue
            host_ip = str(binding.get("HostIp", ""))
            bindings.append((protocol, host_port, host_ip))
    return bindings


def _container_metadata() -> tuple[dict[tuple[str, int], list[ContainerIdentity]], dict[str, ContainerIdentity]]:
    global _CONTAINER_METADATA_UNTIL, _CONTAINER_PORTS, _CONTAINER_BY_ID
    now = time.monotonic()
    if now < _CONTAINER_METADATA_UNTIL:
        return _CONTAINER_PORTS, _CONTAINER_BY_ID
    by_port: dict[tuple[str, int], list[ContainerIdentity]] = {}
    by_id: dict[str, ContainerIdentity] = {}
    for runtime in ("docker", "podman"):
        for record in _container_inspect(runtime):
            container_id = str(record.get("Id", "")).lower()
            if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
                continue
            raw_name = str(record.get("Name", "")).lstrip("/")
            config = record.get("Config", {})
            raw_labels = config.get("Labels", {}) if isinstance(config, dict) else {}
            labels = {
                str(key): str(value)
                for key, value in raw_labels.items()
            } if isinstance(raw_labels, dict) else {}
            identity = ContainerIdentity(runtime, container_id, raw_name, labels)
            by_id[f"{runtime}:{container_id}"] = identity
            by_id.setdefault(container_id, identity)
            for protocol, host_port, host_ip in _container_port_bindings(record):
                bound = ContainerIdentity(runtime, container_id, raw_name, labels, host_ip)
                by_port.setdefault((protocol, host_port), []).append(bound)
    _CONTAINER_PORTS = by_port
    _CONTAINER_BY_ID = by_id
    _CONTAINER_METADATA_UNTIL = now + _CONTAINER_METADATA_TTL
    return by_port, by_id


def _container_from_pid(pid: int) -> ContainerIdentity | None:
    try:
        with open(f"/proc/{pid}/cgroup", encoding="utf-8") as fh:
            cgroup = fh.read()
    except OSError:
        return None
    match = _CONTAINER_CGROUP_RE.search(cgroup)
    if not match:
        return None
    container_id = match.group(1).lower()
    identity = _CONTAINER_BY_ID.get(container_id)
    if identity is not None:
        return identity
    runtime = "podman" if "libpod" in match.group(0).lower() else "docker"
    return ContainerIdentity(runtime, container_id, "", {})


def _container_for_endpoint(protocol: str, host_address: str, port: int) -> ContainerIdentity | None:
    candidates = _CONTAINER_PORTS.get((protocol, port), [])
    matches: list[ContainerIdentity] = []
    seen: set[tuple[str, str]] = set()
    for identity in candidates:
        host_ip = identity.host_ip.split("%", 1)[0]
        if host_ip in {"", "0.0.0.0", "::", "*"} or host_ip == host_address.split("%", 1)[0]:
            key = (identity.runtime, identity.container_id)
            if key not in seen:
                seen.add(key)
                matches.append(identity)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        return ContainerIdentity("ambiguous", "", "", {})
    return None


def _addr_str(family: int, raw: bytes) -> str:
    return socket.inet_ntop(family, raw[:4] if family == socket.AF_INET else raw)


# shared helpers (used by both paths)

def _resolve_pid_name(pid: int, cache: dict[int, str]) -> str:
    if pid not in cache:
        try:
            cache[pid] = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as exc:
            log.debug("Failed to resolve process name for pid=%s: %s", pid, exc)
            cache[pid] = ""
    return cache[pid]


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
    if ip_str in ("0.0.0.0", "::", "*"):
        return True
    try:
        addr = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return True
    if cfg.DISCOVERY_EXCLUDE_LOOPBACK and addr.is_loopback:
        return False
    if addr.is_multicast:
        return False
    if addr.is_link_local:
        return False
    for net in exclude_nets:
        if addr.version == net.version and addr in net:
            return False
    return True


def _bind_scope(ip_str: str) -> str:
    """Describe the bind address without treating it as authorization."""
    if ip_str in ("0.0.0.0", "::", "*"):
        return "wildcard"
    try:
        address = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return "unknown"
    return "loopback" if address.is_loopback else "specific"


def _pid_systemd_unit(pid: int) -> str:
    """Return the systemd service unit owning pid, if cgroup evidence exists."""
    try:
        with open(f"/proc/{pid}/cgroup", encoding="utf-8") as fh:
            for line in fh:
                path = line.rstrip().rsplit(":", 1)[-1]
                for component in reversed(path.split("/")):
                    if component.endswith(".service"):
                        return component
    except OSError:
        pass
    return ""


def _endpoint_zone(host_address: str) -> str:
    """Classify the local bind into a configured ingress zone.

    Exact address-to-interface resolution is intentionally conservative. A
    wildcard bind is reported as public because it is the only zone that can
    safely represent the global port maps used by the current backends.
    """
    global _LOCAL_ADDRESS_ZONES
    try:
        address = ipaddress.ip_address(host_address.split("%", 1)[0])
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "local"
    if host_address in {"0.0.0.0", "::", "*"}:
        return "public"
    if _LOCAL_ADDRESS_ZONES is None:
        _LOCAL_ADDRESS_ZONES = {}
        try:
            raw = subprocess.check_output(
                ["ip", "-j", "address", "show"],
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            links = json.loads(raw)
            for link in links if isinstance(links, list) else []:
                ifname = link.get("ifname")
                if not isinstance(ifname, str):
                    continue
                for zone, spec in cfg.ZONES.items():
                    if ifname not in spec.get("interfaces", []) and "*" not in spec.get("interfaces", []):
                        continue
                    for info in link.get("addr_info", []):
                        local = info.get("local") if isinstance(info, dict) else None
                        if isinstance(local, str):
                            _LOCAL_ADDRESS_ZONES[local.split("%", 1)[0]] = zone
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, ValueError, TypeError):
            pass
    mapped_zone = _LOCAL_ADDRESS_ZONES.get(host_address.split("%", 1)[0])
    if mapped_zone:
        return mapped_zone
    for zone, spec in cfg.ZONES.items():
        for cidr in spec.get("cidrs", []):
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return zone
            except ValueError:
                continue
    return "unknown"


def _endpoint(
    protocol: str,
    host_address: str,
    port: int,
    subject: str,
    attribution_state: str,
    attribution_source: str,
    container: ContainerIdentity | None = None,
) -> RuntimeEndpoint:
    endpoint = RuntimeEndpoint(
        protocol=protocol,
        host_address=host_address,
        host_port=port,
        bind_scope=_bind_scope(host_address),
        ingress_zone=_endpoint_zone(host_address),
        subject=subject,
        attribution_state=attribution_state,
        attribution_source=attribution_source,
    )
    identity = container or _container_for_endpoint(protocol, host_address, port)
    if identity is None:
        return endpoint
    if identity.runtime == "ambiguous":
        endpoint.subject = ""
        endpoint.attribution_state = "ambiguous"
        endpoint.attribution_source = "container-runtime-port-collision"
        return endpoint
    endpoint.subject = identity.subject
    endpoint.attribution_state = "exact"
    endpoint.attribution_source = (
        f"{identity.runtime}-inspect"
        if identity.name or identity.labels
        else f"{identity.runtime}-cgroup"
    )
    endpoint.container_runtime = identity.runtime
    endpoint.container_id = identity.container_id
    endpoint.container_name = identity.name
    endpoint.container_labels = dict(identity.labels)
    return endpoint


def _mark_shared_endpoints(state: ObservedState) -> ObservedState:
    """Mark reuse/listener collisions so policy cannot silently privilege one owner."""
    groups: dict[tuple[str, int], list[RuntimeEndpoint]] = {}
    for endpoint in state.endpoints:
        groups.setdefault((endpoint.protocol, endpoint.host_port), []).append(endpoint)
    for endpoints in groups.values():
        subjects = {endpoint.subject for endpoint in endpoints}
        if len(endpoints) > 1 and len(subjects) > 1:
            for endpoint in endpoints:
                endpoint.attribution_state = "shared" if endpoint.subject else "ambiguous"
                endpoint.attribution_source = "shared-port-inventory"
    return state


def _parse_proc_udp(path: str) -> dict[int, dict]:
    """Parse /proc/net/udp[6], return local_port → {rx_queue, drops}."""
    result: dict[int, dict] = {}
    try:
        with open(path) as f:
            for line in f:
                parts = line.split()
                if len(parts) < 10 or parts[0] == "sl":
                    continue
                try:
                    local_port = int(parts[1].split(":")[1], 16)
                    tx_rx = parts[4].split(":")
                    rx_queue = int(tx_rx[1], 16) if len(tx_rx) > 1 else 0
                    drops = int(parts[-1]) if len(parts) > 12 else 0
                except (ValueError, IndexError):
                    continue
                if local_port in result:
                    result[local_port]["rx_queue"] += rx_queue
                    result[local_port]["drops"] += drops
                else:
                    result[local_port] = {"rx_queue": rx_queue, "drops": drops}
    except OSError:
        pass
    return result


def _build_systemd_socket_map() -> dict[int, str]:
    """Return port → service name for systemd socket-activated services."""
    result: dict[int, str] = {}
    try:
        out = subprocess.check_output(
            ["systemctl", "list-sockets", "--no-pager", "--no-legend", "--all"],
            stderr=subprocess.DEVNULL,
            timeout=5,
        ).decode(errors="replace")
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        return result
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        listen_addr = parts[0]
        if ":" not in listen_addr:
            continue
        try:
            port = int(listen_addr.rsplit(":", 1)[1])
        except ValueError:
            continue
        unit = parts[2] if len(parts) >= 3 else parts[1]
        name = unit.split(".")[0]
        if name:
            result.setdefault(port, name)
    return result


# Linux netlink implementation

def _get_listening_ports_netlink() -> ObservedState:
    """Query sockets via SOCK_DIAG — no subprocess, no psutil."""
    global _LOCAL_ADDRESS_ZONES
    _LOCAL_ADDRESS_ZONES = None
    state = ObservedState()
    exclude_nets = _discovery_exclude_networks()

    inode_pid: dict[int, int] | None = None
    pid_names: dict[int, str] = {}
    systemd_socket_map: dict[int, str] | None = None

    def _proc_name(inode: int) -> str:
        nonlocal inode_pid
        if not inode:
            return ""
        if inode_pid is None:
            inode_pid = _build_inode_pid()
        pid = inode_pid.get(inode)
        if pid is None:
            return ""
        if pid not in pid_names:
            pid_names[pid] = _pid_comm(pid)
        return pid_names[pid]

    def _proc_attribution(inode: int) -> tuple[str, str, str, ContainerIdentity | None]:
        nonlocal inode_pid
        if not inode:
            return "", "unknown", "", None
        if inode_pid is None:
            inode_pid = _build_inode_pid()
        pid = inode_pid.get(inode)
        if pid is None:
            return "", "unknown", "", None
        container = _container_from_pid(pid)
        if container is not None:
            return container.subject, "exact", f"{container.runtime}-cgroup", container
        unit = _pid_systemd_unit(pid)
        if unit:
            return unit, "exact", "systemd-cgroup", None
        name = _proc_name(inode)
        return (name, "delegated", "process-name", None) if name else ("", "unknown", "", None)

    def _resolve_systemd(name: str, port: int) -> str:
        nonlocal systemd_socket_map
        if name != "systemd":
            return name
        if systemd_socket_map is None:
            systemd_socket_map = _build_systemd_socket_map()
        return systemd_socket_map.get(port, name)

    # TCP LISTEN
    for family in (socket.AF_INET, socket.AF_INET6):
        for sport_h, _dp, src, _dst, inode, _rq in _nldiag_dump(family, socket.IPPROTO_TCP, _SS_LISTEN):
            port = sport_h
            if not _bind_ip_is_exposed(_addr_str(family, src), exclude_nets):
                continue
            if port in cfg.DISCOVERY_EXCLUDE_PORTS:
                continue
            state.tcp.add(port)
            raw_name = _proc_name(inode)
            name = _resolve_systemd(raw_name, port)
            if name:
                state.tcp_processes[port] = name
            subject, attribution, source, container = _proc_attribution(inode)
            if raw_name == "systemd" and name != "systemd":
                subject, attribution, source, container = name, "exact", "systemd-socket", None
            if attribution != "exact" and name and name != "systemd" and container is None:
                subject = name
            state.endpoints.append(
                _endpoint("tcp", _addr_str(family, src), port, subject, attribution, source, container)
            )

    # UDP — collect drops from /proc, rqueue from SOCK_DIAG
    proc_udp: dict[int, dict] = {}
    for _path in ("/proc/net/udp", "/proc/net/udp6"):
        for _port, _data in _parse_proc_udp(_path).items():
            if _port in proc_udp:
                proc_udp[_port]["drops"] += _data["drops"]
            else:
                proc_udp[_port] = {"drops": _data["drops"]}

    udp_sockets: list[dict] = []
    udp_agg: dict[int, dict] = {}
    for family in (socket.AF_INET, socket.AF_INET6):
        for sport_h, dport_h, src, _dst, inode, rqueue in _nldiag_dump(
            family, socket.IPPROTO_UDP, _SS_ALL
        ):
            port = sport_h
            if port == 0:
                continue
            connected = dport_h != 0
            udp_sockets.append({
                "port": port,
                "family": family,
                "src": src,
                "inode": inode,
                "connected": connected,
            })
            aggregate = udp_agg.setdefault(port, {"rqueue": 0, "count": 0})
            aggregate["rqueue"] += rqueue
            aggregate["count"] += 1

    for info in udp_sockets:
        port = info["port"]
        family, src = info["family"], info["src"]
        if not _bind_ip_is_exposed(_addr_str(family, src), exclude_nets):
            continue
        if port in cfg.DISCOVERY_EXCLUDE_PORTS:
            continue
        aggregate = udp_agg[port]
        if info["connected"]:
            server_signal = (
                aggregate["count"] > 1           # SO_REUSEPORT proxy
                or aggregate["rqueue"] > 0       # receive backlog (from SOCK_DIAG)
                or proc_udp.get(port, {}).get("drops", 0) > 0
            )
            if not server_signal:
                continue
        state.udp.add(port)
        name = _resolve_systemd(_proc_name(info["inode"]), port)
        if name:
            state.udp_processes.setdefault(port, name)
        subject, attribution, source, container = _proc_attribution(info["inode"])
        if attribution != "exact" and name and name != "systemd" and container is None:
            subject = name
        state.endpoints.append(
            _endpoint("udp", _addr_str(family, src), port, subject, attribution, source, container)
        )
        opts: set[str] = set()
        if aggregate["count"] > 1:
            opts.add("SO_REUSEPORT")
        if aggregate["rqueue"] > 0:
            opts.add("rx_queue>0")
        if proc_udp.get(port, {}).get("drops", 0) > 0:
            opts.add("drops>0")
        if opts:
            state.udp_sock_opts[port] = frozenset(opts)

    # SCTP LISTEN
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            for sport_h, _dp, src, _dst, _in, _rq in _nldiag_dump(
                family, _IPPROTO_SCTP, _SS_LISTEN
            ):
                if _bind_ip_is_exposed(_addr_str(family, src), exclude_nets) and sport_h not in cfg.DISCOVERY_EXCLUDE_PORTS:
                    state.sctp.add(sport_h)
                    subject, attribution, source, container = _proc_attribution(_in)
                    state.endpoints.append(
                        _endpoint("sctp", _addr_str(family, src), sport_h, subject, attribution, source, container)
                    )
    except OSError:
        pass

    return _mark_shared_endpoints(state)


def _append_published_container_endpoints(
    state: ObservedState,
    published: dict[tuple[str, int], list[ContainerIdentity]],
) -> ObservedState:
    """Add runtime endpoints implemented by container NAT rather than a host socket."""
    exclude_nets = _discovery_exclude_networks()
    existing = {
        (
            endpoint.protocol,
            endpoint.host_port,
            endpoint.host_address.split("%", 1)[0],
            endpoint.container_runtime,
            endpoint.container_id,
        )
        for endpoint in state.endpoints
    }
    for (protocol, port), identities in published.items():
        for identity in identities:
            host_address = identity.host_ip or "0.0.0.0"
            key = (
                protocol,
                port,
                host_address.split("%", 1)[0],
                identity.runtime,
                identity.container_id,
            )
            if key in existing or not _bind_ip_is_exposed(host_address, exclude_nets):
                continue
            if protocol == "tcp":
                state.tcp.add(port)
                state.tcp_processes.setdefault(port, identity.subject)
            elif protocol == "udp":
                state.udp.add(port)
                state.udp_processes.setdefault(port, identity.subject)
            elif protocol == "sctp":
                state.sctp.add(port)
            else:
                continue
            state.endpoints.append(
                _endpoint(
                    protocol,
                    host_address,
                    port,
                    identity.subject,
                    "exact",
                    f"{identity.runtime}-inspect",
                    identity,
                )
            )
            existing.add(key)
    return _mark_shared_endpoints(state)


# psutil fallback (non-Linux)

def _collect_proc_udp_stats() -> dict[int, dict]:
    proc_udp: dict[int, dict] = {}
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        for port, data in _parse_proc_udp(path).items():
            if port in proc_udp:
                proc_udp[port]["rx_queue"] += data["rx_queue"]
                proc_udp[port]["drops"] += data["drops"]
            else:
                proc_udp[port] = dict(data)
    return proc_udp


def _resolve_process_name(
    pid: int | None,
    port: int,
    pid_names: dict[int, str],
    systemd_map: dict[int, str] | None,
) -> tuple[str, dict[int, str] | None]:
    if pid is None:
        return "", systemd_map
    name = _resolve_pid_name(pid, pid_names)
    if name == "systemd":
        if systemd_map is None:
            systemd_map = _build_systemd_socket_map()
        name = systemd_map.get(port, name)
    return name, systemd_map


def _annotate_udp_sock_opts(port: int, proc_udp: dict[int, dict], state: ObservedState) -> None:
    pd = proc_udp.get(port, {})
    opts: set[str] = set()
    if pd.get("rx_queue", 0) > 0:
        opts.add("rx_queue>0")
    if pd.get("drops", 0) > 0:
        opts.add("drops>0")
    if opts:
        state.udp_sock_opts[port] = state.udp_sock_opts.get(port, frozenset()) | frozenset(opts)


def _get_listening_ports_psutil(cached_conns=None) -> ObservedState:
    if psutil is None or _net_connections is None:
        sys.exit("psutil not installed. Run: pip3 install psutil")

    connections = cached_conns if cached_conns is not None else _net_connections(kind="inet")
    global _LOCAL_ADDRESS_ZONES
    _LOCAL_ADDRESS_ZONES = None
    state = ObservedState()
    exclude_nets = _discovery_exclude_networks()
    pid_names: dict[int, str] = {}
    proc_udp = _collect_proc_udp_stats()
    systemd_map: dict[int, str] | None = None

    for conn in connections:
        if not (conn.laddr and conn.laddr.port):
            continue
        port = conn.laddr.port
        if conn.type == socket.SOCK_STREAM:
            if conn.status == psutil.CONN_LISTEN:
                if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                    continue
                if port in cfg.DISCOVERY_EXCLUDE_PORTS:
                    continue
                state.tcp.add(port)
                pid = getattr(conn, "pid", None)
                name, systemd_map = _resolve_process_name(pid, port, pid_names, systemd_map)
                if name:
                    state.tcp_processes[port] = name
                container = _container_from_pid(pid) if isinstance(pid, int) else None
                state.endpoints.append(
                    _endpoint(
                        "tcp", conn.laddr.ip, port, name,
                        "exact" if name.endswith(".service") else ("delegated" if name else "unknown"),
                        "systemd-socket" if name.endswith(".service") else ("process-name" if name else ""),
                        container,
                    )
                )
        elif conn.type in (socket.SOCK_DGRAM, socket.SOCK_SEQPACKET):
            if conn.raddr:
                if conn.type != socket.SOCK_DGRAM:
                    continue
                pd = proc_udp.get(port, {})
                if not (pd.get("rx_queue", 0) > 0 or pd.get("drops", 0) > 0):
                    continue
            if not _bind_ip_is_exposed(conn.laddr.ip, exclude_nets):
                continue
            if port in cfg.DISCOVERY_EXCLUDE_PORTS:
                continue
            if conn.type == socket.SOCK_DGRAM:
                state.udp.add(port)
                pid = getattr(conn, "pid", None)
                name, systemd_map = _resolve_process_name(pid, port, pid_names, systemd_map)
                if name:
                    state.udp_processes[port] = name
                container = _container_from_pid(pid) if isinstance(pid, int) else None
                state.endpoints.append(
                    _endpoint(
                        "udp", conn.laddr.ip, port, name,
                        "exact" if name.endswith(".service") else ("delegated" if name else "unknown"),
                        "systemd-socket" if name.endswith(".service") else ("process-name" if name else ""),
                        container,
                    )
                )
                _annotate_udp_sock_opts(port, proc_udp, state)
            else:
                state.sctp.add(port)
                state.endpoints.append(
                    _endpoint("sctp", conn.laddr.ip, port, "", "unknown", "")
                )

    return _mark_shared_endpoints(state)


# public API

def get_listening_ports(cached_conns=None) -> ObservedState:
    """Read externally reachable listening TCP/UDP/SCTP ports."""
    if _IS_LINUX:
        published, _ = _container_metadata()
        return _append_published_container_endpoints(
            _get_listening_ports_netlink(), published
        )
    return _get_listening_ports_psutil(cached_conns)
