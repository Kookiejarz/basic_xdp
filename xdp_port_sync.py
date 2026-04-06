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
import ctypes
import ctypes.util
import errno
import logging
import os
import platform
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field

try:
    import psutil
except ImportError:
    psutil = None

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"
TCP_CONNTRACK_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_conntrack"
TRUSTED_IPS_MAP_PATH = "/sys/fs/bpf/xdp_fw/trusted_src_ips"

NFT_FAMILY = "inet"
NFT_TABLE = "basic_xdp"
NFT_TCP_SET = "tcp_ports"
NFT_UDP_SET = "udp_ports"

BACKEND_AUTO = "auto"
BACKEND_XDP = "xdp"
BACKEND_NFTABLES = "nftables"

# Always-whitelisted ports (e.g. SSH emergency fallback)
TCP_PERMANENT: dict[int, str] = {}
UDP_PERMANENT: dict[int, str] = {}
TRUSTED_SRC_IPS: dict[str, str] = {}

# Wait this long after an EXEC/EXIT event before scanning,
# giving the new process time to call bind().
DEBOUNCE_S = 0.3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# psutil 6.0 renamed net_connections() -> connections()
_net_connections = None
if psutil is not None:
    _net_connections = getattr(psutil, "connections", psutil.net_connections)

# BPF syscall layer
_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_NR_BPF: int = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)

_BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
_BPF_OBJ_GET = 7


def _bpf(cmd: int, attr: ctypes.Array) -> int:
    ret = _libc.syscall(_NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def _obj_get(path: str) -> int:
    """Open a pinned BPF object and return its fd."""
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return _bpf(_BPF_OBJ_GET, attr)


def _render_nft_ports(ports: set[int]) -> str:
    return "{ " + ", ".join(str(port) for port in sorted(ports)) + " }"


def _run_nft(args: list[str], input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["nft", *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
    )


class BpfArrayMap:
    """Pinned BPF ARRAY map (key = __u32 port, value = __u32 0/1)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = _obj_get(path)
        self._cache: set[int] = set()

        self._key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(4)
        self._attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._attr, 0, self.fd, k_ptr, v_ptr, 0)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _update(self, port: int, val: int) -> None:
        struct.pack_into("=I", self._key, 0, port)
        struct.pack_into("=I", self._val, 0, val)
        _bpf(_BPF_MAP_UPDATE_ELEM, self._attr)

    def active_ports(self) -> set[int]:
        return set(self._cache)

    def set(self, port: int, val: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s port %d -> %d", self.path, port, val)
            self._cache.add(port) if val else self._cache.discard(port)
            return True
        try:
            self._update(port, val)
            self._cache.add(port) if val else self._cache.discard(port)
            return True
        except OSError as exc:
            log.warning("BPF update failed port=%d: %s", port, exc)
            return False


class BpfHashMap:
    """Pinned BPF HASH map (key = IPv4 __be32, value = __u32 1)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = _obj_get(path)
        self._cache: set[str] = set()

        self._key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(4)
        self._update_attr = ctypes.create_string_buffer(128)
        self._delete_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, k_ptr)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _pack_ip(self, ip_str: str) -> None:
        ctypes.memmove(self._key, socket.inet_aton(ip_str), 4)

    def _update(self, ip_str: str, val: int) -> None:
        self._pack_ip(ip_str)
        struct.pack_into("=I", self._val, 0, val)
        _bpf(_BPF_MAP_UPDATE_ELEM, self._update_attr)

    def _delete(self, ip_str: str) -> None:
        self._pack_ip(ip_str)
        _bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)

    def active_keys(self) -> set[str]:
        return set(self._cache)

    def set(self, ip_str: str, val: int, dry_run: bool = False) -> bool:
        if not val:
            return self.delete(ip_str, dry_run)

        if dry_run:
            log.info("[DRY] %s ip %s -> 1", self.path, ip_str)
            self._cache.add(ip_str)
            return True
        try:
            self._update(ip_str, 1)
            self._cache.add(ip_str)
            return True
        except OSError as exc:
            log.warning("BPF update failed ip=%s: %s", ip_str, exc)
            return False

    def delete(self, ip_str: str, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s delete ip %s", self.path, ip_str)
            self._cache.discard(ip_str)
            return True
        try:
            self._delete(ip_str)
            self._cache.discard(ip_str)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.discard(ip_str)
                return True
            log.warning("BPF delete failed ip=%s: %s", ip_str, exc)
            return False


class PortBackend:
    name = "backend"

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        trusted_target: set[str],
        dry_run: bool,
    ) -> None:
        raise NotImplementedError

    def close(self) -> None:
        return None


class XdpBackend(PortBackend):
    name = BACKEND_XDP

    def __init__(self) -> None:
        self.tcp_map = BpfArrayMap(TCP_MAP_PATH)
        self.udp_map = BpfArrayMap(UDP_MAP_PATH)
        self.trusted_map = BpfHashMap(TRUSTED_IPS_MAP_PATH)

    def close(self) -> None:
        self.tcp_map.close()
        self.udp_map.close()
        self.trusted_map.close()

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        trusted_target: set[str],
        dry_run: bool,
    ) -> None:
        changed = False

        for port in sorted(tcp_target - self.tcp_map.active_ports()):
            tag = f" [{TCP_PERMANENT[port]}]" if port in TCP_PERMANENT else ""
            if self.tcp_map.set(port, 1, dry_run):
                log.info("TCP +%d%s", port, tag)
                changed = True

        for port in sorted(self.tcp_map.active_ports() - tcp_target - set(TCP_PERMANENT)):
            if self.tcp_map.set(port, 0, dry_run):
                log.info("TCP -%d  (stopped)", port)
                changed = True

        for port in sorted(udp_target - self.udp_map.active_ports()):
            tag = f" [{UDP_PERMANENT[port]}]" if port in UDP_PERMANENT else ""
            if self.udp_map.set(port, 1, dry_run):
                log.info("UDP +%d%s", port, tag)
                changed = True

        for port in sorted(self.udp_map.active_ports() - udp_target - set(UDP_PERMANENT)):
            if self.udp_map.set(port, 0, dry_run):
                log.info("UDP -%d  (stopped)", port)
                changed = True

        # HASH maps need delete, not write-zero, when trust entries disappear.
        for ip_str in sorted(trusted_target - self.trusted_map.active_keys()):
            tag = f" [{TRUSTED_SRC_IPS[ip_str]}]" if ip_str in TRUSTED_SRC_IPS else ""
            if self.trusted_map.set(ip_str, 1, dry_run):
                log.info("TRUST +%s%s", ip_str, tag)
                changed = True

        for ip_str in sorted(self.trusted_map.active_keys() - trusted_target - set(TRUSTED_SRC_IPS)):
            if self.trusted_map.delete(ip_str, dry_run):
                log.info("TRUST -%s  (removed)", ip_str)
                changed = True

        if not changed:
            log.debug("Whitelist up-to-date.")


class NftablesBackend(PortBackend):
    name = BACKEND_NFTABLES

    def __init__(self) -> None:
        if shutil.which("nft") is None:
            raise RuntimeError("nft command not found")
        self._tcp_cache: set[int] = set()
        self._udp_cache: set[int] = set()
        self._ensure_ruleset()

    def _ensure_ruleset(self) -> None:
        result = _run_nft(["list", "table", NFT_FAMILY, NFT_TABLE], check=False)
        if result.returncode == 0:
            body = result.stdout
            if all(marker in body for marker in (f"set {NFT_TCP_SET}", f"set {NFT_UDP_SET}", "chain input")):
                return
            _run_nft(["delete", "table", NFT_FAMILY, NFT_TABLE], check=True)

        script = f"""table {NFT_FAMILY} {NFT_TABLE} {{
    set {NFT_TCP_SET} {{
        type inet_service
    }}

    set {NFT_UDP_SET} {{
        type inet_service
    }}

    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "lo" accept
        ct state established,related accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        tcp flags & (ack | rst | fin) != 0 accept
        tcp flags & (syn | ack) == syn tcp dport @{NFT_TCP_SET} accept
        udp sport {{ 53, 67, 123, 443, 547 }} accept
        udp dport @{NFT_UDP_SET} accept
        counter drop
    }}
}}
"""
        _run_nft(["-f", "-"], input_text=script, check=True)

    def _apply_targets(self, tcp_target: set[int], udp_target: set[int], dry_run: bool) -> None:
        lines = [
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_TCP_SET}",
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_UDP_SET}",
        ]
        if tcp_target:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_TCP_SET} {_render_nft_ports(tcp_target)}"
            )
        if udp_target:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_UDP_SET} {_render_nft_ports(udp_target)}"
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

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        trusted_target: set[str],
        dry_run: bool,
    ) -> None:
        changed = False
        _ = trusted_target

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

        self._apply_targets(tcp_target, udp_target, dry_run)
        self._tcp_cache = set(tcp_target)
        self._udp_cache = set(udp_target)

        if not changed:
            log.debug("Whitelist up-to-date.")


@dataclass
class PortState:
    tcp: set[int] = field(default_factory=set)
    udp: set[int] = field(default_factory=set)


def get_listening_ports() -> PortState:
    """Read listening TCP/UDP ports via psutil."""
    if psutil is None or _net_connections is None:
        sys.exit("psutil not installed. Run: pip3 install psutil")

    state = PortState()
    for conn in _net_connections(kind="inet"):
        if not (conn.laddr and conn.laddr.port):
            continue
        if conn.type == socket.SOCK_STREAM and conn.status == psutil.CONN_LISTEN:
            state.tcp.add(conn.laddr.port)
        elif conn.type == socket.SOCK_DGRAM:
            # UDP has no LISTEN state. Keep only bound sockets without a
            # connected remote peer, which better matches server-style ports.
            if conn.raddr:
                continue
            state.udp.add(conn.laddr.port)
    return state


def sync_once(backend: PortBackend, dry_run: bool) -> None:
    current = get_listening_ports()
    tcp_target = current.tcp | set(TCP_PERMANENT)
    udp_target = current.udp | set(UDP_PERMANENT)
    trusted_target = set(TRUSTED_SRC_IPS)
    backend.sync_ports(tcp_target, udp_target, trusted_target, dry_run)


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
    if name == BACKEND_XDP:
        return XdpBackend()
    if name == BACKEND_NFTABLES:
        return NftablesBackend()
    if name != BACKEND_AUTO:
        raise RuntimeError(f"Unsupported backend: {name}")

    if (
        os.path.exists(TCP_MAP_PATH)
        and os.path.exists(UDP_MAP_PATH)
        and os.path.exists(TCP_CONNTRACK_MAP_PATH)
        and os.path.exists(TRUSTED_IPS_MAP_PATH)
    ):
        try:
            backend = XdpBackend()
            log.info("Backend selected: xdp")
            return backend
        except OSError as exc:
            log.warning("XDP backend unavailable (%s); trying nftables.", exc)

    backend = NftablesBackend()
    log.info("Backend selected: nftables")
    return backend


def watch(interval: int, dry_run: bool, backend_name: str) -> None:
    backend = open_backend(backend_name)
    nl = open_proc_connector()

    sync_once(backend, dry_run)
    last_sync_t = time.monotonic()
    last_event_t = 0.0

    try:
        while True:
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
                last_sync_t = time.monotonic()
                last_event_t = 0.0

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        backend.close()


def main() -> None:
    def _parse_trusted_ip(ip_str: str) -> str:
        try:
            socket.inet_aton(ip_str)
        except OSError as exc:
            raise argparse.ArgumentTypeError(f"invalid IPv4 address: {ip_str}") from exc
        return ip_str

    p = argparse.ArgumentParser(description="Basic XDP port-whitelist sync daemon")
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
        "--trusted-ip",
        action="append",
        nargs=2,
        metavar=("IP", "LABEL"),
        default=[],
        help="Add a trusted IPv4 source IP and label (repeatable)",
    )
    args = p.parse_args()

    try:
        for ip_str, label in args.trusted_ip:
            TRUSTED_SRC_IPS[_parse_trusted_ip(ip_str)] = label
    except argparse.ArgumentTypeError as exc:
        p.error(str(exc))

    backend = None
    try:
        if args.watch:
            watch(args.interval, args.dry_run, args.backend)
        else:
            backend = open_backend(args.backend)
            sync_once(backend, args.dry_run)
            log.info("Sync completed.")
    finally:
        if backend is not None:
            backend.close()


if __name__ == "__main__":
    main()
