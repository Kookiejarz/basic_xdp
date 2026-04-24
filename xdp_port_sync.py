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
import ipaddress
import ctypes.util
import errno
import logging
import os
import platform
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

try:
    import psutil
except ImportError:
    psutil = None

TOML_CONFIG_PATH = "/etc/auto_xdp/config.toml"

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"
TCP_CONNTRACK_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_conntrack"
TRUSTED_IPS_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/trusted_ipv4"
TRUSTED_IPS_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/trusted_ipv6"
SYN_RATE_MAP_PATH     = "/sys/fs/bpf/xdp_fw/syn_rate_ports"
UDP_RATE_MAP_PATH     = "/sys/fs/bpf/xdp_fw/udp_rate_ports"
UDP_GLOBAL_RL_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_global_rl"
TCP_ACL_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/tcp_acl_v4"
TCP_ACL_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/tcp_acl_v6"
UDP_ACL_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/udp_acl_v4"
UDP_ACL_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/udp_acl_v6"
REQUIRED_XDP_MAP_PATHS = (
    TCP_MAP_PATH,
    UDP_MAP_PATH,
    TCP_CONNTRACK_MAP_PATH,
    TRUSTED_IPS_MAP_PATH4,
    TRUSTED_IPS_MAP_PATH6,
)

# All rate-limit heuristics and access-control settings are loaded from
# /etc/auto_xdp/config.toml at startup (and on SIGHUP).  These dicts are
# populated by apply_toml_config(); do not add hardcoded values here.
_SYN_RATE_BY_PROC:    dict[str, int] = {}
_SYN_RATE_BY_SERVICE: dict[str, int] = {}
_UDP_RATE_BY_PROC:    dict[str, int] = {}
_UDP_RATE_BY_SERVICE: dict[str, int] = {}

NFT_FAMILY = "inet"
NFT_TABLE = "auto_xdp"
NFT_TCP_SET = "tcp_ports"
NFT_UDP_SET = "udp_ports"
NFT_TRUSTED_SET4 = "trusted_v4"
NFT_TRUSTED_SET6 = "trusted_v6"

BACKEND_AUTO = "auto"
BACKEND_XDP = "xdp"
BACKEND_NFTABLES = "nftables"

TCP_PERMANENT:   dict[int, str] = {}
UDP_PERMANENT:   dict[int, str] = {}
TRUSTED_SRC_IPS: dict[str, str] = {}
ACL_RULES:       list[dict]     = []

_ACL_MAX_PORTS = 64
_ACL_VAL_SIZE  = 4 + _ACL_MAX_PORTS * 2  # u32 count + u16 ports[64] = 132 bytes


def load_toml_config(path: str = TOML_CONFIG_PATH) -> dict:
    if tomllib is None:
        log.debug("tomllib not available; skipping TOML config load.")
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        log.warning("Failed to load %s: %s", path, exc)
        return {}


def apply_toml_config(cfg: dict) -> None:
    """Replace all config-driven globals from a parsed TOML dict.

    Called at startup and on SIGHUP.  Always does a full reset so that
    deletions in the config file take effect without a restart.
    """
    global TCP_PERMANENT, UDP_PERMANENT, TRUSTED_SRC_IPS, ACL_RULES
    global _SYN_RATE_BY_PROC, _SYN_RATE_BY_SERVICE, _UDP_RATE_BY_PROC, _UDP_RATE_BY_SERVICE

    TCP_PERMANENT   = {}
    UDP_PERMANENT   = {}
    TRUSTED_SRC_IPS = {}
    ACL_RULES       = []
    _SYN_RATE_BY_PROC    = {}
    _SYN_RATE_BY_SERVICE = {}
    _UDP_RATE_BY_PROC    = {}
    _UDP_RATE_BY_SERVICE = {}

    perm = cfg.get("permanent_ports", {})
    for p in perm.get("tcp", []):
        TCP_PERMANENT[int(p)] = "config"
    for p in perm.get("udp", []):
        UDP_PERMANENT[int(p)] = "config"

    for cidr, label in cfg.get("trusted_ips", {}).items():
        TRUSTED_SRC_IPS[cidr] = str(label)

    for rule in cfg.get("acl", []):
        ACL_RULES.append({
            "proto": rule["proto"],
            "cidr":  rule["cidr"],
            "ports": [int(p) for p in rule.get("ports", [])],
        })

    rl = cfg.get("rate_limits", {})
    _SYN_RATE_BY_PROC    = {k: int(v) for k, v in rl.get("syn_by_proc",    {}).items()}
    _SYN_RATE_BY_SERVICE = {k: int(v) for k, v in rl.get("syn_by_service", {}).items()}
    _UDP_RATE_BY_PROC    = {k: int(v) for k, v in rl.get("udp_by_proc",    {}).items()}
    _UDP_RATE_BY_SERVICE = {k: int(v) for k, v in rl.get("udp_by_service", {}).items()}


# Wait this long after an EXEC/EXIT event before scanning,
# giving the new process time to call bind().
DEBOUNCE_S = 0.3

DEFAULT_LOG_LEVEL = os.environ.get("BASIC_XDP_LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, DEFAULT_LOG_LEVEL, logging.INFO),
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

_BPF_MAP_LOOKUP_ELEM = 1
_BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
_BPF_MAP_GET_NEXT_KEY = 4
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


def _render_nft_addrs(addrs: set[str]) -> str:
    return "{ " + ", ".join(sorted(addrs)) + " }"


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
        self._update_attr = ctypes.create_string_buffer(128)
        self._lookup_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQQ", self._lookup_attr, 0, self.fd, k_ptr, v_ptr)
        self._load_cache()

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
        _bpf(_BPF_MAP_UPDATE_ELEM, self._update_attr)

    def _lookup(self, port: int) -> int:
        struct.pack_into("=I", self._key, 0, port)
        _bpf(_BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
        return struct.unpack_from("=I", self._val, 0)[0]

    def _load_cache(self) -> None:
        for port in range(65536):
            try:
                if self._lookup(port):
                    self._cache.add(port)
            except OSError:
                continue

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


class BpfLpmMap:
    """Pinned BPF LPM_TRIE map for CIDR prefix matching (IPv4 or IPv6)."""

    def __init__(self, path: str, family: int) -> None:
        self.path = path
        self.fd = _obj_get(path)
        self._family = family
        self._addr_len = 4 if family == socket.AF_INET else 16
        self._max_prefix = 32 if family == socket.AF_INET else 128
        self._key_len = 4 + self._addr_len
        self._cache: set[str] = set()
        self._key = ctypes.create_string_buffer(self._key_len)
        self._next_key = ctypes.create_string_buffer(self._key_len)
        self._val = ctypes.create_string_buffer(4)
        self._update_attr = ctypes.create_string_buffer(128)
        self._lookup_attr = ctypes.create_string_buffer(128)
        self._delete_attr = ctypes.create_string_buffer(128)
        self._next_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        next_k_ptr = ctypes.cast(self._next_key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQQ", self._lookup_attr, 0, self.fd, k_ptr, v_ptr)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, k_ptr)
        struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, 0, next_k_ptr)
        self._load_cache()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _pack_key(self, cidr_str: str) -> str:
        if self._family == socket.AF_INET:
            net = ipaddress.IPv4Network(cidr_str, strict=False)
        else:
            net = ipaddress.IPv6Network(cidr_str, strict=False)
        addr_bytes = net.network_address.packed
        ctypes.memmove(self._key, struct.pack("=I", net.prefixlen) + addr_bytes, self._key_len)
        return f"{net.network_address}/{net.prefixlen}"

    def _unpack_key(self, key_raw: bytes) -> str:
        prefixlen = struct.unpack_from("=I", key_raw, 0)[0]
        addr_raw = key_raw[4:4 + self._addr_len]
        if self._family == socket.AF_INET:
            ip_str = socket.inet_ntoa(addr_raw)
        else:
            ip_str = socket.inet_ntop(socket.AF_INET6, addr_raw)
        return f"{ip_str}/{prefixlen}"

    def _update(self, cidr_str: str, val: int) -> str:
        normalized = self._pack_key(cidr_str)
        struct.pack_into("=I", self._val, 0, val)
        _bpf(_BPF_MAP_UPDATE_ELEM, self._update_attr)
        return normalized

    def _delete_key(self, cidr_str: str) -> str:
        normalized = self._pack_key(cidr_str)
        _bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
        return normalized

    def _lookup_raw_key(self, key_raw: bytes) -> int:
        ctypes.memmove(self._key, key_raw, self._key_len)
        _bpf(_BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
        return struct.unpack_from("=I", self._val, 0)[0]

    def _iter_raw_keys(self):
        current_ptr = 0
        while True:
            struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, current_ptr,
                             ctypes.cast(self._next_key, ctypes.c_void_p).value or 0)
            try:
                _bpf(_BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key.raw[:self._key_len])
            yield key_raw
            ctypes.memmove(self._key, key_raw, self._key_len)
            current_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0

    def _load_cache(self) -> None:
        try:
            for key_raw in self._iter_raw_keys():
                try:
                    if self._lookup_raw_key(key_raw):
                        self._cache.add(self._unpack_key(key_raw))
                except OSError:
                    continue
        except OSError:
            return

    def active_keys(self) -> set[str]:
        return set(self._cache)

    def set(self, cidr_str: str, val: int, dry_run: bool = False) -> bool:
        if not val:
            return self.delete(cidr_str, dry_run)
        if dry_run:
            log.info("[DRY] %s cidr %s -> 1", self.path, cidr_str)
            self._cache.add(cidr_str)
            return True
        try:
            normalized = self._update(cidr_str, 1)
            self._cache.add(normalized)
            return True
        except OSError as exc:
            log.warning("BPF update failed cidr=%s: %s", cidr_str, exc)
            return False

    def delete(self, cidr_str: str, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s delete cidr %s", self.path, cidr_str)
            self._cache.discard(cidr_str)
            return True
        try:
            normalized = self._delete_key(cidr_str)
            self._cache.discard(normalized)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.discard(cidr_str)
                return True
            log.warning("BPF delete failed cidr=%s: %s", cidr_str, exc)
            return False


class BpfTrustedMaps:
    """Pair of IPv4/IPv6 LPM trie maps for trusted source CIDRs."""

    def __init__(self, path4: str, path6: str) -> None:
        self._map4 = BpfLpmMap(path4, socket.AF_INET)
        self._map6 = BpfLpmMap(path6, socket.AF_INET6)

    def close(self) -> None:
        self._map4.close()
        self._map6.close()

    def active_keys(self) -> set[str]:
        return self._map4.active_keys() | self._map6.active_keys()

    def set(self, cidr_str: str, val: int, dry_run: bool = False) -> bool:
        if ":" in cidr_str:
            return self._map6.set(cidr_str, val, dry_run)
        return self._map4.set(cidr_str, val, dry_run)

    def delete(self, cidr_str: str, dry_run: bool = False) -> bool:
        if ":" in cidr_str:
            return self._map6.delete(cidr_str, dry_run)
        return self._map4.delete(cidr_str, dry_run)


class BpfAclMap:
    """Pinned BPF LPM_TRIE map for per-CIDR port ACLs (key=CIDR, value=port list)."""

    def __init__(self, path: str, family: int) -> None:
        self.path = path
        self.fd = _obj_get(path)
        self._family = family
        self._addr_len = 4 if family == socket.AF_INET else 16
        self._max_prefix = 32 if family == socket.AF_INET else 128
        self._key_len = 4 + self._addr_len
        self._cache: dict[str, frozenset[int]] = {}

        self._key = ctypes.create_string_buffer(self._key_len)
        self._next_key = ctypes.create_string_buffer(self._key_len)
        self._val = ctypes.create_string_buffer(_ACL_VAL_SIZE)
        self._update_attr = ctypes.create_string_buffer(128)
        self._lookup_attr = ctypes.create_string_buffer(128)
        self._delete_attr = ctypes.create_string_buffer(128)
        self._next_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        next_k_ptr = ctypes.cast(self._next_key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQQ", self._lookup_attr, 0, self.fd, k_ptr, v_ptr)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, k_ptr)
        struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, 0, next_k_ptr)
        self._load_cache()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _pack_key(self, cidr_str: str) -> str:
        if self._family == socket.AF_INET:
            net = ipaddress.IPv4Network(cidr_str, strict=False)
        else:
            net = ipaddress.IPv6Network(cidr_str, strict=False)
        addr_bytes = net.network_address.packed
        ctypes.memmove(self._key, struct.pack("=I", net.prefixlen) + addr_bytes, self._key_len)
        return f"{net.network_address}/{net.prefixlen}"

    def _unpack_key(self, key_raw: bytes) -> str:
        prefixlen = struct.unpack_from("=I", key_raw, 0)[0]
        addr_raw = key_raw[4:4 + self._addr_len]
        if self._family == socket.AF_INET:
            ip_str = socket.inet_ntoa(addr_raw)
        else:
            ip_str = socket.inet_ntop(socket.AF_INET6, addr_raw)
        return f"{ip_str}/{prefixlen}"

    def _pack_val(self, ports: list[int]) -> None:
        clamped = ports[:_ACL_MAX_PORTS]
        count = len(clamped)
        padded = clamped + [0] * (_ACL_MAX_PORTS - count)
        ctypes.memmove(self._val, struct.pack("=I" + "H" * _ACL_MAX_PORTS, count, *padded), _ACL_VAL_SIZE)

    def _unpack_val(self) -> frozenset[int]:
        count = struct.unpack_from("=I", self._val, 0)[0]
        count = min(count, _ACL_MAX_PORTS)
        ports = struct.unpack_from(f"={count}H", self._val, 4)
        return frozenset(ports)

    def _iter_raw_keys(self):
        current_ptr = 0
        while True:
            struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, current_ptr,
                             ctypes.cast(self._next_key, ctypes.c_void_p).value or 0)
            try:
                _bpf(_BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key.raw[:self._key_len])
            yield key_raw
            ctypes.memmove(self._key, key_raw, self._key_len)
            current_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0

    def _load_cache(self) -> None:
        try:
            for key_raw in self._iter_raw_keys():
                try:
                    ctypes.memmove(self._key, key_raw, self._key_len)
                    _bpf(_BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
                    cidr = self._unpack_key(key_raw)
                    self._cache[cidr] = self._unpack_val()
                except OSError:
                    continue
        except OSError:
            return

    def active_entries(self) -> dict[str, frozenset[int]]:
        return dict(self._cache)

    def set(self, cidr_str: str, ports: list[int], dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s cidr %s ports %s", self.path, cidr_str, ports)
            if self._family == socket.AF_INET:
                net = ipaddress.IPv4Network(cidr_str, strict=False)
            else:
                net = ipaddress.IPv6Network(cidr_str, strict=False)
            normalized = f"{net.network_address}/{net.prefixlen}"
            self._cache[normalized] = frozenset(ports)
            return True
        try:
            normalized = self._pack_key(cidr_str)
            self._pack_val(ports)
            _bpf(_BPF_MAP_UPDATE_ELEM, self._update_attr)
            self._cache[normalized] = frozenset(ports)
            return True
        except OSError as exc:
            log.warning("BPF ACL update failed cidr=%s: %s", cidr_str, exc)
            return False

    def delete(self, cidr_str: str, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s delete cidr %s", self.path, cidr_str)
            if self._family == socket.AF_INET:
                net = ipaddress.IPv4Network(cidr_str, strict=False)
            else:
                net = ipaddress.IPv6Network(cidr_str, strict=False)
            self._cache.pop(f"{net.network_address}/{net.prefixlen}", None)
            return True
        try:
            normalized = self._pack_key(cidr_str)
            _bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
            self._cache.pop(normalized, None)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                if self._family == socket.AF_INET:
                    net = ipaddress.IPv4Network(cidr_str, strict=False)
                else:
                    net = ipaddress.IPv6Network(cidr_str, strict=False)
                self._cache.pop(f"{net.network_address}/{net.prefixlen}", None)
                return True
            log.warning("BPF ACL delete failed cidr=%s: %s", cidr_str, exc)
            return False


class BpfAclMaps:
    """Four ACL LPM trie maps: TCP/UDP × IPv4/IPv6."""

    def __init__(self, tcp4: str, tcp6: str, udp4: str, udp6: str) -> None:
        self._tcp4 = BpfAclMap(tcp4, socket.AF_INET)
        self._tcp6 = BpfAclMap(tcp6, socket.AF_INET6)
        self._udp4 = BpfAclMap(udp4, socket.AF_INET)
        self._udp6 = BpfAclMap(udp6, socket.AF_INET6)

    def close(self) -> None:
        for m in (self._tcp4, self._tcp6, self._udp4, self._udp6):
            m.close()

    def _map_for(self, proto: str, cidr: str) -> BpfAclMap:
        is6 = ":" in cidr
        if proto == "tcp":
            return self._tcp6 if is6 else self._tcp4
        return self._udp6 if is6 else self._udp4

    def set(self, proto: str, cidr: str, ports: list[int], dry_run: bool = False) -> bool:
        return self._map_for(proto, cidr).set(cidr, ports, dry_run)

    def delete(self, proto: str, cidr: str, dry_run: bool = False) -> bool:
        return self._map_for(proto, cidr).delete(cidr, dry_run)

    def active_entries(self) -> dict[tuple[str, str], frozenset[int]]:
        """Returns {(proto, cidr): ports} for all currently active ACL entries."""
        result: dict[tuple[str, str], frozenset[int]] = {}
        for cidr, ports in self._tcp4.active_entries().items():
            result[("tcp", cidr)] = ports
        for cidr, ports in self._tcp6.active_entries().items():
            result[("tcp", cidr)] = ports
        for cidr, ports in self._udp4.active_entries().items():
            result[("udp", cidr)] = ports
        for cidr, ports in self._udp6.active_entries().items():
            result[("udp", cidr)] = ports
        return result


class BpfConntrackMap:
    """Pinned BPF LRU_HASH map (key = struct ct_key, value = __u64)."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = _obj_get(path)
        self._cache: set[bytes] = set()

        self._key = ctypes.create_string_buffer(40)
        self._next_key = ctypes.create_string_buffer(40)
        self._val = ctypes.create_string_buffer(8)
        self._attr = ctypes.create_string_buffer(128)
        self._next_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        next_k_ptr = ctypes.cast(self._next_key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, 0, next_k_ptr)
        self._load_cache()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def active_keys(self) -> set[bytes]:
        return set(self._cache)

    def _iter_raw_keys(self):
        current_ptr = 0
        while True:
            struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, current_ptr, ctypes.cast(self._next_key, ctypes.c_void_p).value or 0)
            try:
                _bpf(_BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key.raw[:40])
            yield key_raw
            ctypes.memmove(self._key, key_raw, 40)
            current_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0

    def _load_cache(self) -> None:
        try:
            for key_raw in self._iter_raw_keys():
                self._cache.add(key_raw)
        except OSError:
            return

    def set(self, key_bytes: bytes, dry_run: bool = False) -> bool:
        if dry_run:
            self._cache.add(key_bytes)
            return True
        try:
            ctypes.memmove(self._key, key_bytes, 40)
            # Use monotonic_ns as a stable timestamp for seeded flows.
            struct.pack_into("=Q", self._val, 0, time.monotonic_ns())
            _bpf(_BPF_MAP_UPDATE_ELEM, self._attr)
            self._cache.add(key_bytes)
            return True
        except OSError as exc:
            log.warning("BPF conntrack update failed: %s", exc)
            return False


def _port_rate_limit(port: int, proc: str = "") -> int:
    """Return the SYN rate limit for a TCP port, or 0 to skip rate limiting.

    Resolution order:
      1. Process name (_SYN_RATE_BY_PROC) — catches services on non-standard ports.
      2. IANA service name (_SYN_RATE_BY_SERVICE) — fallback for unknown processes.
      3. Anything else → 0 (no rate limit).
    """
    if proc:
        rate = _SYN_RATE_BY_PROC.get(proc)
        if rate is not None:
            return rate
    try:
        svc = socket.getservbyport(port, "tcp")
    except OSError:
        return 0
    return _SYN_RATE_BY_SERVICE.get(svc, 0)


def _udp_port_rate_limit(port: int, proc: str = "") -> int:
    """Return the UDP rate limit for a port, or 0 to skip rate limiting."""
    if proc:
        rate = _UDP_RATE_BY_PROC.get(proc)
        if rate is not None:
            return rate
    try:
        svc = socket.getservbyport(port, "udp")
    except OSError:
        return 0
    return _UDP_RATE_BY_SERVICE.get(svc, 0)


class BpfSynRatePortsMap:
    """Pinned BPF HASH map: key=__u32 dest_port, value=struct{u32 rate_max, u32 _pad}."""

    _VAL_SIZE = 8  # rate_max (__u32) + _pad (__u32)

    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = _obj_get(path)
        self._cache: dict[int, int] = {}  # port -> rate_max currently in map

        self._key = ctypes.create_string_buffer(4)
        self._next_key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(self._VAL_SIZE)
        self._update_attr = ctypes.create_string_buffer(128)
        self._lookup_attr = ctypes.create_string_buffer(128)
        self._delete_attr = ctypes.create_string_buffer(128)
        self._next_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        next_k_ptr = ctypes.cast(self._next_key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQQ", self._lookup_attr, 0, self.fd, k_ptr, v_ptr)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, k_ptr)
        struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, 0, next_k_ptr)
        self._load_cache()

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _iter_raw_keys(self):
        current_ptr = 0
        while True:
            struct.pack_into(
                "=I4xQQ", self._next_attr, 0, self.fd,
                current_ptr, ctypes.cast(self._next_key, ctypes.c_void_p).value or 0,
            )
            try:
                _bpf(_BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key.raw[:4])
            yield key_raw
            ctypes.memmove(self._key, key_raw, 4)
            current_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0

    def _load_cache(self) -> None:
        try:
            for key_raw in self._iter_raw_keys():
                port = struct.unpack_from("=I", key_raw)[0]
                ctypes.memmove(self._key, key_raw, 4)
                try:
                    _bpf(_BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
                    rate_max = struct.unpack_from("=I", self._val)[0]
                    self._cache[port] = rate_max
                except OSError:
                    continue
        except OSError:
            return

    def active(self) -> dict[int, int]:
        return dict(self._cache)

    def set(self, port: int, rate_max: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s port %d rate_max=%d", self.path, port, rate_max)
            self._cache[port] = rate_max
            return True
        try:
            struct.pack_into("=I", self._key, 0, port)
            struct.pack_into("=II", self._val, 0, rate_max, 0)
            _bpf(_BPF_MAP_UPDATE_ELEM, self._update_attr)
            self._cache[port] = rate_max
            return True
        except OSError as exc:
            log.warning("BPF syn_rate_ports update failed port=%d: %s", port, exc)
            return False

    def delete(self, port: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s delete port %d", self.path, port)
            self._cache.pop(port, None)
            return True
        try:
            struct.pack_into("=I", self._key, 0, port)
            _bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
            self._cache.pop(port, None)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.pop(port, None)
                return True
            log.warning("BPF syn_rate_ports delete failed port=%d: %s", port, exc)
            return False


class PortBackend:
    name = "backend"

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        trusted_target: set[str],
        conntrack_target: set[bytes],
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
        self.trusted_map = BpfTrustedMaps(TRUSTED_IPS_MAP_PATH4, TRUSTED_IPS_MAP_PATH6)
        self.conntrack_map = BpfConntrackMap(TCP_CONNTRACK_MAP_PATH)
        try:
            self.syn_rate_map: BpfSynRatePortsMap | None = BpfSynRatePortsMap(SYN_RATE_MAP_PATH)
            log.debug("syn_rate_ports map opened; per-service SYN rate limiting active.")
        except OSError as exc:
            log.debug("syn_rate_ports map unavailable (%s); SYN rate limiting inactive.", exc)
            self.syn_rate_map = None
        try:
            self.udp_rate_map: BpfSynRatePortsMap | None = BpfSynRatePortsMap(UDP_RATE_MAP_PATH)
            log.debug("udp_rate_ports map opened; per-source UDP rate limiting active.")
        except OSError as exc:
            log.debug("udp_rate_ports map unavailable (%s); UDP rate limiting inactive.", exc)
            self.udp_rate_map = None
        try:
            self.acl_maps: BpfAclMaps | None = BpfAclMaps(
                TCP_ACL_MAP_PATH4, TCP_ACL_MAP_PATH6,
                UDP_ACL_MAP_PATH4, UDP_ACL_MAP_PATH6,
            )
            log.debug("ACL maps opened; per-CIDR port ACL active.")
        except OSError as exc:
            log.debug("ACL maps unavailable (%s); per-CIDR ACL inactive.", exc)
            self.acl_maps = None

    def close(self) -> None:
        self.tcp_map.close()
        self.udp_map.close()
        self.trusted_map.close()
        self.conntrack_map.close()
        if self.syn_rate_map is not None:
            self.syn_rate_map.close()
        if self.udp_rate_map is not None:
            self.udp_rate_map.close()
        if self.acl_maps is not None:
            self.acl_maps.close()

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        trusted_target: set[str],
        conntrack_target: set[bytes],
        dry_run: bool,
    ) -> None:
        changed = False
        tcp_permanent = set(TCP_PERMANENT)
        udp_permanent = set(UDP_PERMANENT)
        trusted_permanent = set(TRUSTED_SRC_IPS)
        active_tcp = self.tcp_map.active_ports()
        active_udp = self.udp_map.active_ports()
        active_trusted = self.trusted_map.active_keys()
        active_conntrack = self.conntrack_map.active_keys()

        for port in sorted(tcp_target - active_tcp):
            tag = f" [{TCP_PERMANENT[port]}]" if port in TCP_PERMANENT else ""
            if self.tcp_map.set(port, 1, dry_run):
                log.debug("TCP +%d%s", port, tag)
                changed = True

        for port in sorted(active_tcp - tcp_target - tcp_permanent):
            if self.tcp_map.set(port, 0, dry_run):
                log.debug("TCP -%d  (stopped)", port)
                changed = True

        for port in sorted(udp_target - active_udp):
            tag = f" [{UDP_PERMANENT[port]}]" if port in UDP_PERMANENT else ""
            if self.udp_map.set(port, 1, dry_run):
                log.debug("UDP +%d%s", port, tag)
                changed = True

        for port in sorted(active_udp - udp_target - udp_permanent):
            if self.udp_map.set(port, 0, dry_run):
                log.debug("UDP -%d  (stopped)", port)
                changed = True

        # HASH maps need delete, not write-zero, when trust entries disappear.
        for ip_str in sorted(trusted_target - active_trusted):
            tag = f" [{TRUSTED_SRC_IPS[ip_str]}]" if ip_str in TRUSTED_SRC_IPS else ""
            if self.trusted_map.set(ip_str, 1, dry_run):
                log.info("TRUST +%s%s", ip_str, tag)
                changed = True

        for ip_str in sorted(active_trusted - trusted_target - trusted_permanent):
            if self.trusted_map.delete(ip_str, dry_run):
                log.info("TRUST -%s  (removed)", ip_str)
                changed = True

        # Periodic conntrack sync (seeding established flows)
        for flow in sorted(conntrack_target - active_conntrack):
            if self.conntrack_map.set(flow, dry_run):
                log.debug("CT +flow (established)")
                changed = True

        if not changed:
            log.debug("Whitelist up-to-date.")

        # Sync per-port SYN rate limits based on detected service types.
        if self.syn_rate_map is not None:
            self._sync_syn_rate(tcp_target, dry_run)

        if self.udp_rate_map is not None:
            self._sync_udp_rate(udp_target, dry_run)

        if self.acl_maps is not None:
            self._sync_acl(dry_run)

    def _sync_acl(self, dry_run: bool) -> None:
        if self.acl_maps is None:
            return
        desired: dict[tuple[str, str], frozenset[int]] = {}
        for rule in ACL_RULES:
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

    def _sync_syn_rate(self, tcp_ports: set[int], dry_run: bool) -> None:
        """Update syn_rate_ports to match the current set of whitelisted TCP ports."""
        active = self.syn_rate_map.active()  # type: ignore[union-attr]

        # Resolve port → process name so _port_rate_limit can catch services
        # on non-standard ports (e.g. sshd on 2222 won't match getservbyport).
        port_procs: dict[int, str] = {}
        if psutil is not None and _net_connections is not None:
            try:
                for conn in _net_connections(kind="inet"):
                    if not (conn.laddr and conn.laddr.port in tcp_ports):
                        continue
                    if conn.type != socket.SOCK_STREAM:
                        continue
                    if getattr(conn, "status", None) != psutil.CONN_LISTEN:
                        continue
                    pid = getattr(conn, "pid", None)
                    if pid is None:
                        continue
                    try:
                        port_procs[conn.laddr.port] = psutil.Process(pid).name()
                    except Exception:
                        pass
            except Exception:
                pass

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

    def _sync_udp_rate(self, udp_ports: set[int], dry_run: bool) -> None:
        """Update udp_rate_ports to match the current set of whitelisted UDP ports."""
        active = self.udp_rate_map.active()  # type: ignore[union-attr]

        desired: dict[int, int] = {}
        for port in udp_ports:
            rate = _udp_port_rate_limit(port)
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


class NftablesBackend(PortBackend):
    name = BACKEND_NFTABLES

    def __init__(self) -> None:
        if shutil.which("nft") is None:
            raise RuntimeError("nft command not found")
        self._tcp_cache: set[int] = set()
        self._udp_cache: set[int] = set()
        self._trusted_cache: set[str] = set()
        self._ensure_ruleset()

    def _ensure_ruleset(self) -> None:
        result = _run_nft(["list", "table", NFT_FAMILY, NFT_TABLE], check=False)
        if result.returncode == 0:
            body = result.stdout
            if all(marker in body for marker in (
                f"set {NFT_TCP_SET}", f"set {NFT_UDP_SET}",
                f"set {NFT_TRUSTED_SET4}", "chain input",
            )):
                return
            _run_nft(["delete", "table", NFT_FAMILY, NFT_TABLE], check=True)

        script = f"""table {NFT_FAMILY} {NFT_TABLE} {{
    set {NFT_TCP_SET} {{
        type inet_service
    }}

    set {NFT_UDP_SET} {{
        type inet_service
    }}

    set {NFT_TRUSTED_SET4} {{
        type ipv4_addr
        flags interval
    }}

    set {NFT_TRUSTED_SET6} {{
        type ipv6_addr
        flags interval
    }}

    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "lo" accept
        ct state established,related accept
        ip saddr @{NFT_TRUSTED_SET4} accept
        ip6 saddr @{NFT_TRUSTED_SET6} accept
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

    def _apply_trusted(self, trusted_target: set[str], dry_run: bool) -> None:
        v4 = {a for a in trusted_target if ":" not in a}
        v6 = {a for a in trusted_target if ":" in a}
        lines = [
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_TRUSTED_SET4}",
            f"flush set {NFT_FAMILY} {NFT_TABLE} {NFT_TRUSTED_SET6}",
        ]
        if v4:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_TRUSTED_SET4} {_render_nft_addrs(v4)}"
            )
        if v6:
            lines.append(
                f"add element {NFT_FAMILY} {NFT_TABLE} {NFT_TRUSTED_SET6} {_render_nft_addrs(v6)}"
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
            raise RuntimeError(f"nftables trusted-ip update failed: {stderr}") from exc

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        trusted_target: set[str],
        conntrack_target: set[bytes],
        dry_run: bool,
    ) -> None:
        changed = False
        _ = conntrack_target  # kernel conntrack handles established flows natively

        for ip_str in sorted(trusted_target - self._trusted_cache):
            tag = f" [{TRUSTED_SRC_IPS[ip_str]}]" if ip_str in TRUSTED_SRC_IPS else ""
            log.info("TRUST +%s%s", ip_str, tag)
            changed = True
        for ip_str in sorted(self._trusted_cache - trusted_target):
            log.info("TRUST -%s  (removed)", ip_str)
            changed = True

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
        self._apply_trusted(trusted_target, dry_run)
        self._tcp_cache = set(tcp_target)
        self._udp_cache = set(udp_target)
        self._trusted_cache = set(trusted_target)

        if not changed:
            log.debug("Whitelist up-to-date.")


@dataclass
class PortState:
    tcp: set[int] = field(default_factory=set)
    udp: set[int] = field(default_factory=set)
    established: set[bytes] = field(default_factory=set)


def get_listening_ports() -> PortState:
    """Read listening TCP/UDP ports and established TCP flows via psutil."""
    if psutil is None or _net_connections is None:
        sys.exit("psutil not installed. Run: pip3 install psutil")

    state = PortState()
    for conn in _net_connections(kind="inet"):
        if not (conn.laddr and conn.laddr.port):
            continue

        if conn.type == socket.SOCK_STREAM:
            if conn.status == psutil.CONN_LISTEN:
                state.tcp.add(conn.laddr.port)
            elif conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                try:
                    if conn.family == socket.AF_INET:
                        family = 2  # CT_FAMILY_IPV4
                        remote_ip = socket.inet_aton(conn.raddr.ip) + (b"\x00" * 12)
                        local_ip = socket.inet_aton(conn.laddr.ip) + (b"\x00" * 12)
                    elif conn.family == socket.AF_INET6:
                        family = 10  # CT_FAMILY_IPV6
                        remote_ip = socket.inet_pton(socket.AF_INET6, conn.raddr.ip)
                        local_ip = socket.inet_pton(socket.AF_INET6, conn.laddr.ip)
                    else:
                        continue
                    # struct ct_key { u8 family, u8 pad[3], be16 sport, be16 dport, u32 saddr[4], u32 daddr[4] }
                    key = struct.pack("!B3xHH16s16s", family, conn.raddr.port, conn.laddr.port, remote_ip, local_ip)
                    state.established.add(key)
                except Exception:
                    continue
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
    conntrack_target = current.established
    backend.sync_ports(tcp_target, udp_target, trusted_target, conntrack_target, dry_run)


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
    missing_xdp_maps = [path for path in REQUIRED_XDP_MAP_PATHS if not os.path.exists(path)]

    if name == BACKEND_XDP:
        if missing_xdp_maps:
            raise RuntimeError(f"required XDP maps missing: {', '.join(missing_xdp_maps)}")
        return XdpBackend()
    if name == BACKEND_NFTABLES:
        return NftablesBackend()
    if name != BACKEND_AUTO:
        raise RuntimeError(f"Unsupported backend: {name}")

    if not missing_xdp_maps:
        try:
            backend = XdpBackend()
            log.info("Backend selected: xdp")
            return backend
        except OSError as exc:
            log.warning("XDP backend unavailable (%s); trying nftables.", exc)
    elif missing_xdp_maps:
        log.warning("XDP maps incomplete (%s); trying nftables.", ", ".join(missing_xdp_maps))

    backend = NftablesBackend()
    log.info("Backend selected: nftables")
    return backend


def watch(interval: int, dry_run: bool, backend_name: str, config_path: str = TOML_CONFIG_PATH) -> None:
    backend = None
    nl = None

    last_sync_t = 0.0
    last_event_t = 0.0
    reload_requested = False

    def _on_sighup(signum: int, frame: object) -> None:
        nonlocal reload_requested
        reload_requested = True

    signal.signal(signal.SIGHUP, _on_sighup)

    try:
        while True:
            # Re-initialize backend if needed
            if backend is None:
                try:
                    backend = open_backend(backend_name)
                    log.info("Backend initialized.")
                    # Force a sync after (re)initialization
                    sync_once(backend, dry_run)
                    last_sync_t = time.monotonic()
                    last_event_t = 0.0
                except Exception as exc:
                    log.error("Failed to open backend: %s. Retrying in 5s...", exc)
                    time.sleep(5)
                    continue

            # Re-subscribe to netlink if needed
            if nl is None:
                nl = open_proc_connector()

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

            if reload_requested:
                reload_requested = False
                log.info("SIGHUP received — reloading config from %s", config_path)
                apply_toml_config(load_toml_config(config_path))
                last_sync_t = 0.0  # force sync on next iteration

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
                    # If it's a BPF/backend error, reset it for re-init
                    if isinstance(exc, (OSError, RuntimeError)):
                        log.warning("Backend may be broken; will attempt to re-initialize.")
                        backend.close()
                        backend = None

                last_sync_t = time.monotonic()
                last_event_t = 0.0

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        if backend:
            backend.close()


def main() -> None:
    def _parse_trusted_ip(ip_str: str) -> str:
        try:
            net = ipaddress.IPv4Network(ip_str, strict=False)
            return f"{net.network_address}/{net.prefixlen}"
        except ValueError:
            pass
        try:
            net = ipaddress.IPv6Network(ip_str, strict=False)
            return f"{net.network_address}/{net.prefixlen}"
        except ValueError:
            pass
        raise argparse.ArgumentTypeError(f"invalid IPv4/IPv6 address or CIDR: {ip_str}")

    p = argparse.ArgumentParser(description="Auto XDP port-whitelist sync daemon")
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
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default=DEFAULT_LOG_LEVEL.lower(),
        help="Set daemon log level (default: %(default)s)",
    )
    p.add_argument(
        "--trusted-ip",
        action="append",
        nargs=2,
        metavar=("IP", "LABEL"),
        default=[],
        help="Add a trusted IPv4/IPv6 source IP or CIDR and label (repeatable)",
    )
    p.add_argument(
        "--config",
        default=TOML_CONFIG_PATH,
        metavar="PATH",
        help=f"TOML config file path (default: {TOML_CONFIG_PATH})",
    )
    args = p.parse_args()
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    log.setLevel(getattr(logging, args.log_level.upper()))

    apply_toml_config(load_toml_config(args.config))

    try:
        for ip_str, label in args.trusted_ip:
            TRUSTED_SRC_IPS[_parse_trusted_ip(ip_str)] = label
    except argparse.ArgumentTypeError as exc:
        p.error(str(exc))

    backend = None
    try:
        if args.watch:
            watch(args.interval, args.dry_run, args.backend, args.config)
        else:
            backend = open_backend(args.backend)
            sync_once(backend, args.dry_run)
            log.info("Sync completed.")
    finally:
        if backend is not None:
            backend.close()


if __name__ == "__main__":
    main()
