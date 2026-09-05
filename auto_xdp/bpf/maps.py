from __future__ import annotations

import ctypes
import errno
import ipaddress
import logging
import os
import socket
import struct
import subprocess
import time
from typing import Any

from auto_xdp import config as cfg
from auto_xdp.bpf.syscall import (
    BPF_F_LOCK,
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    BPF_MAP_LOOKUP_BATCH,
    BPF_MAP_LOOKUP_ELEM,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_UPDATE_ELEM,
    bpf,
    map_create,
    map_get_fd_by_id,
    map_id as _map_id,
    map_max_entries,
    obj_get,
)


log = logging.getLogger(__name__)

def render_nft_ports(ports: set[int]) -> str:
    return "{ " + ", ".join(str(port) for port in sorted(ports)) + " }"


def run_nft(args: list[str], input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["nft", *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
    )


class BpfBaseMap:
    def close(self) -> None:
        raise NotImplementedError

    def __del__(self) -> None:
        self.close()


class CacheVerifyMixin:
    """Kernel verification for userspace-owned config maps.

    Subclasses keep a local cache (set or dict) mirroring kernel contents and
    implement _read_kernel() as a pure read. verify() re-reads the kernel,
    repairs the cache on drift, and returns the discrepancy count. The next
    reconcile pass then restores any missing/extra kernel entries.
    """

    path: str
    _cache: Any

    def _read_kernel(self) -> Any:
        raise NotImplementedError

    def verify(self) -> int:
        kernel = self._read_kernel()
        if kernel == self._cache:
            return 0
        if isinstance(kernel, dict) and isinstance(self._cache, dict):
            keys = kernel.keys() | self._cache.keys()
            diff = sum(1 for k in keys if kernel.get(k) != self._cache.get(k))
        else:
            diff = len(set(kernel) ^ set(self._cache))
        log.warning(
            "BPF map cache drift path=%s discrepancies=%d; cache repaired from kernel",
            self.path, diff,
        )
        self._cache = kernel
        return diff


class BpfFdMap(BpfBaseMap):
    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = obj_get(path)

    def close(self) -> None:
        fd = getattr(self, "fd", -1)
        if fd >= 0:
            os.close(fd)
            self.fd = -1


class BpfArrayMap(CacheVerifyMixin, BpfFdMap):
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self._max_entries: int = map_max_entries(self.fd)
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

    def _update(self, port: int, val: int) -> None:
        struct.pack_into("=I", self._key, 0, port)
        struct.pack_into("=I", self._val, 0, val)
        bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)

    def _lookup(self, port: int) -> int:
        struct.pack_into("=I", self._key, 0, port)
        bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
        return struct.unpack_from("=I", self._val, 0)[0]

    def _read_kernel(self) -> set[int]:
        result: set[int] = set()
        n = self._max_entries
        keys_buf = ctypes.create_string_buffer(4 * n)
        vals_buf = ctypes.create_string_buffer(4 * n)
        out_batch = ctypes.create_string_buffer(4)
        attr = ctypes.create_string_buffer(56)
        # BPF_MAP_LOOKUP_BATCH attr: in_batch, out_batch, keys, values, count, map_fd, elem_flags, flags
        struct.pack_into(
            "=QQQQIIQQ", attr, 0,
            0,
            ctypes.cast(out_batch, ctypes.c_void_p).value or 0,
            ctypes.cast(keys_buf, ctypes.c_void_p).value or 0,
            ctypes.cast(vals_buf, ctypes.c_void_p).value or 0,
            n, self.fd, 0, 0,
        )
        try:
            bpf(BPF_MAP_LOOKUP_BATCH, attr)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                # Kernel too old or other error; fall back to sequential scan.
                for port in range(n):
                    try:
                        if self._lookup(port):
                            result.add(port)
                    except OSError:
                        continue
                return result
            # ENOENT: end of map; kernel has written the fetched count back to attr.
        fetched = struct.unpack_from("=I", attr, 32)[0]
        for i in range(fetched):
            if struct.unpack_from("=I", vals_buf, i * 4)[0]:
                result.add(struct.unpack_from("=I", keys_buf, i * 4)[0])
        return result

    def _load_cache(self) -> None:
        self._cache = self._read_kernel()

    def active_ports(self) -> set[int]:
        return set(self._cache)

    def map_id(self) -> int:
        return _map_id(self.fd)

    def get(self, port: int) -> int:
        return 1 if port in self._cache else 0

    def set(self, port: int, val: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s port %d -> %d", self.path, port, val)
            return True
        try:
            self._update(port, val)
            self._cache.add(port) if val else self._cache.discard(port)
            return True
        except OSError as exc:
            log.warning("BPF update failed port=%d: %s", port, exc)
            return False


class BpfZonePortMap(CacheVerifyMixin, BpfFdMap):
    """Interface-index/port admission map for non-public exposure grants."""

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self._cache: set[tuple[int, int]] = set()
        self._key = ctypes.create_string_buffer(8)
        self._next_key = ctypes.create_string_buffer(8)
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

    def _pack_key(self, ifindex: int, port: int) -> tuple[int, int]:
        key = (int(ifindex), int(port))
        struct.pack_into("=II", self._key, 0, *key)
        return key

    def _iter_raw_keys(self):
        current_ptr = 0
        while True:
            struct.pack_into(
                "=I4xQQ", self._next_attr, 0, self.fd, current_ptr,
                ctypes.cast(self._next_key, ctypes.c_void_p).value or 0,
            )
            try:
                bpf(BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key.raw[:8])
            yield key_raw
            ctypes.memmove(self._key, key_raw, 8)
            current_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0

    def _read_kernel(self) -> set[tuple[int, int]]:
        result: set[tuple[int, int]] = set()
        try:
            for key_raw in self._iter_raw_keys():
                try:
                    ctypes.memmove(self._key, key_raw, 8)
                    bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
                    if struct.unpack_from("=I", self._val, 0)[0]:
                        result.add(struct.unpack_from("=II", self._key, 0))
                except OSError:
                    continue
        except OSError:
            pass
        return result

    def _load_cache(self) -> None:
        self._cache = self._read_kernel()

    def active_entries(self) -> set[tuple[int, int]]:
        return set(self._cache)

    def set(self, ifindex: int, port: int, val: int = 1, dry_run: bool = False) -> bool:
        key = self._pack_key(ifindex, port)
        if not val:
            return self.delete(*key, dry_run=dry_run)
        if dry_run:
            log.info("[DRY] %s %s -> 1", self.path, key)
            return True
        try:
            struct.pack_into("=I", self._val, 0, 1)
            bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
            self._cache.add(key)
            return True
        except OSError as exc:
            log.warning("BPF zone update failed key=%s: %s", key, exc)
            return False

    def delete(self, ifindex: int, port: int, dry_run: bool = False) -> bool:
        key = self._pack_key(ifindex, port)
        if dry_run:
            log.info("[DRY] %s delete %s", self.path, key)
            return True
        try:
            bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
            self._cache.discard(key)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.discard(key)
                return True
            log.warning("BPF zone delete failed key=%s: %s", self.path, exc)
            return False


XDP_CFG_FLAG_BOGON_DISABLED       = 1 << 0  # bogon filter off (default: on)
XDP_CFG_FLAG_ABUSEIPDB_ENABLED    = 1 << 1  # AbuseIPDB active (default: off)
XDP_CFG_FLAG_DROP_EVENTS_DISABLED = 1 << 2  # ring-buf events off (default: on)
XDP_CFG_FLAG_SLOT_DROP            = 1 << 3  # unknown proto → drop (default: pass)


class BpfRuntimeConfigMap(BpfFdMap):
    # 8 × u64 timing fields + u32 cfg_flags + u32 _pad
    _STRUCT_FMT = "=QQQQQQQQII"
    _STRUCT_SIZE = struct.calcsize(_STRUCT_FMT)

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self._key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(self._STRUCT_SIZE)
        self._update_attr = ctypes.create_string_buffer(128)
        self._lookup_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQQ", self._lookup_attr, 0, self.fd, k_ptr, v_ptr)

    def _lookup_raw(self) -> tuple[int, ...] | None:
        try:
            struct.pack_into("=I", self._key, 0, 0)
            bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
            return struct.unpack_from(self._STRUCT_FMT, self._val, 0)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                log.warning("BPF runtime config lookup failed path=%s: %s", self.path, exc)
            return None

    def get(self) -> tuple[int, int, int, int, int, int, int, int] | None:
        raw = self._lookup_raw()
        return raw[:8] if raw is not None else None  # type: ignore[return-value]

    def get_cfg_flags(self) -> int | None:
        raw = self._lookup_raw()
        return raw[8] if raw is not None else None

    def set(self, fields: tuple[int, int, int, int, int, int, int, int],
            cfg_flags: int = 0, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s runtime_config=%s cfg_flags=0x%x", self.path, fields, cfg_flags)
            return True
        try:
            struct.pack_into("=I", self._key, 0, 0)
            struct.pack_into(self._STRUCT_FMT, self._val, 0, *fields, cfg_flags, 0)
            bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
            return True
        except OSError as exc:
            log.warning("BPF runtime config update failed path=%s: %s", self.path, exc)
            return False


class BpfGlobalRlMap(BpfFdMap):
    # struct udp_global_state: lock(4) + byte_rate_max(4) + window_start_ns(8) + prev_bytes(8) + curr_bytes(8) + blocked_until_ns(8)
    _STRUCT_FMT = "=IIQQQQ"
    _STRUCT_SIZE = struct.calcsize(_STRUCT_FMT)  # 40 bytes

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self._key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(self._STRUCT_SIZE)
        self._update_attr = ctypes.create_string_buffer(128)
        self._lookup_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, BPF_F_LOCK)
        struct.pack_into("=I4xQQQ", self._lookup_attr, 0, self.fd, k_ptr, v_ptr, BPF_F_LOCK)

    def get(self) -> int:
        try:
            struct.pack_into("=I", self._key, 0, 0)
            bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
            _, byte_rate_max, _, _, _, _ = struct.unpack_from(self._STRUCT_FMT, self._val, 0)
            return byte_rate_max
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                log.warning("BPF global rl lookup failed path=%s: %s", self.path, exc)
            return 0

    def set(self, byte_rate_max: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s global_rl byte_rate_max=%d bytes/s", self.path, byte_rate_max)
            return True
        try:
            struct.pack_into("=I", self._key, 0, 0)
            struct.pack_into(self._STRUCT_FMT, self._val, 0, 0, byte_rate_max, 0, 0, 0, 0)
            bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
            return True
        except OSError as exc:
            log.warning("BPF global rl update failed path=%s: %s", self.path, exc)
            return False


class BpfLpmMap(CacheVerifyMixin, BpfFdMap):
    def __init__(self, path: str, family: int) -> None:
        super().__init__(path)
        self._family = family
        self._addr_len = 4 if family == socket.AF_INET else 16
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

    def _pack_key(self, cidr_str: str) -> str:
        net: ipaddress.IPv4Network | ipaddress.IPv6Network
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
        bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
        return normalized

    def _delete_key(self, cidr_str: str) -> str:
        normalized = self._pack_key(cidr_str)
        bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
        return normalized

    def _lookup_raw_key(self, key_raw: bytes) -> int:
        ctypes.memmove(self._key, key_raw, self._key_len)
        bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
        return struct.unpack_from("=I", self._val, 0)[0]

    def _iter_raw_keys(self):
        current_ptr = 0
        while True:
            struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, current_ptr, ctypes.cast(self._next_key, ctypes.c_void_p).value or 0)
            try:
                bpf(BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key.raw[:self._key_len])
            yield key_raw
            ctypes.memmove(self._key, key_raw, self._key_len)
            current_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0

    def _read_kernel(self) -> set[str]:
        result: set[str] = set()
        try:
            for key_raw in self._iter_raw_keys():
                try:
                    if self._lookup_raw_key(key_raw):
                        result.add(self._unpack_key(key_raw))
                except OSError:
                    continue
        except OSError:
            pass
        return result

    def _load_cache(self) -> None:
        self._cache = self._read_kernel()

    def active_keys(self) -> set[str]:
        return set(self._cache)

    def set(self, cidr_str: str, val: int, dry_run: bool = False) -> bool:
        if not val:
            return self.delete(cidr_str, dry_run)
        if dry_run:
            log.info("[DRY] %s cidr %s -> 1", self.path, cidr_str)
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
            return True
        try:
            normalized = self._delete_key(cidr_str)
            self._cache.discard(normalized)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.discard(cfg.normalize_cidr(cidr_str))
                return True
            log.warning("BPF delete failed cidr=%s: %s", cidr_str, exc)
            return False


class BpfTrustedMaps(BpfBaseMap):
    def __init__(self, path4: str, path6: str) -> None:
        self._map4 = BpfLpmMap(path4, socket.AF_INET)
        self._map6 = BpfLpmMap(path6, socket.AF_INET6)

    def close(self) -> None:
        if (map4 := getattr(self, "_map4", None)) is not None:
            map4.close()
        if (map6 := getattr(self, "_map6", None)) is not None:
            map6.close()

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

    def verify(self) -> int:
        return self._map4.verify() + self._map6.verify()


class BpfAclMap(CacheVerifyMixin, BpfFdMap):
    def __init__(self, path: str, family: int) -> None:
        super().__init__(path)
        self._family = family
        self._addr_len = 4 if family == socket.AF_INET else 16
        self._key_len = 4 + self._addr_len
        self._cache: dict[str, frozenset[int]] = {}
        self._key = ctypes.create_string_buffer(self._key_len)
        self._next_key = ctypes.create_string_buffer(self._key_len)
        self._val = ctypes.create_string_buffer(cfg.ACL_VAL_SIZE)
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

    def _pack_key(self, cidr_str: str) -> str:
        net: ipaddress.IPv4Network | ipaddress.IPv6Network
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
        clamped = ports[:cfg.ACL_MAX_PORTS]
        count = len(clamped)
        padded = clamped + [0] * (cfg.ACL_MAX_PORTS - count)
        ctypes.memmove(self._val, struct.pack("=I" + "H" * cfg.ACL_MAX_PORTS, count, *padded), cfg.ACL_VAL_SIZE)

    def _unpack_val(self) -> frozenset[int]:
        count = struct.unpack_from("=I", self._val, 0)[0]
        count = min(count, cfg.ACL_MAX_PORTS)
        ports = struct.unpack_from(f"={count}H", self._val, 4)
        return frozenset(ports)

    def _iter_raw_keys(self):
        current_ptr = 0
        while True:
            struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, current_ptr, ctypes.cast(self._next_key, ctypes.c_void_p).value or 0)
            try:
                bpf(BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key.raw[:self._key_len])
            yield key_raw
            ctypes.memmove(self._key, key_raw, self._key_len)
            current_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0

    def _read_kernel(self) -> dict[str, frozenset[int]]:
        result: dict[str, frozenset[int]] = {}
        try:
            for key_raw in self._iter_raw_keys():
                try:
                    ctypes.memmove(self._key, key_raw, self._key_len)
                    bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
                    cidr = self._unpack_key(key_raw)
                    result[cidr] = self._unpack_val()
                except OSError:
                    continue
        except OSError:
            pass
        return result

    def _load_cache(self) -> None:
        self._cache = self._read_kernel()

    def active_entries(self) -> dict[str, frozenset[int]]:
        return dict(self._cache)

    def set(self, cidr_str: str, ports: list[int], dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s cidr %s ports %s", self.path, cidr_str, ports)
            return True
        try:
            normalized = self._pack_key(cidr_str)
            self._pack_val(ports)
            bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
            self._cache[normalized] = frozenset(ports)
            return True
        except OSError as exc:
            log.warning("BPF ACL update failed cidr=%s: %s", cidr_str, exc)
            return False

    def delete(self, cidr_str: str, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s delete cidr %s", self.path, cidr_str)
            return True
        try:
            normalized = self._pack_key(cidr_str)
            bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
            self._cache.pop(normalized, None)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.pop(normalized, None)
                return True
            log.warning("BPF ACL delete failed cidr=%s: %s", cidr_str, exc)
            return False


class BpfAclMaps(BpfBaseMap):
    def __init__(self, tcp4: str, tcp6: str, udp4: str, udp6: str) -> None:
        self._tcp4 = BpfAclMap(tcp4, socket.AF_INET)
        self._tcp6 = BpfAclMap(tcp6, socket.AF_INET6)
        self._udp4 = BpfAclMap(udp4, socket.AF_INET)
        self._udp6 = BpfAclMap(udp6, socket.AF_INET6)

    def close(self) -> None:
        for attr in ("_tcp4", "_tcp6", "_udp4", "_udp6"):
            if (map_obj := getattr(self, attr, None)) is not None:
                map_obj.close()

    def _map_for(self, proto: str, cidr: str) -> BpfAclMap:
        is6 = ":" in cidr
        if proto == "tcp":
            return self._tcp6 if is6 else self._tcp4
        return self._udp6 if is6 else self._udp4

    def set(self, proto: str, cidr: str, ports: list[int], dry_run: bool = False) -> bool:
        return self._map_for(proto, cidr).set(cidr, ports, dry_run)

    def delete(self, proto: str, cidr: str, dry_run: bool = False) -> bool:
        return self._map_for(proto, cidr).delete(cidr, dry_run)

    def verify(self) -> int:
        return (
            self._tcp4.verify() + self._tcp6.verify()
            + self._udp4.verify() + self._udp6.verify()
        )

    def active_entries(self) -> dict[tuple[str, str], frozenset[int]]:
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


class BpfSynRatePortsMap(CacheVerifyMixin, BpfFdMap):
    def __init__(self, path: str) -> None:
        super().__init__(path)
        self._max_entries: int = map_max_entries(self.fd)
        self._cache: dict[int, int] = {}
        self._key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(8)
        self._update_attr = ctypes.create_string_buffer(128)
        self._delete_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, k_ptr)
        self._load_cache()

    def _read_kernel(self) -> dict[int, int]:
        result: dict[int, int] = {}
        n = self._max_entries
        keys_buf = ctypes.create_string_buffer(4 * n)
        vals_buf = ctypes.create_string_buffer(8 * n)
        out_batch = ctypes.create_string_buffer(4)
        attr = ctypes.create_string_buffer(56)
        struct.pack_into(
            "=QQQQIIQQ", attr, 0,
            0,
            ctypes.cast(out_batch, ctypes.c_void_p).value or 0,
            ctypes.cast(keys_buf, ctypes.c_void_p).value or 0,
            ctypes.cast(vals_buf, ctypes.c_void_p).value or 0,
            n, self.fd, 0, 0,
        )
        try:
            bpf(BPF_MAP_LOOKUP_BATCH, attr)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                return result
        fetched = struct.unpack_from("=I", attr, 32)[0]
        for i in range(fetched):
            port = struct.unpack_from("=I", keys_buf, i * 4)[0]
            rate_max = struct.unpack_from("=I", vals_buf, i * 8)[0]
            result[port] = rate_max
        return result

    def _load_cache(self) -> None:
        self._cache = self._read_kernel()

    def active(self) -> dict[int, int]:
        return dict(self._cache)

    def set(self, port: int, rate_max: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s port %d rate_max=%d", self.path, port, rate_max)
            return True
        try:
            struct.pack_into("=I", self._key, 0, port)
            struct.pack_into("=II", self._val, 0, rate_max, 0)
            bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
            self._cache[port] = rate_max
            return True
        except OSError as exc:
            log.warning("BPF port config update failed path=%s port=%d: %s", self.path, port, exc)
            return False

    def delete(self, port: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s delete port %d", self.path, port)
            return True
        try:
            struct.pack_into("=I", self._key, 0, port)
            bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
            self._cache.pop(port, None)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.pop(port, None)
                return True
            log.warning("BPF port config delete failed path=%s port=%d: %s", self.path, port, exc)
            return False


class BpfRateOuterMap(CacheVerifyMixin, BpfFdMap):
    """ARRAY_OF_MAPS outer keyed by dport; each occupied slot holds a
    per-port LRU inner matching the compiled map template exactly.

    Cache shape: {dport: inner max_entries}.
    """

    def __init__(self, path: str, inner_key_size: int,
                 inner_value_size: int, inner_max_entries: int,
                 name_prefix: str) -> None:
        super().__init__(path)
        self._inner_key_size = inner_key_size
        self._inner_value_size = inner_value_size
        self._inner_max_entries = inner_max_entries
        self._name_prefix = name_prefix
        self._max_entries: int = map_max_entries(self.fd)
        self._cache: dict[int, int] = self._read_kernel()

    def active(self) -> dict[int, int]:
        return dict(self._cache)

    def _read_kernel(self) -> dict[int, int]:
        """Full slot scan. O(65536) lookups; runs at init and on verify()
        (30s cadence / after failed applies) — accepted cost."""
        out: dict[int, int] = {}
        key = ctypes.create_string_buffer(4)
        val = ctypes.create_string_buffer(4)
        attr = ctypes.create_string_buffer(64)
        k_ptr = ctypes.cast(key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQ", attr, 0, self.fd, k_ptr, v_ptr)
        for port in range(self._max_entries):
            struct.pack_into("=I", key, 0, port)
            try:
                bpf(BPF_MAP_LOOKUP_ELEM, attr)
            except OSError:
                continue  # empty slot
            (inner_id,) = struct.unpack_from("=I", val, 0)
            try:
                ifd = map_get_fd_by_id(inner_id)
            except OSError:
                continue
            try:
                out[port] = map_max_entries(ifd)
            finally:
                os.close(ifd)
        return out

    def _update_slot(self, port: int, inner_fd: int) -> bool:
        key = ctypes.create_string_buffer(4)
        val = ctypes.create_string_buffer(4)
        attr = ctypes.create_string_buffer(64)
        struct.pack_into("=I", key, 0, port)
        struct.pack_into("=I", val, 0, inner_fd)
        k_ptr = ctypes.cast(key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", attr, 0, self.fd, k_ptr, v_ptr, 0)
        try:
            bpf(BPF_MAP_UPDATE_ELEM, attr)
            return True
        except OSError as exc:
            log.error("rate outer %s: slot update port=%d failed: %s",
                      self.path, port, exc)
            return False

    def _delete_slot(self, port: int) -> bool:
        key = ctypes.create_string_buffer(4)
        attr = ctypes.create_string_buffer(64)
        struct.pack_into("=I", key, 0, port)
        k_ptr = ctypes.cast(key, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQ", attr, 0, self.fd, k_ptr)
        try:
            bpf(BPF_MAP_DELETE_ELEM, attr)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                return True
            log.error("rate outer %s: slot delete port=%d failed: %s",
                      self.path, port, exc)
            return False

    def set(self, port: int, capacity: int, dry_run: bool = False) -> bool:
        if capacity != self._inner_max_entries:
            log.error(
                "rate outer %s: inner capacity %d does not match compiled template %d",
                self.path, capacity, self._inner_max_entries,
            )
            return False
        if self._cache.get(port) == capacity:
            return True
        if dry_run:
            log.info("[DRY] %s port %d inner entries=%d", self.path, port, capacity)
            return True
        name = f"{self._name_prefix}{port}".encode()[:15]
        try:
            inner_fd = map_create(BPF_MAP_TYPE_LRU_HASH,
                                  self._inner_key_size,
                                  self._inner_value_size,
                                  capacity, 0, name=name)
        except OSError as exc:
            log.error("rate outer %s: inner create port=%d entries=%d failed: %s",
                      self.path, port, capacity, exc)
            return False
        try:
            if not self._update_slot(port, inner_fd):
                return False
        finally:
            os.close(inner_fd)
        self._cache[port] = capacity
        return True

    def delete(self, port: int, dry_run: bool = False) -> bool:
        if port not in self._cache:
            return True
        if dry_run:
            log.info("[DRY] %s delete port %d", self.path, port)
            return True
        if not self._delete_slot(port):
            return False
        self._cache.pop(port, None)
        return True


class BpfPortPolicyMap(CacheVerifyMixin, BpfFdMap):
    _STRUCT_FMT = "=IIIIIIII"
    _STRUCT_SIZE = struct.calcsize(_STRUCT_FMT)

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self._max_entries: int = map_max_entries(self.fd)
        self._cache: dict[int, tuple[int, ...]] = {}
        self._key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(self._STRUCT_SIZE)
        self._update_attr = ctypes.create_string_buffer(128)
        self._delete_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, k_ptr)
        self._load_cache()

    def _read_kernel(self) -> dict[int, tuple[int, ...]]:
        result: dict[int, tuple[int, ...]] = {}
        n = self._max_entries
        keys_buf = ctypes.create_string_buffer(4 * n)
        vals_buf = ctypes.create_string_buffer(self._STRUCT_SIZE * n)
        out_batch = ctypes.create_string_buffer(4)
        attr = ctypes.create_string_buffer(56)
        struct.pack_into(
            "=QQQQIIQQ", attr, 0,
            0,
            ctypes.cast(out_batch, ctypes.c_void_p).value or 0,
            ctypes.cast(keys_buf, ctypes.c_void_p).value or 0,
            ctypes.cast(vals_buf, ctypes.c_void_p).value or 0,
            n, self.fd, 0, 0,
        )
        try:
            bpf(BPF_MAP_LOOKUP_BATCH, attr)
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                return result
        fetched = struct.unpack_from("=I", attr, 32)[0]
        for i in range(fetched):
            port = struct.unpack_from("=I", keys_buf, i * 4)[0]
            result[port] = struct.unpack_from(self._STRUCT_FMT, vals_buf, i * self._STRUCT_SIZE)
        return result

    def _load_cache(self) -> None:
        self._cache = self._read_kernel()

    def active_structs(self) -> dict[int, tuple[int, ...]]:
        return dict(self._cache)

    def set_fields(self, port: int, fields: tuple[int, ...], dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s port %d fields=%s", self.path, port, fields)
            return True
        try:
            struct.pack_into("=I", self._key, 0, port)
            struct.pack_into(self._STRUCT_FMT, self._val, 0, *fields)
            bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
            self._cache[port] = fields
            return True
        except OSError as exc:
            log.warning("BPF port policy update failed path=%s port=%d: %s", self.path, port, exc)
            return False

    def ensure_prefixes(self, ports: set[int], prefix_v4: int, prefix_v6: int, dry_run: bool = False) -> None:
        for port in sorted(ports):
            current = self._cache.get(port)
            if current is None:
                continue
            updated = list(current)
            updated[3] = prefix_v4
            updated[4] = prefix_v6
            fields = tuple(updated)
            if fields != current:
                self.set_fields(port, fields, dry_run)

    def delete(self, port: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s delete port %d", self.path, port)
            return True
        try:
            struct.pack_into("=I", self._key, 0, port)
            bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
            self._cache.pop(port, None)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.pop(port, None)
                return True
            log.warning("BPF port policy delete failed path=%s port=%d: %s", self.path, port, exc)
            return False


class BpfPortPolicyViewMap:
    def __init__(self, backing: BpfPortPolicyMap, field_index: int, path: str) -> None:
        self._backing = backing
        self._field_index = field_index
        self.path = path

    def active(self) -> dict[int, int]:
        return {
            port: fields[self._field_index]
            for port, fields in self._backing.active_structs().items()
            if fields[self._field_index] != 0
        }

    def set(self, port: int, rate_max: int, dry_run: bool = False) -> bool:
        current = self._backing.active_structs().get(
            port,
            (0, 0, 0, cfg.RATE_LIMIT_SOURCE_PREFIX_V4, cfg.RATE_LIMIT_SOURCE_PREFIX_V6, 0, 0, 0),
        )
        updated = list(current)
        updated[self._field_index] = rate_max
        fields = tuple(updated)
        if fields[:3] == (0, 0, 0):
            return self._backing.delete(port, dry_run)
        return self._backing.set_fields(port, fields, dry_run)

    def delete(self, port: int, dry_run: bool = False) -> bool:
        current = self._backing.active_structs().get(port)
        if current is None:
            return self._backing.delete(port, dry_run)
        updated = list(current)
        updated[self._field_index] = 0
        fields = tuple(updated)
        if fields[:3] == (0, 0, 0):
            return self._backing.delete(port, dry_run)
        return self._backing.set_fields(port, fields, dry_run)


class BpfSit4EndpointsMap(CacheVerifyMixin, BpfFdMap):
    """Hash map: outer IPv4 source → allowed (1) for 6in4 tunnel endpoints.

    Key: 4-byte network-order IPv4 address (__be32).
    Value: 4-byte __u32 (1 = allow).
    """

    def __init__(self, path: str) -> None:
        super().__init__(path)
        self._cache: set[str] = set()
        self._key = ctypes.create_string_buffer(4)
        self._next_key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(4)
        self._update_attr = ctypes.create_string_buffer(128)
        self._lookup_attr = ctypes.create_string_buffer(128)
        self._delete_attr = ctypes.create_string_buffer(128)
        self._next_attr = ctypes.create_string_buffer(128)
        k_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        nk_ptr = ctypes.cast(self._next_key, ctypes.c_void_p).value or 0
        v_ptr = ctypes.cast(self._val, ctypes.c_void_p).value or 0
        struct.pack_into("=I4xQQQ", self._update_attr, 0, self.fd, k_ptr, v_ptr, 0)
        struct.pack_into("=I4xQQ", self._lookup_attr, 0, self.fd, k_ptr, v_ptr)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, k_ptr)
        struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, 0, nk_ptr)
        self._load_cache()

    def _pack_key(self, ip_str: str) -> None:
        ctypes.memmove(self._key, socket.inet_aton(ip_str), 4)

    def _read_kernel(self) -> set[str]:
        result: set[str] = set()
        current_ptr = 0
        while True:
            struct.pack_into(
                "=I4xQQ", self._next_attr, 0, self.fd,
                current_ptr,
                ctypes.cast(self._next_key, ctypes.c_void_p).value or 0,
            )
            try:
                bpf(BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key.raw[:4])
            result.add(socket.inet_ntoa(key_raw))
            ctypes.memmove(self._key, key_raw, 4)
            current_ptr = ctypes.cast(self._key, ctypes.c_void_p).value or 0
        return result

    def _load_cache(self) -> None:
        self._cache = self._read_kernel()

    def active_keys(self) -> set[str]:
        return set(self._cache)

    def set(self, ip_str: str, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s sit4 +%s", self.path, ip_str)
            return True
        try:
            self._pack_key(ip_str)
            struct.pack_into("=I", self._val, 0, 1)
            bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
            self._cache.add(ip_str)
            return True
        except OSError as exc:
            log.warning("BPF sit4_endpoints update failed ip=%s: %s", ip_str, exc)
            return False

    def delete(self, ip_str: str, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s sit4 -%s", self.path, ip_str)
            return True
        try:
            self._pack_key(ip_str)
            bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
            self._cache.discard(ip_str)
            return True
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                self._cache.discard(ip_str)
                return True
            log.warning("BPF sit4_endpoints delete failed ip=%s: %s", ip_str, exc)
            return False
