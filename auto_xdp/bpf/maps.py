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

from auto_xdp import config as cfg
from auto_xdp.bpf.syscall import (
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    BPF_MAP_LOOKUP_ELEM,
    BPF_MAP_UPDATE_ELEM,
    bpf,
    obj_get,
)


log = logging.getLogger(__name__)


def render_nft_ports(ports: set[int]) -> str:
    return "{ " + ", ".join(str(port) for port in sorted(ports)) + " }"


def render_nft_addrs(addrs: set[str]) -> str:
    return "{ " + ", ".join(sorted(addrs)) + " }"


def run_nft(args: list[str], input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["nft", *args],
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
    )


class BpfArrayMap:
    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = obj_get(path)
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
        bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)

    def _lookup(self, port: int) -> int:
        struct.pack_into("=I", self._key, 0, port)
        bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
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
    def __init__(self, path: str, family: int) -> None:
        self.path = path
        self.fd = obj_get(path)
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
            self._cache.add(cfg.normalize_cidr(cidr_str))
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
            self._cache.discard(cfg.normalize_cidr(cidr_str))
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


class BpfTrustedMaps:
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
    def __init__(self, path: str, family: int) -> None:
        self.path = path
        self.fd = obj_get(path)
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

    def _load_cache(self) -> None:
        try:
            for key_raw in self._iter_raw_keys():
                try:
                    ctypes.memmove(self._key, key_raw, self._key_len)
                    bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
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
            self._cache[f"{net.network_address}/{net.prefixlen}"] = frozenset(ports)
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
            if self._family == socket.AF_INET:
                net = ipaddress.IPv4Network(cidr_str, strict=False)
            else:
                net = ipaddress.IPv6Network(cidr_str, strict=False)
            self._cache.pop(f"{net.network_address}/{net.prefixlen}", None)
            return True
        try:
            normalized = self._pack_key(cidr_str)
            bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
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
    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = obj_get(path)
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
                bpf(BPF_MAP_GET_NEXT_KEY, self._next_attr)
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

    def refresh_cache(self) -> None:
        self._cache.clear()
        self._load_cache()

    def set(self, key_bytes: bytes, dry_run: bool = False) -> bool:
        if dry_run:
            self._cache.add(key_bytes)
            return True
        try:
            ctypes.memmove(self._key, key_bytes, 40)
            struct.pack_into("=Q", self._val, 0, time.monotonic_ns())
            bpf(BPF_MAP_UPDATE_ELEM, self._attr)
            self._cache.add(key_bytes)
            return True
        except OSError as exc:
            log.warning("BPF conntrack update failed: %s", exc)
            return False


class BpfSynRatePortsMap:
    def __init__(self, path: str) -> None:
        self.path = path
        self.fd = obj_get(path)
        self._cache: dict[int, int] = {}
        self._key = ctypes.create_string_buffer(4)
        self._next_key = ctypes.create_string_buffer(4)
        self._val = ctypes.create_string_buffer(8)
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
            struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, current_ptr, ctypes.cast(self._next_key, ctypes.c_void_p).value or 0)
            try:
                bpf(BPF_MAP_GET_NEXT_KEY, self._next_attr)
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
                    bpf(BPF_MAP_LOOKUP_ELEM, self._lookup_attr)
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
            bpf(BPF_MAP_UPDATE_ELEM, self._update_attr)
            self._cache[port] = rate_max
            return True
        except OSError as exc:
            log.warning("BPF port config update failed path=%s port=%d: %s", self.path, port, exc)
            return False

    def delete(self, port: int, dry_run: bool = False) -> bool:
        if dry_run:
            log.info("[DRY] %s delete port %d", self.path, port)
            self._cache.pop(port, None)
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
