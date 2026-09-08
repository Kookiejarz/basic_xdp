from __future__ import annotations

import ctypes
import ctypes.util
import os
import platform
import struct


_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
NR_BPF: int = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)

BPF_MAP_CREATE = 0
BPF_MAP_LOOKUP_ELEM = 1
BPF_MAP_UPDATE_ELEM = 2
BPF_MAP_DELETE_ELEM = 3
BPF_MAP_GET_NEXT_KEY = 4
BPF_OBJ_GET = 7
BPF_MAP_GET_FD_BY_ID = 14
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_MAP_LOOKUP_BATCH = 24
BPF_F_LOCK = 4

BPF_MAP_TYPE_LRU_HASH = 9
BPF_MAP_TYPE_ARRAY_OF_MAPS = 12


def bpf(cmd: int, attr: ctypes.Array | bytearray | memoryview) -> int:
    if isinstance(attr, (bytearray, memoryview)):
        attr_ptr = ctypes.addressof(ctypes.c_char.from_buffer(attr))
    else:
        attr_ptr = ctypes.cast(attr, ctypes.c_void_p).value or 0
    ret = _libc.syscall(
        NR_BPF,
        ctypes.c_int(cmd),
        ctypes.c_void_p(attr_ptr),
        ctypes.c_uint(len(attr)),
    )
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def obj_get(path: str) -> int:
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return bpf(BPF_OBJ_GET, attr)


def _map_info_u32(fd: int, offset: int) -> int:
    info = ctypes.create_string_buffer(128)
    attr = ctypes.create_string_buffer(16)
    info_ptr = ctypes.cast(info, ctypes.c_void_p).value or 0
    struct.pack_into("=IIQ", attr, 0, fd, len(info), info_ptr)
    bpf(BPF_OBJ_GET_INFO_BY_FD, attr)
    return struct.unpack_from("=I", info, offset)[0]


def map_max_entries(fd: int) -> int:
    """Return the max_entries of an open BPF map fd."""
    return _map_info_u32(fd, 16)


def map_value_size(fd: int) -> int:
    """Return the value_size of an open BPF map fd."""
    return _map_info_u32(fd, 12)


def map_id(fd: int) -> int:
    """Return the kernel-assigned map ID for an open BPF map fd."""
    return _map_info_u32(fd, 4)


def map_create(map_type: int, key_size: int, value_size: int,
               max_entries: int, map_flags: int = 0,
               inner_map_fd: int = 0, name: bytes = b"") -> int:
    """BPF_MAP_CREATE. Returns the new map fd (caller closes)."""
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=IIIIII", attr, 0, map_type, key_size, value_size,
                     max_entries, map_flags, inner_map_fd)
    # numa_node at 24 stays 0; map_name is 16 bytes at offset 28.
    struct.pack_into("16s", attr, 28, name[:15])
    return bpf(BPF_MAP_CREATE, attr)


def map_get_fd_by_id(map_id_: int) -> int:
    """BPF_MAP_GET_FD_BY_ID. Returns an fd for the map (caller closes)."""
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=I", attr, 0, map_id_)
    return bpf(BPF_MAP_GET_FD_BY_ID, attr)


def probe_inner_map_support() -> bool:
    """True if the kernel accepts an LRU_HASH inner in an ARRAY_OF_MAPS
    outer. LRU inner maps must match the outer's compiled template metadata."""
    inner_fd = -1
    outer_fd = -1
    try:
        inner_fd = map_create(BPF_MAP_TYPE_LRU_HASH, 4, 16, 1,
                              0, name=b"axdp_probe_i")
        outer_fd = map_create(BPF_MAP_TYPE_ARRAY_OF_MAPS, 4, 4, 1,
                              inner_map_fd=inner_fd, name=b"axdp_probe_o")
        return True
    except PermissionError:
        # EPERM means "can't create BPF maps at all" (non-root / no CAP_BPF),
        # not "kernel lacks map-in-map" — let callers report it as such.
        raise
    except OSError:
        return False
    finally:
        for fd in (inner_fd, outer_fd):
            if fd >= 0:
                os.close(fd)
