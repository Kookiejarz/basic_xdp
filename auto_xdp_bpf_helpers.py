#!/usr/bin/env python3
"""Helpers for Auto XDP BPF map operations."""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import platform
import socket
import struct
import subprocess
import time

try:
    import psutil
except ImportError:
    psutil = None


NR_BPF = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def bpf(cmd: int, attr: ctypes.Array) -> int:
    ret = libc.syscall(NR_BPF, ctypes.c_int(cmd), attr, ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def obj_get(path: str) -> int:
    path_b = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = ctypes.create_string_buffer(128)
    struct.pack_into("=Q", attr, 0, ctypes.cast(path_b, ctypes.c_void_p).value or 0)
    return bpf(BPF_OBJ_GET, attr)


def cmd_pin_maps(prog_id: int, pin_dir: str) -> int:
    try:
        prog = json.loads(
            subprocess.check_output(["bpftool", "-j", "prog", "show", "id", str(prog_id)], text=True)
        )
        map_ids = prog.get("map_ids") or []
        if not map_ids and isinstance(prog.get("maps"), list):
            for m in prog["maps"]:
                if isinstance(m, dict) and "id" in m:
                    map_ids.append(m["id"])

        for map_id in map_ids:
            info = json.loads(
                subprocess.check_output(["bpftool", "-j", "map", "show", "id", str(map_id)], text=True)
            )
            name = info.get("name", f"map_{map_id}")
            pin_path = f"{pin_dir}/{name}"
            subprocess.check_call(["bpftool", "map", "pin", "id", str(map_id), pin_path])
        if not map_ids:
            print("pin-maps failed: no map ids found in bpftool prog json", file=os.sys.stderr)
            return 1
        return 0
    except Exception as exc:
        print(f"pin-maps failed: {exc}", file=os.sys.stderr)
        return 1


def iter_established_tcp():
    if psutil is None:
        return
    getter = getattr(psutil, "connections", psutil.net_connections)
    for conn in getter(kind="inet"):
        if getattr(conn, "family", None) not in (socket.AF_INET, socket.AF_INET6):
            continue
        if getattr(conn, "type", None) != socket.SOCK_STREAM:
            continue
        if conn.status != psutil.CONN_ESTABLISHED:
            continue
        if not conn.laddr or not conn.raddr:
            continue
        yield conn


def pack_ct_key(conn) -> bytes:
    if conn.family == socket.AF_INET:
        family = socket.AF_INET
        remote_ip = socket.inet_aton(conn.raddr.ip) + (b"\x00" * 12)
        local_ip = socket.inet_aton(conn.laddr.ip) + (b"\x00" * 12)
    else:
        family = socket.AF_INET6
        remote_ip = socket.inet_pton(socket.AF_INET6, conn.raddr.ip)
        local_ip = socket.inet_pton(socket.AF_INET6, conn.laddr.ip)
    return struct.pack("!B3xHH16s16s", family, conn.raddr.port, conn.laddr.port, remote_ip, local_ip)


def cmd_seed_tcp_conntrack(map_path: str) -> int:
    if psutil is None:
        print(0)
        return 0

    try:
        fd = obj_get(map_path)
    except OSError as exc:
        print(f"seed-tcp-conntrack failed to open map: {exc}", file=os.sys.stderr)
        return 1

    key = ctypes.create_string_buffer(40)
    value = ctypes.create_string_buffer(8)
    attr = ctypes.create_string_buffer(128)
    struct.pack_into(
        "=I4xQQQ",
        attr,
        0,
        fd,
        ctypes.cast(key, ctypes.c_void_p).value or 0,
        ctypes.cast(value, ctypes.c_void_p).value or 0,
        0,
    )

    seeded = 0
    stamp = time.monotonic_ns()
    for conn in iter_established_tcp():
        try:
            packed = pack_ct_key(conn)
            ctypes.memmove(key, packed, len(packed))
            struct.pack_into("=Q", value, 0, stamp)
            bpf(BPF_MAP_UPDATE_ELEM, attr)
            seeded += 1
        except OSError:
            continue

    os.close(fd)
    print(seeded)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Auto XDP BPF helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pin = sub.add_parser("pin-maps", help="Pin all maps referenced by a program id")
    pin.add_argument("--prog-id", type=int, required=True)
    pin.add_argument("--pin-dir", required=True)

    seed = sub.add_parser("seed-tcp-conntrack", help="Seed established TCP flows into conntrack map")
    seed.add_argument("--map-path", required=True)

    args = parser.parse_args()
    if args.cmd == "pin-maps":
        return cmd_pin_maps(args.prog_id, args.pin_dir)
    if args.cmd == "seed-tcp-conntrack":
        return cmd_seed_tcp_conntrack(args.map_path)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
