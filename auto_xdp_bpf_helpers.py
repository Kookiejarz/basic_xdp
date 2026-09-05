#!/usr/bin/env python3
"""Helpers for Auto XDP BPF map operations.

Deliberately self-contained: setup bootstrap (lib/setup/build.sh) may fetch
this single file to a temp path and run it before the auto_xdp package exists
on the host.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import os
import platform
import struct
import subprocess
import sys


NR_BPF = {
    "x86_64": 321,
    "aarch64": 280,
    "armv7l": 386,
    "armv6l": 386,
}.get(platform.machine(), 321)
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
            print("pin-maps failed: no map ids found in bpftool prog json", file=sys.stderr)
            return 1
        return 0
    except Exception as exc:
        print(f"pin-maps failed: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Auto XDP BPF helper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pin = sub.add_parser("pin-maps", help="Pin all maps referenced by a program id")
    pin.add_argument("--prog-id", type=int, required=True)
    pin.add_argument("--pin-dir", required=True)

    args = parser.parse_args()
    if args.cmd == "pin-maps":
        return cmd_pin_maps(args.prog_id, args.pin_dir)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
