from __future__ import annotations

import argparse
import ctypes
import datetime as _dt
import errno
from importlib import resources
import json
import math
import os
import re
import secrets
import socket
import struct
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from auto_xdp import config as cfg
from auto_xdp import approvals
from auto_xdp import discovery, policy
from auto_xdp.admin.detect import detect_backend as _detect_backend
from auto_xdp.bpf.syscall import (
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_GET_NEXT_KEY,
    BPF_MAP_LOOKUP_BATCH,
    BPF_MAP_LOOKUP_ELEM,
    bpf,
    map_max_entries,
    obj_get,
)
from auto_xdp.discovery import _build_systemd_socket_map

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_LOG_LEVELS = {"debug", "info", "warning", "error"}
_IPPROTO_BY_NAME = {
    "gre": 47,
    "esp": 50,
    "sctp": 132,
}


def _slot_handler_name(path: Path) -> str:
    return path.name.removesuffix("_handler.c")


def _discover_builtin_slot_info() -> dict[str, tuple[int, str]]:
    info: dict[str, tuple[int, str]] = {}
    handlers_dir = Path(__file__).resolve().parents[1] / "handlers"
    if not handlers_dir.is_dir():
        return {
            name: (proto, f"{name}_handler.o")
            for name, proto in _IPPROTO_BY_NAME.items()
        }
    for source in sorted(handlers_dir.glob("*_handler.c")):
        text = source.read_text(encoding="utf-8", errors="ignore")
        if "SEC(\"xdp/" not in text:
            continue
        name = _slot_handler_name(source)
        proto = _IPPROTO_BY_NAME.get(name)
        if proto is None:
            continue
        info[name] = (proto, f"{name}_handler.o")
    return info


_BUILTIN_SLOT_INFO = _discover_builtin_slot_info()
_BUILTIN_SLOT_PROTO = {proto: name for name, (proto, _obj) in _BUILTIN_SLOT_INFO.items()}
_BUILTIN_SLOT_ARTIFACTS = {
    artifact
    for name, (_proto, obj_name) in _BUILTIN_SLOT_INFO.items()
    for artifact in (f"{name}_handler.c", obj_name)
}
_CUSTOM_SLOT_ARTIFACT_RE = re.compile(r"^custom_\d+_.+\.(?:c|o)$")
_CUSTOM_PORT_ARTIFACT_RE = re.compile(r"^custom_(?:tcp|udp)_\d+_.+\.(?:c|o)$")
_PORT_HANDLER_MARKERS = ("udp_hv4", "udp_hv6", "hblk4", "hblk6")


def _default_config_template() -> str:
    try:
        return resources.files("auto_xdp").joinpath("default_config.toml").read_text()
    except (FileNotFoundError, ModuleNotFoundError):
        return (Path(__file__).resolve().parents[1] / "config.toml").read_text()


def _load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if tomllib is not None:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    return _parse_toml_fallback(path.read_text())


def _parse_toml_fallback(text: str) -> dict[str, Any]:
    def split_items(raw: str) -> list[str]:
        items: list[str] = []
        cur: list[str] = []
        depth = 0
        in_str = False
        escape = False
        string_char: str | None = None
        for ch in raw[1:-1]:
            if escape:
                cur.append(ch)
                escape = False
                continue
            if ch == "\\" and in_str:
                cur.append(ch)
                escape = True
                continue
            if ch in ('"', "'") and not in_str:
                in_str = True
                string_char = ch
                cur.append(ch)
                continue
            if ch == string_char and in_str:
                in_str = False
                string_char = None
                cur.append(ch)
                continue
            if not in_str:
                if ch in ("[", "{"):
                    depth += 1
                elif ch in ("]", "}"):
                    depth -= 1
                elif ch == "," and depth == 0:
                    item = "".join(cur).strip()
                    if item:
                        items.append(item)
                    cur = []
                    continue
            cur.append(ch)
        item = "".join(cur).strip()
        if item:
            items.append(item)
        return items

    def parse_value(raw: str) -> Any:
        raw = raw.strip()
        if raw.startswith('"'):
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                if not raw.endswith('"') or len(raw) < 2:
                    raise ValueError(f"Malformed string value in config: {raw!r}")
                return raw[1:-1]
        if raw.startswith("'"):
            if not raw.endswith("'") or len(raw) < 2:
                raise ValueError(f"Malformed string value in config: {raw!r}")
            return raw[1:-1]
        if raw == "true":
            return True
        if raw == "false":
            return False
        if raw.startswith("["):
            return [parse_value(item) for item in split_items(raw)]
        if raw.startswith("{"):
            return {
                key.strip(): parse_value(value)
                for key, sep, value in (part.partition("=") for part in split_items(raw))
                if sep
            }
        try:
            return int(raw)
        except ValueError:
            pass
        try:
            return float(raw)
        except ValueError:
            return raw

    root: dict[str, Any] = {}
    current: dict[str, Any] = root
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        table_match = re.match(r"^\[([^\[\]]+)\]$", line)
        if table_match:
            current = root
            for key in table_match.group(1).split("."):
                current = current.setdefault(key.strip(), {})
            continue
        key_match = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*(.+)$", line)
        if key_match:
            current[key_match.group(1)] = parse_value(key_match.group(2).strip())
    return root


def _fmt_key(key: Any) -> str:
    key = str(key)
    return key if _BARE_KEY_RE.match(key) else json.dumps(key)


def _fmt_path(parts: list[Any]) -> str:
    return ".".join(_fmt_key(part) for part in parts)


def _is_array_of_tables(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(item, dict) for item in value)


def _fmt_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("TOML does not support NaN or infinity")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_fmt_value(item) for item in value) + "]"
    if isinstance(value, dict):
        inner = ", ".join(f"{_fmt_key(k)} = {_fmt_value(v)}" for k, v in value.items())
        return "{ " + inner + " }"
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def _emit_table_body(table: dict[str, Any], path_parts: list[Any]) -> list[str]:
    lines: list[str] = []
    scalar_items: list[tuple[str, Any]] = []
    array_table_items: list[tuple[str, list[dict[str, Any]]]] = []
    table_items: list[tuple[str, dict[str, Any]]] = []

    for key, value in table.items():
        if _is_array_of_tables(value):
            array_table_items.append((key, value))
        elif isinstance(value, dict):
            table_items.append((key, value))
        else:
            scalar_items.append((key, value))

    for key, value in scalar_items:
        lines.append(f"{_fmt_key(key)} = {_fmt_value(value)}")

    for key, value in array_table_items:
        if lines:
            lines.append("")
        child_path = path_parts + [key]
        for idx, item in enumerate(value):
            if idx > 0:
                lines.append("")
            lines.append(f"[[{_fmt_path(child_path)}]]")
            lines.extend(_emit_table_body(item, child_path))

    for key, value in table_items:
        if lines:
            lines.append("")
        child_path = path_parts + [key]
        lines.append(f"[{_fmt_path(child_path)}]")
        lines.extend(_emit_table_body(value, child_path))

    return lines


def _write_toml(path: Path, data: dict[str, Any]) -> None:
    lines = _emit_table_body(data, [])
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as tmp:
        tmp.write("\n".join(lines).rstrip() + "\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _load_config(path: str) -> tuple[Path, dict[str, Any]]:
    config_path = Path(path)
    return config_path, _load_toml(config_path)


def _write_stdout(text: str) -> None:
    sys.stdout.write(text)
    if not text.endswith("\n"):
        sys.stdout.write("\n")


def _normalize_cidr(value: str) -> str:
    try:
        return cfg.normalize_cidr(value)
    except ValueError as exc:
        raise ValueError(f"invalid IPv4/IPv6 address or CIDR: {value}") from exc


def _normalize_ports(values: list[int]) -> list[int]:
    ports = sorted({int(port) for port in values})
    for port in ports:
        if port <= 0 or port > 65535:
            raise ValueError(f"invalid port: {port}")
    return ports


def _slot_paths(args: argparse.Namespace) -> tuple[Path, Path, Path]:
    bpf_pin_dir = Path(args.bpf_pin_dir)
    install_dir = Path(args.install_dir)
    if args.handlers_dir:
        handlers_dir = Path(args.handlers_dir)
    else:
        handlers_dir = install_dir / "handlers"
    return bpf_pin_dir, install_dir, handlers_dir


def _builtin_handlers_dir(args: argparse.Namespace) -> Path:
    return Path(args.install_dir) / "handlers"


def _run_checked(cmd: list[str], fail_msg: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        if detail:
            print(detail, file=sys.stderr)
        raise RuntimeError(fail_msg)
    return result


def _bpf_key_u32(value: int) -> list[str]:
    return [str((value >> shift) & 0xFF) for shift in (0, 8, 16, 24)]


def _json_u32(value: object) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, list) and len(value) >= 4:
        raw = bytes(int(item, 0) if isinstance(item, str) else int(item) for item in value[:4])
        return int.from_bytes(raw, byteorder="little")
    if isinstance(value, dict):
        for key in ("id", "value"):
            if key in value:
                return _json_u32(value[key])
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"cannot decode BPF u32 value: {value!r}")


def _pinned_program_id(pin_path: Path) -> int:
    result = _run_checked(
        ["bpftool", "-j", "prog", "show", "pinned", str(pin_path)],
        f"Failed to inspect candidate program pin {pin_path}",
    )
    try:
        payload = json.loads(result.stdout)
        if isinstance(payload, list):
            payload = payload[0]
        if not isinstance(payload, dict):
            raise ValueError("program JSON is not an object")
        return int(payload["id"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read program ID from {pin_path}") from exc


def _prog_array_entry_id(map_path: Path, key: int) -> int | None:
    result = subprocess.run(
        [
            "bpftool",
            "-j",
            "map",
            "lookup",
            "pinned",
            str(map_path),
            "key",
            *_bpf_key_u32(key),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict):
            return None
        return _json_u32(payload["value"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def _prog_array_update(map_path: Path, key: int, prog_pin: Path) -> None:
    _run_checked(
        [
            "bpftool",
            "map",
            "update",
            "pinned",
            str(map_path),
            "key",
            *_bpf_key_u32(key),
            "value",
            "pinned",
            str(prog_pin),
        ],
        f"Failed to update program-array entry {key}",
    )


def _prog_array_delete(map_path: Path, key: int) -> bool:
    result = subprocess.run(
        [
            "bpftool",
            "map",
            "delete",
            "pinned",
            str(map_path),
            "key",
            *_bpf_key_u32(key),
        ],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _verify_prog_array_entry(map_path: Path, key: int, expected_id: int) -> None:
    actual_id = _prog_array_entry_id(map_path, key)
    if actual_id != expected_id:
        raise RuntimeError(
            f"Program-array verification failed for entry {key}: "
            f"expected program ID {expected_id}, got {actual_id!r}"
        )


def _rollback_prog_array_entry(
    map_path: Path,
    key: int,
    old_pin: Path | None,
    old_id: int | None,
) -> None:
    if old_pin is None or old_id is None:
        if not _prog_array_delete(map_path, key) and _prog_array_entry_id(map_path, key) is not None:
            raise RuntimeError(f"Failed to remove candidate program-array entry {key}")
        return
    _prog_array_update(map_path, key, old_pin)
    _verify_prog_array_entry(map_path, key, old_id)


def _transactional_file_prog_swap(
    map_path: Path,
    key: int,
    candidate_pin: Path,
    live_pin: Path,
) -> None:
    """Atomically switch a PROG_ARRAY entry, then commit its canonical pin.

    The old program remains pinned until the kernel lookup confirms the new
    program ID.  Any failure before the final cleanup restores the old entry
    and pin name.
    """
    try:
        candidate_id = _pinned_program_id(candidate_pin)
        old_exists = live_pin.exists()
        old_id = _pinned_program_id(live_pin) if old_exists else None
        active_id = _prog_array_entry_id(map_path, key)
        if old_id is None and active_id is not None:
            raise RuntimeError(
                f"Program-array entry {key} is active but its rollback pin {live_pin} is missing"
            )
        if old_id is not None and active_id not in {None, old_id}:
            raise RuntimeError(
                f"Program-array entry {key} does not match its rollback pin {live_pin}"
            )
    except (OSError, RuntimeError):
        if candidate_pin.exists():
            try:
                candidate_pin.unlink()
            except OSError:
                pass
        raise
    backup_pin = live_pin.with_name(f"{live_pin.name}_rollback_{secrets.token_hex(4)}")
    old_pin_for_rollback: Path | None = live_pin if old_exists else None
    switched = False
    moved_old = False
    moved_candidate = False
    try:
        _prog_array_update(map_path, key, candidate_pin)
        switched = True
        _verify_prog_array_entry(map_path, key, candidate_id)

        if old_exists:
            live_pin.rename(backup_pin)
            moved_old = True
            old_pin_for_rollback = backup_pin
        candidate_pin.rename(live_pin)
        moved_candidate = True
        _verify_prog_array_entry(map_path, key, candidate_id)
        if _pinned_program_id(live_pin) != candidate_id:
            raise RuntimeError(f"Committed pin {live_pin} does not reference the candidate program")

        if moved_old:
            backup_pin.unlink()
    except (OSError, RuntimeError) as exc:
        rollback_error: Exception | None = None
        if switched:
            try:
                _rollback_prog_array_entry(map_path, key, old_pin_for_rollback, old_id)
            except (OSError, RuntimeError) as rollback_exc:
                rollback_error = rollback_exc

        if moved_candidate and live_pin.exists():
            try:
                live_pin.rename(candidate_pin)
            except OSError:
                pass
        if moved_old and backup_pin.exists() and not live_pin.exists():
            try:
                backup_pin.rename(live_pin)
            except OSError:
                pass

        if rollback_error is not None:
            raise RuntimeError(
                f"Handler switch failed ({exc}); rollback also failed ({rollback_error}). "
                "Candidate and rollback pins were retained."
            ) from exc
        if candidate_pin.exists():
            try:
                candidate_pin.unlink()
            except OSError:
                pass
        raise RuntimeError(f"Handler switch failed; previous program restored: {exc}") from exc


def _slot_prog_name(pin_path: Path) -> str:
    result = subprocess.run(
        ["bpftool", "prog", "show", "pinned", str(pin_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return "custom"
    match = re.search(r"\bname\s+(\S+)", result.stdout)
    return match.group(1) if match else "custom"


def _ensure_config_exists(path: Path) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_default_config_template())


def _resolve_target_arch() -> tuple[str, str]:
    machine = os.uname().machine
    if machine == "x86_64":
        return "x86", "-D__x86_64__"
    if machine in {"aarch64", "arm64"}:
        return "arm64", "-D__aarch64__"
    if machine.startswith("armv7") or machine.startswith("armv6") or machine == "arm":
        return "arm", "-D__arm__"
    return machine, ""


def _resolve_asm_include(target_arch: str) -> str | None:
    candidates: list[str] = []
    result = subprocess.run(["gcc", "-print-multiarch"], capture_output=True, text=True)
    multiarch = result.stdout.strip() if result.returncode == 0 else ""
    if multiarch:
        candidates.append(f"/usr/include/{multiarch}")

    if target_arch == "x86":
        candidates.append("/usr/include/x86_64-linux-gnu")
    elif target_arch == "arm64":
        candidates.append("/usr/include/aarch64-linux-gnu")
    elif target_arch == "arm":
        candidates.append("/usr/include/arm-linux-gnueabihf")

    candidates.extend(
        [
            f"/usr/src/linux-headers-{os.uname().release}/arch/{target_arch}/include/generated",
            "/usr/include",
        ]
    )
    for candidate in candidates:
        if os.path.isdir(candidate) and (os.path.isdir(os.path.join(candidate, "asm")) or candidate == "/usr/include"):
            return candidate
    return "/usr/include"


def _compile_handler_source(
    source_path: Path,
    proto: int | str,
    handlers_dir: Path,
    port: int | None = None,
    *,
    sdk_dir: Path | None = None,
) -> Path:
    if not source_path.is_file():
        raise RuntimeError(f"Handler source not found: {source_path}")
    if source_path.suffix != ".c":
        raise RuntimeError(f"Unsupported handler source type: {source_path}")

    handlers_dir.mkdir(parents=True, exist_ok=True)
    stem = f"custom_{proto}_{port}_{source_path.stem}.o" if port is not None else f"custom_{proto}_{source_path.stem}.o"
    output_path = handlers_dir / stem
    target_arch, host_arch_flag = _resolve_target_arch()
    asm_inc = _resolve_asm_include(target_arch)
    if asm_inc is None:
        raise RuntimeError("ASM headers not found; cannot compile handler source.")

    cmd = [
        "clang",
        "-O3",
        "-g",
        "-target",
        "bpf",
        "-mcpu=v3",
        f"-D__TARGET_ARCH_{target_arch}",
    ]
    if host_arch_flag:
        cmd.append(host_arch_flag)
    cmd.extend(
        [
            "-fno-stack-protector",
            "-Wall",
            "-Wno-unused-value",
            "-I/usr/include",
            f"-I{asm_inc}",
            "-I/usr/include/bpf",
            f"-I{handlers_dir}",
            *([f"-I{sdk_dir}"] if sdk_dir is not None else []),
            f"-I{source_path.parent}",
            "-c",
            str(source_path),
            "-o",
            str(output_path),
        ]
    )
    _run_checked(cmd, f"Failed to compile {source_path}")
    return output_path


def _normalize_handler_port(value: int) -> int:
    if value <= 0 or value > 65535:
        raise ValueError(f"invalid port: {value}")
    return value


def _port_handler_map_path(bpf_pin_dir: Path, proto: str) -> Path:
    return bpf_pin_dir / ("tcp_port_handlers" if proto == "tcp" else "udp_port_handlers")


def _port_handler_dir(bpf_pin_dir: Path, proto: str, port: int) -> Path:
    return bpf_pin_dir / "port_handlers" / proto / str(port)


def _transactional_dir_prog_swap(
    map_path: Path,
    key: int,
    candidate_dir: Path,
    live_dir: Path,
) -> None:
    candidate_pin = candidate_dir / "prog"
    live_pin = live_dir / "prog"
    try:
        candidate_id = _pinned_program_id(candidate_pin)
        old_exists = live_pin.exists()
        old_id = _pinned_program_id(live_pin) if old_exists else None
        active_id = _prog_array_entry_id(map_path, key)
        if old_id is None and active_id is not None:
            raise RuntimeError(
                f"Program-array entry {key} is active but its rollback pin {live_pin} is missing"
            )
        if old_id is not None and active_id not in {None, old_id}:
            raise RuntimeError(
                f"Program-array entry {key} does not match its rollback pin {live_pin}"
            )
    except (OSError, RuntimeError):
        shutil.rmtree(candidate_dir, ignore_errors=True)
        raise

    backup_dir = live_dir.with_name(f"{live_dir.name}_rollback_{secrets.token_hex(4)}")
    old_pin_for_rollback: Path | None = live_pin if old_exists else None
    switched = False
    moved_old = False
    moved_candidate = False
    try:
        _prog_array_update(map_path, key, candidate_pin)
        switched = True
        _verify_prog_array_entry(map_path, key, candidate_id)

        if live_dir.exists():
            live_dir.rename(backup_dir)
            moved_old = True
            old_pin_for_rollback = backup_dir / "prog" if old_exists else None
        candidate_dir.rename(live_dir)
        moved_candidate = True
        _verify_prog_array_entry(map_path, key, candidate_id)
        if _pinned_program_id(live_dir / "prog") != candidate_id:
            raise RuntimeError(f"Committed pin {live_dir / 'prog'} does not reference the candidate program")
    except (OSError, RuntimeError) as exc:
        rollback_error: Exception | None = None
        if switched:
            try:
                _rollback_prog_array_entry(map_path, key, old_pin_for_rollback, old_id)
            except (OSError, RuntimeError) as rollback_exc:
                rollback_error = rollback_exc

        if moved_candidate and live_dir.exists():
            try:
                live_dir.rename(candidate_dir)
            except OSError:
                pass
        if moved_old and backup_dir.exists() and not live_dir.exists():
            try:
                backup_dir.rename(live_dir)
            except OSError:
                pass

        if rollback_error is not None:
            raise RuntimeError(
                f"Handler switch failed ({exc}); rollback also failed ({rollback_error}). "
                "Candidate and rollback generations were retained."
            ) from exc
        if candidate_dir.exists():
            shutil.rmtree(candidate_dir, ignore_errors=True)
        raise RuntimeError(f"Handler switch failed; previous program restored: {exc}") from exc

    if moved_old:
        try:
            shutil.rmtree(backup_dir)
        except OSError as exc:
            # Traffic already uses the verified candidate. Retaining the old
            # generation is safer than treating cleanup as a failed switch.
            print(f"Warning: old handler generation retained at {backup_dir}: {exc}", file=sys.stderr)


class _BpfUdpValidationMap:
    """Small iterator used only to purge handler-specific UDP validation state."""

    def __init__(self, path: Path, key_len: int) -> None:
        self.path = path
        self.fd = obj_get(str(path))
        self._key = bytearray(key_len)
        self._next_key = bytearray(key_len)
        self._value = bytearray(4)
        self._lookup_attr = bytearray(128)
        self._delete_attr = bytearray(128)
        self._next_attr = bytearray(128)
        self._key_buf = memoryview(self._key)
        self._next_key_buf = memoryview(self._next_key)
        key_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._key))
        next_key_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._next_key))
        value_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._value))
        struct.pack_into("=I4xQQ", self._lookup_attr, 0, self.fd, key_ptr, value_ptr)
        struct.pack_into("=I4xQ", self._delete_attr, 0, self.fd, key_ptr)
        struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, 0, next_key_ptr)

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> _BpfUdpValidationMap:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _iter_keys(self) -> list[bytes]:
        result: list[bytes] = []
        current_ptr = 0
        while True:
            next_key_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._next_key))
            struct.pack_into("=I4xQQ", self._next_attr, 0, self.fd, current_ptr, next_key_ptr)
            try:
                bpf(BPF_MAP_GET_NEXT_KEY, self._next_attr)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    break
                raise
            key_raw = bytes(self._next_key_buf)
            result.append(key_raw)
            self._key_buf[:] = key_raw
            current_ptr = ctypes.addressof(ctypes.c_char.from_buffer(self._key))
        return result

    def delete_key_port(self, dest_port: int, dport_offset: int = 2) -> int:
        deleted = 0
        for key_raw in self._iter_keys():
            if struct.unpack_from("!H", key_raw, dport_offset)[0] != dest_port:
                continue
            self._key_buf[:] = key_raw
            try:
                bpf(BPF_MAP_DELETE_ELEM, self._delete_attr)
                deleted += 1
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    raise
        return deleted


def _flush_udp_validated_for_port(bpf_pin_dir: Path, port: int) -> int:
    deleted = 0
    for name, key_len in (("udp_hv4", 12), ("udp_hv6", 36)):
        map_path = bpf_pin_dir / name
        if not map_path.exists():
            continue
        with _BpfUdpValidationMap(map_path, key_len) as validated:
            deleted += validated.delete_key_port(port)
    return deleted


def _cleanup_existing_port_handler(bpf_pin_dir: Path, proto: str, port: int) -> None:
    map_path = _port_handler_map_path(bpf_pin_dir, proto)
    subprocess.run(
        [
            "bpftool",
            "map",
            "delete",
            "pinned",
            str(map_path),
            "key",
            str(port),
            "0",
            "0",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    if proto == "udp":
        _flush_udp_validated_for_port(bpf_pin_dir, port)
    pin_dir = _port_handler_dir(bpf_pin_dir, proto, port)
    shutil.rmtree(pin_dir, ignore_errors=True)


def _port_handler_config_update(config_path: Path, proto: str, port: int, path: str | None) -> None:
    cfg_path, data = _load_config(str(config_path))
    port_handlers = data.setdefault("port_handlers", {})
    table = port_handlers.setdefault(proto, {})
    if path is None:
        table.pop(str(port), None)
    else:
        table[str(port)] = path
    _write_toml(cfg_path, data)


def _iter_configured_port_handlers(config_path: Path) -> list[tuple[str, int, str]]:
    _, data = _load_config(str(config_path))
    port_handlers = data.get("port_handlers", {})
    results: list[tuple[str, int, str]] = []
    for proto in ("tcp", "udp"):
        table = port_handlers.get(proto, {})
        if not isinstance(table, dict):
            continue
        for raw_port, raw_path in table.items():
            port = _normalize_handler_port(int(raw_port))
            path = str(raw_path)
            if path:
                results.append((proto, port, path))
    return sorted(results, key=lambda item: (item[0], item[1]))


def _cmd_config_show(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if not path.exists():
        print(f"(no config file at {path} — run: axdp config init)")
        return 0
    _write_stdout(path.read_text())
    return 0


def _cmd_config_init(args: argparse.Namespace) -> int:
    path = Path(args.config)
    if path.exists():
        print(f"Config already exists: {path}  (use 'axdp config show' to view)")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_default_config_template())
    print(f"Created: {path}")
    return 0


def _cmd_log_level(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    if not args.level:
        print(str(data.get("daemon", {}).get("log_level", "warning")).lower())
        return 0

    level = args.level.lower()
    if level not in _LOG_LEVELS:
        print(f"Invalid log level: {level}", file=sys.stderr)
        print("Valid values: debug, info, warning, error", file=sys.stderr)
        return 1

    daemon = data.setdefault("daemon", {})
    daemon["log_level"] = level
    _write_toml(path, data)
    print(f"daemon.log_level={level}")
    return 0


def _cmd_under_attack(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    under_attack = data.setdefault("under_attack", {})

    if not args.mode:
        enabled = bool(under_attack.get("enabled", False))
        print("on" if enabled else "off")
        return 0

    mode = args.mode.lower()
    if mode not in {"on", "off"}:
        print(f"Invalid under_attack mode: {mode}", file=sys.stderr)
        print("Valid values: on, off", file=sys.stderr)
        return 1

    enabled = mode == "on"
    under_attack["enabled"] = enabled
    _write_toml(path, data)
    print(f"under_attack.enabled={'true' if enabled else 'false'}")
    return 0


def _cmd_trust_list(args: argparse.Namespace) -> int:
    _, data = _load_config(args.config)
    trusted = data.get("trusted_ips", {})
    if not trusted:
        print("  (none)")
        return 0
    rows = sorted((_normalize_cidr(cidr), str(label)) for cidr, label in trusted.items())
    for cidr, label in rows:
        print(f"  {cidr:<20}  {label}")
    return 0


def _cmd_trust_add(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    cidr = _normalize_cidr(args.cidr)
    data.setdefault("trusted_ips", {})[cidr] = args.label
    _write_toml(path, data)
    print(f"Added trusted: {cidr} ({args.label})")
    return 0


def _cmd_trust_del(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    cidr = _normalize_cidr(args.cidr)
    data.setdefault("trusted_ips", {}).pop(cidr, None)
    _write_toml(path, data)
    print(f"Removed trusted: {cidr}")
    return 0


def _cmd_acl_list(args: argparse.Namespace) -> int:
    _, data = _load_config(args.config)
    rules = data.get("acl", [])
    if not rules:
        print("  (none)")
        return 0
    normalized: list[tuple[str, str, list[int]]] = []
    for rule in rules:
        proto = str(rule["proto"]).lower()
        cidr = _normalize_cidr(str(rule["cidr"]))
        ports = _normalize_ports([int(port) for port in rule.get("ports", [])])
        normalized.append((proto, cidr, ports))
    for proto, cidr, ports in sorted(normalized, key=lambda item: (item[0], item[1])):
        joined = " ".join(str(port) for port in ports)
        print(f"  {proto.upper():<4}  {cidr:<22}  ports: {joined}")
    return 0


def _cmd_acl_add(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    cidr = _normalize_cidr(args.cidr)
    ports = _normalize_ports(args.ports)
    rules = data.setdefault("acl", [])
    rules = [
        rule
        for rule in rules
        if not (
            str(rule.get("proto", "")).lower() == args.proto
            and _normalize_cidr(str(rule.get("cidr"))) == cidr
        )
    ]
    rules.append({"proto": args.proto, "cidr": cidr, "ports": ports})
    data["acl"] = rules
    _write_toml(path, data)
    print(f"Added ACL: {args.proto} {cidr} ports {' '.join(str(port) for port in ports)}")
    return 0


def _cmd_acl_del(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    cidr = _normalize_cidr(args.cidr)
    data["acl"] = [
        rule
        for rule in data.get("acl", [])
        if not (
            str(rule.get("proto", "")).lower() == args.proto
            and _normalize_cidr(str(rule.get("cidr"))) == cidr
        )
    ]
    _write_toml(path, data)
    print(f"Removed ACL: {args.proto} {cidr}")
    return 0


def _cmd_slot_enable_builtin(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    slots = data.setdefault("slots", {})
    enabled = slots.setdefault("enabled", [])
    if args.name not in enabled:
        enabled.append(args.name)
    _write_toml(path, data)
    return 0


def _cmd_slot_enable_custom(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    slots = data.setdefault("slots", {})
    enabled = slots.setdefault("enabled", [])
    enabled = [entry for entry in enabled if not (isinstance(entry, dict) and entry.get("proto") == args.proto)]
    enabled.append({"proto": args.proto, "path": args.path})
    slots["enabled"] = enabled
    _write_toml(path, data)
    return 0


def _cmd_slot_disable(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    builtin_name = _BUILTIN_SLOT_PROTO.get(args.proto)
    slots = data.setdefault("slots", {})
    enabled = slots.get("enabled", [])
    slots["enabled"] = [
        entry
        for entry in enabled
        if not (isinstance(entry, str) and entry == builtin_name)
        and not (isinstance(entry, dict) and int(entry.get("proto", -1)) == args.proto)
    ]
    _write_toml(path, data)
    return 0


def _looks_like_port_handler_source(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return any(marker in text for marker in _PORT_HANDLER_MARKERS)


def _iter_available_port_handler_files(handlers_dir: Path) -> list[Path]:
    if not handlers_dir.is_dir():
        return []

    candidates: dict[str, Path] = {}
    for path in handlers_dir.iterdir():
        if not path.is_file() or path.suffix not in {".c", ".o"}:
            continue
        if path.name in _BUILTIN_SLOT_ARTIFACTS or _CUSTOM_SLOT_ARTIFACT_RE.match(path.name):
            continue

        include = False
        if _CUSTOM_PORT_ARTIFACT_RE.match(path.name):
            include = True
        elif path.suffix == ".c":
            include = _looks_like_port_handler_source(path)
        else:
            source_peer = path.with_suffix(".c")
            include = source_peer.is_file() and _looks_like_port_handler_source(source_peer)

        if not include:
            continue

        key = path.stem
        current = candidates.get(key)
        if current is None or (current.suffix != ".o" and path.suffix == ".o"):
            candidates[key] = path

    return [candidates[key] for key in sorted(candidates)]


def _cmd_slot_list(args: argparse.Namespace) -> int:
    bpf_pin_dir, _, _ = _slot_paths(args)
    handlers_dir = _builtin_handlers_dir(args)
    slot_pin_dir = bpf_pin_dir / "handlers"
    proto_handlers = bpf_pin_dir / "proto_handlers"

    if not proto_handlers.exists():
        print("Loaded handlers:\n  XDP not running (proto_handlers map not found).\n")
    else:
        print("Loaded handlers:")
        found = False
        for pin in sorted(slot_pin_dir.glob("proto_*")):
            if not pin.is_file():
                continue
            proto = pin.name.removeprefix("proto_")
            name = _slot_prog_name(pin)
            print(f"  proto {proto:<5} {name}")
            found = True
        if not found:
            print("  (none)")
        print("")
    print("Available handlers:")
    for name in _BUILTIN_SLOT_INFO:
        proto_num, obj_name = _BUILTIN_SLOT_INFO[name]
        obj_path = handlers_dir / obj_name
        pin_path = slot_pin_dir / f"proto_{proto_num}"
        if obj_path.exists():
            if pin_path.exists():
                print(f"  {name:<6} (proto {proto_num})  [loaded]")
            else:
                print(f"  {name:<6} (proto {proto_num})")
        else:
            print(f"  {name:<6} (proto {proto_num})  [.o not found: {obj_path}]")
    return 0


def _cmd_slot_load(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, handlers_dir = _slot_paths(args)
    builtin_handlers_dir = _builtin_handlers_dir(args)
    slot_ctx_map = bpf_pin_dir / "slot_ctx_map"
    proto_handlers = bpf_pin_dir / "proto_handlers"
    slot_pin_dir = bpf_pin_dir / "handlers"

    builtin_name = ""
    if args.name_or_proto in _BUILTIN_SLOT_INFO:
        builtin_name = args.name_or_proto
        proto, obj_name = _BUILTIN_SLOT_INFO[builtin_name]
        obj_path = builtin_handlers_dir / obj_name
    elif args.name_or_proto.isdigit():
        proto = int(args.name_or_proto)
        if not args.path:
            print("Custom handler requires a .o or .c path: axdp slot load PROTO /path/to/handler.o", file=sys.stderr)
            return 1
        custom_path = Path(args.path)
        if custom_path.suffix == ".c":
            try:
                obj_path = _compile_handler_source(
                    custom_path, proto, handlers_dir, sdk_dir=builtin_handlers_dir
                )
            except RuntimeError as exc:
                print(str(exc), file=sys.stderr)
                return 1
        else:
            obj_path = custom_path
    else:
        print(f"Unknown handler: {args.name_or_proto} (built-in: gre, esp, sctp)", file=sys.stderr)
        return 1

    if not obj_path.is_file():
        print(f"Handler object not found: {obj_path}", file=sys.stderr)
        return 1
    if not slot_ctx_map.exists():
        print("XDP not loaded (slot_ctx_map not found). Run setup first.", file=sys.stderr)
        return 1
    if not proto_handlers.exists():
        print("XDP not loaded (proto_handlers map not found).", file=sys.stderr)
        return 1

    slot_pin_dir.mkdir(parents=True, exist_ok=True)
    pin_path = slot_pin_dir / f"proto_{proto}"
    candidate_pin = slot_pin_dir / f"proto_{proto}_next_{secrets.token_hex(4)}"

    load_cmd = [
        "bpftool",
        "prog",
        "load",
        str(obj_path),
        str(candidate_pin),
        "type",
        "xdp",
        "map",
        "name",
        "slot_ctx_map",
        "pinned",
        str(slot_ctx_map),
    ]

    if proto == 132 and builtin_name == "sctp":
        sctp_whitelist = bpf_pin_dir / "sctp_whitelist"
        if not sctp_whitelist.exists():
            print("XDP not loaded completely (sctp_whitelist map not found).", file=sys.stderr)
            return 1
        load_cmd.extend(
            [
                "map",
                "name",
                "sctp_whitelist",
                "pinned",
                str(sctp_whitelist),
            ]
        )

    try:
        _run_checked(load_cmd, f"Failed to load {obj_path}")
    except RuntimeError as exc:
        if candidate_pin.exists():
            candidate_pin.unlink()
        print(str(exc), file=sys.stderr)
        return 1

    try:
        _transactional_file_prog_swap(proto_handlers, proto, candidate_pin, pin_path)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Loaded handler for proto {proto} from {obj_path}")
    _ensure_config_exists(path)
    if builtin_name:
        _cmd_slot_enable_builtin(argparse.Namespace(config=str(path), name=builtin_name))
    else:
        _cmd_slot_enable_custom(argparse.Namespace(config=str(path), proto=proto, path=str(obj_path)))
    print(f"  config: {path}")
    return 0


def _cmd_slot_unload(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, _ = _slot_paths(args)
    slot_pin_dir = bpf_pin_dir / "handlers"
    proto_handlers = bpf_pin_dir / "proto_handlers"
    target = args.name_or_proto

    if target.isdigit():
        proto = int(target)
    else:
        proto = None
        for pin in sorted(slot_pin_dir.glob("proto_*")):
            if not pin.is_file():
                continue
            name = _slot_prog_name(pin)
            if name == target or f"_{target}_" in name or name.endswith(f"_{target}"):
                proto = int(pin.name.removeprefix("proto_"))
                break
        if proto is None:
            print(f"No loaded handler matches: {target}", file=sys.stderr)
            return 1

    subprocess.run(
        [
            "bpftool",
            "map",
            "delete",
            "pinned",
            str(proto_handlers),
            "key",
            str(proto),
            "0",
            "0",
            "0",
        ],
        capture_output=True,
        text=True,
    )
    pin_path = slot_pin_dir / f"proto_{proto}"
    if pin_path.exists():
        pin_path.unlink()

    print(f"Unloaded handler for proto {proto}")
    if path.exists():
        _cmd_slot_disable(argparse.Namespace(config=str(path), proto=proto))
        print(f"  config: {path}")
    return 0


def _cmd_port_handler_list(args: argparse.Namespace) -> int:
    bpf_pin_dir, _, handlers_dir = _slot_paths(args)
    base_dir = bpf_pin_dir / "port_handlers"
    configured = _iter_configured_port_handlers(Path(args.config))
    available_by_path = {
        str(path): path
        for directory in (_builtin_handlers_dir(args), handlers_dir)
        for path in _iter_available_port_handler_files(directory)
    }
    available = [available_by_path[key] for key in sorted(available_by_path)]

    print("Loaded per-port handlers:")
    found = False
    for proto in ("tcp", "udp"):
        proto_dir = base_dir / proto
        if not proto_dir.is_dir():
            continue
        port_dirs = [item for item in proto_dir.iterdir() if item.is_dir() and item.name.isdigit()]
        for port_dir in sorted(port_dirs, key=lambda item: int(item.name)):
            if not port_dir.is_dir():
                continue
            prog_pin = port_dir / "prog"
            if not prog_pin.exists():
                continue
            name = _slot_prog_name(prog_pin)
            print(f"  {proto.upper():<3}  {port_dir.name:<5}  {name}")
            found = True
    if not found:
        print("  (none)")

    print("")
    print("Configured per-port handlers:")
    if not configured:
        print("  (none)")
    else:
        for proto, port, path in configured:
            print(f"  {proto.upper():<3}  {port:<5}  {path}")

    print("")
    print("Available local port handler files:")
    if not available:
        print("  (none)")
        return 0
    for handler_path in available:
        print(f"  {handler_path.stem:<20} {handler_path}")
    return 0


def _cmd_port_handler_load(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, handlers_dir = _slot_paths(args)
    proto = str(args.proto).lower()
    port = _normalize_handler_port(int(args.port))
    slot_ctx_map = bpf_pin_dir / "slot_ctx_map"
    handler_map = _port_handler_map_path(bpf_pin_dir, proto)

    source_path = Path(args.path)
    if source_path.suffix == ".c":
        try:
            obj_path = _compile_handler_source(
                source_path,
                proto,
                handlers_dir,
                port=port,
                sdk_dir=_builtin_handlers_dir(args),
            )
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    else:
        obj_path = source_path

    if not obj_path.is_file():
        print(f"Handler object not found: {obj_path}", file=sys.stderr)
        return 1
    obj_path = obj_path.resolve()
    if not slot_ctx_map.exists():
        print("XDP not loaded (slot_ctx_map not found). Run setup first.", file=sys.stderr)
        return 1
    if not handler_map.exists():
        print(f"XDP not loaded ({handler_map.name} map not found).", file=sys.stderr)
        return 1

    shared_maps = [
        ("slot_ctx_map", slot_ctx_map),
        ("hblk4", bpf_pin_dir / "hblk4"),
        ("hblk6", bpf_pin_dir / "hblk6"),
    ]
    if proto == "udp":
        shared_maps.extend(
            [
                ("udp_hv4", bpf_pin_dir / "udp_hv4"),
                ("udp_hv6", bpf_pin_dir / "udp_hv6"),
            ]
        )

    missing = [name for name, map_path in shared_maps if not map_path.exists()]
    if missing:
        print(f"XDP not loaded completely (missing pinned maps: {', '.join(missing)}).", file=sys.stderr)
        return 1

    pin_dir = _port_handler_dir(bpf_pin_dir, proto, port)
    pin_dir.parent.mkdir(parents=True, exist_ok=True)
    candidate_dir = Path(tempfile.mkdtemp(prefix=f"{port}_next_", dir=str(pin_dir.parent)))
    prog_pin = candidate_dir / "prog"

    load_cmd = [
        "bpftool",
        "prog",
        "load",
        str(obj_path),
        str(prog_pin),
        "type",
        "xdp",
        "pinmaps",
        str(candidate_dir),
    ]
    for name, map_path in shared_maps:
        load_cmd.extend(["map", "name", name, "pinned", str(map_path)])

    try:
        _run_checked(load_cmd, f"Failed to load {obj_path}")
    except RuntimeError as exc:
        shutil.rmtree(candidate_dir, ignore_errors=True)
        print(str(exc), file=sys.stderr)
        return 1

    try:
        _transactional_dir_prog_swap(handler_map, port, candidate_dir, pin_dir)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    # Handler-specific validation caches must not survive a successful handler
    # replacement. Flush only after the new program is committed so a failed
    # candidate never mutates the active handler's state.
    if proto == "udp":
        _flush_udp_validated_for_port(bpf_pin_dir, port)

    if not args.no_config_update:
        _ensure_config_exists(path)
        _port_handler_config_update(path, proto, port, str(obj_path))
    print(f"Loaded {proto.upper()} handler for port {port} from {obj_path}")
    if not args.no_config_update:
        print(f"  config: {path}")
    return 0


def _autodetect_iface() -> str:
    """Return the default-route interface name, or raise RuntimeError."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], stderr=subprocess.DEVNULL, text=True
        )
    except (subprocess.CalledProcessError, OSError):
        out = ""
    for line in out.splitlines():
        parts = line.split()
        # format: default via ... dev IFACE ...
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                return parts[idx + 1]
    raise RuntimeError("Could not detect interface. Use --iface IFACE.")


def _read_xdp_ports(bpf_pin_dir: str) -> tuple[list[int], list[int]]:
    """Returns (tcp_ports, udp_ports) from BPF whitelist maps via direct BPF syscalls."""
    tcp_path = str(Path(bpf_pin_dir) / "tcp_whitelist")
    udp_path = str(Path(bpf_pin_dir) / "udp_whitelist")

    for p in (tcp_path, udp_path):
        if not Path(p).exists():
            raise RuntimeError(f"XDP whitelist maps not found under {bpf_pin_dir}")

    def _read_array_ports(path: str) -> list[int]:
        try:
            fd = obj_get(path)
        except OSError as exc:
            raise RuntimeError(f"Cannot open BPF map {path}: {exc}") from exc
        try:
            n = map_max_entries(fd)
            keys_buf = ctypes.create_string_buffer(4 * n)
            vals_buf = ctypes.create_string_buffer(4 * n)
            out_batch = ctypes.create_string_buffer(4)
            attr = ctypes.create_string_buffer(56)
            struct.pack_into(
                "=QQQQIIQQ", attr, 0,
                0,
                ctypes.cast(out_batch, ctypes.c_void_p).value or 0,
                ctypes.cast(keys_buf, ctypes.c_void_p).value or 0,
                ctypes.cast(vals_buf, ctypes.c_void_p).value or 0,
                n, fd, 0, 0,
            )
            try:
                bpf(BPF_MAP_LOOKUP_BATCH, attr)
            except OSError as exc:
                if exc.errno != errno.ENOENT:
                    # Sequential fallback for kernels without batch support
                    k = ctypes.create_string_buffer(4)
                    v = ctypes.create_string_buffer(4)
                    la = ctypes.create_string_buffer(128)
                    struct.pack_into(
                        "=I4xQQ", la, 0, fd,
                        ctypes.cast(k, ctypes.c_void_p).value or 0,
                        ctypes.cast(v, ctypes.c_void_p).value or 0,
                    )
                    ports: list[int] = []
                    for port in range(1, min(n, 65536)):
                        try:
                            struct.pack_into("=I", k, 0, port)
                            bpf(BPF_MAP_LOOKUP_ELEM, la)
                            if struct.unpack_from("=I", v, 0)[0]:
                                ports.append(port)
                        except OSError:
                            continue
                    return ports
                # ENOENT means end-of-map; count in attr is updated.
            fetched = struct.unpack_from("=I", attr, 32)[0]
            return sorted({
                struct.unpack_from("=I", keys_buf, i * 4)[0]
                for i in range(fetched)
                if struct.unpack_from("=I", vals_buf, i * 4)[0]
                and 0 < struct.unpack_from("=I", keys_buf, i * 4)[0] <= 65535
            })
        finally:
            os.close(fd)

    return _read_array_ports(tcp_path), _read_array_ports(udp_path)


def _read_nft_ports(nft_family: str, nft_table: str) -> tuple[list[int], list[int]]:
    """Returns (tcp_ports, udp_ports) from nft sets."""
    if not shutil.which("nft"):
        raise RuntimeError("nft command not found")

    def _read_set(set_name: str) -> list[int]:
        try:
            out = subprocess.check_output(
                ["nft", "-j", "list", "set", nft_family, nft_table, set_name],
                stderr=subprocess.DEVNULL,
            )
            data = json.loads(out)
        except (subprocess.CalledProcessError, json.JSONDecodeError, OSError):
            return []
        ports: set[int] = set()
        for item in data.get("nftables", []):
            e = item.get("element")
            if not e:
                continue
            for v in e.get("elem", []):
                if isinstance(v, int) and 0 < v <= 65535:
                    ports.add(v)
        return sorted(ports)

    return _read_set("tcp_ports"), _read_set("udp_ports")


def _display_proc_name(
    proc_name: str,
    port: int,
    systemd_socket_map: dict[int, str] | None,
) -> tuple[str, dict[int, str] | None]:
    if proc_name != "systemd":
        return proc_name, systemd_socket_map
    if systemd_socket_map is None:
        systemd_socket_map = _build_systemd_socket_map()
    return systemd_socket_map.get(port, proc_name), systemd_socket_map


def _lookup_port_procs(proto: str, ports: list[int]) -> dict[int, set[str]]:
    """Returns {port: set_of_process_names} by scanning /proc/net/{tcp,udp}."""
    proc_by_port: dict[int, set[str]] = {p: set() for p in ports}
    systemd_socket_map: dict[int, str] | None = None

    def _parse_proc_net(path: str, state_filter: str, check_no_remote: bool = False) -> dict[int, int]:
        result: dict[int, int] = {}
        try:
            with open(path) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    if len(parts) < 10:
                        continue
                    local, remote, st, inode_str = parts[1], parts[2], parts[3], parts[9]
                    if st != state_filter:
                        continue
                    if check_no_remote and not remote.endswith(":0000"):
                        continue
                    port = int(local.split(":")[1], 16)
                    if port > 0:
                        result[port] = int(inode_str)
        except OSError:
            pass
        return result

    if proto == "tcp":
        port_to_inode: dict[int, int] = {}
        port_to_inode.update(_parse_proc_net("/proc/net/tcp", "0A"))
        port_to_inode.update(_parse_proc_net("/proc/net/tcp6", "0A"))
    else:
        port_to_inode = {}
        port_to_inode.update(_parse_proc_net("/proc/net/udp", "07", check_no_remote=True))
        port_to_inode.update(_parse_proc_net("/proc/net/udp6", "07", check_no_remote=True))

    wanted_inodes = {inode for port, inode in port_to_inode.items() if port in proc_by_port}
    inode_map: dict[int, str] = {}
    if wanted_inodes:
        try:
            for entry in os.scandir("/proc"):
                if not entry.name.isdigit():
                    continue
                pid = entry.name
                try:
                    for fd_entry in os.scandir(f"/proc/{pid}/fd"):
                        try:
                            link = os.readlink(fd_entry.path)
                            if link.startswith("socket:["):
                                inode = int(link[8:-1])
                                if inode in wanted_inodes:
                                    with open(f"/proc/{pid}/comm") as cf:
                                        proc_name = cf.read().strip()
                                    prev = inode_map.get(inode)
                                    if prev is None or prev == "systemd":
                                        inode_map[inode] = proc_name
                                    if proc_name != "systemd":
                                        wanted_inodes.discard(inode)
                        except OSError:
                            pass
                except OSError:
                    pass
                if not wanted_inodes:
                    break
        except OSError:
            pass

    for port, inode in port_to_inode.items():
        if port in proc_by_port and inode in inode_map:
            proc_name, systemd_socket_map = _display_proc_name(inode_map[inode], port, systemd_socket_map)
            proc_by_port[port].add(proc_name)

    return proc_by_port


def _read_rate_map(map_path: str) -> dict[int, int]:
    """Returns {port: rate_per_sec} from a BPF rate map."""
    rates: dict[int, int] = {}
    if not map_path or not Path(map_path).exists():
        return rates

    def _b(v: Any) -> int:
        if isinstance(v, int):
            return v & 0xFF
        if isinstance(v, str):
            try:
                return int(v, 0) & 0xFF
            except ValueError:
                return 0
        return 0

    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", map_path],
            stderr=subprocess.DEVNULL,
        )
        for row in json.loads(out):
            key = row.get("key", [])
            val = row.get("value", [])
            if isinstance(key, list) and len(key) >= 4:
                port = _b(key[0]) | (_b(key[1]) << 8) | (_b(key[2]) << 16) | (_b(key[3]) << 24)
                if isinstance(val, list) and len(val) >= 4:
                    rate = _b(val[0]) | (_b(val[1]) << 8) | (_b(val[2]) << 16) | (_b(val[3]) << 24)
                    if rate > 0:
                        rates[port] = rate
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError, ValueError):
        pass
    return rates


def _print_port_lines(
    proto: str,
    ports: list[int],
    proc_map: dict[int, set[str]],
    port_rates: dict[int, int],
) -> None:
    """Prints the port table rows."""
    import socket as _socket

    if not ports:
        print("  (none)")
        return
    for p in sorted(set(ports)):
        try:
            svc = _socket.getservbyport(p, proto)
        except OSError:
            svc = "-"
        procs = ",".join(sorted(proc_map.get(p, set()))) or "-"
        rate = port_rates.get(p)
        rate_str = f"{rate}/s" if rate else "-"
        print(f"  {p:5d}  {svc:<14}  {procs:<14}  {rate_str}")


def _collect_ports(
    backend: str,
    bpf_pin_dir: str,
    nft_family: str,
    nft_table: str,
) -> tuple[list[int], list[int]]:
    if backend == "xdp":
        return _read_xdp_ports(bpf_pin_dir)
    if backend == "nftables":
        return _read_nft_ports(nft_family, nft_table)
    raise RuntimeError("No active backend detected.")


def _diff_port_lists(old: list[int], new: list[int]) -> tuple[list[int], list[int]]:
    old_set = set(old)
    new_set = set(new)
    added = sorted(new_set - old_set)
    removed = sorted(old_set - new_set)
    return added, removed


def _cmd_ports(args: argparse.Namespace) -> int:
    """Handler for the ports subcommand."""
    bpf_pin_dir: str = args.bpf_pin_dir
    run_state_dir: str = args.run_state_dir
    nft_family: str = args.nft_family
    nft_table: str = args.nft_table
    ifaces: list[str] = (args.iface or "").split() or []

    # Auto-detect interface if not provided
    if not ifaces:
        try:
            ifaces = [_autodetect_iface()]
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    iface = ifaces[0]

    # Detect backend
    try:
        backend = _detect_backend(Path(bpf_pin_dir), Path(run_state_dir), ifaces, nft_family, nft_table)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    # Initial port read
    try:
        tcp_ports, udp_ports = _collect_ports(backend, bpf_pin_dir, nft_family, nft_table)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    syn_rate_map = str(Path(bpf_pin_dir) / "tcp_port_policies")
    udp_rate_map = str(Path(bpf_pin_dir) / "udp_port_policies")

    def _render_current(tcp: list[int], udp: list[int]) -> None:
        tcp_procs = _lookup_port_procs("tcp", tcp)
        udp_procs = _lookup_port_procs("udp", udp)
        tcp_rates = _read_rate_map(syn_rate_map)
        udp_rates = _read_rate_map(udp_rate_map)
        print(f"Backend   : {backend}")
        print(f"Interface : {iface}")
        print("TCP allow :")
        _print_port_lines("tcp", tcp, tcp_procs, tcp_rates)
        print("UDP allow :")
        _print_port_lines("udp", udp, udp_procs, udp_rates)

    _render_current(tcp_ports, udp_ports)

    if not args.watch:
        return 0

    import time as _time
    import datetime as _datetime

    prev_tcp = tcp_ports
    prev_udp = udp_ports

    try:
        while True:
            _time.sleep(args.interval)
            try:
                new_backend = _detect_backend(Path(bpf_pin_dir), Path(run_state_dir), ifaces, nft_family, nft_table)
                new_tcp, new_udp = _collect_ports(new_backend, bpf_pin_dir, nft_family, nft_table)
            except RuntimeError:
                continue

            if new_tcp == prev_tcp and new_udp == prev_udp:
                continue

            now_ts = _datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            added_tcp, removed_tcp = _diff_port_lists(prev_tcp, new_tcp)
            added_udp, removed_udp = _diff_port_lists(prev_udp, new_udp)

            print("")
            print(f"[{now_ts}] Port whitelist updated")
            if added_tcp:
                print(f"  TCP + {' '.join(str(p) for p in added_tcp)}")
            if removed_tcp:
                print(f"  TCP - {' '.join(str(p) for p in removed_tcp)}")
            if added_udp:
                print(f"  UDP + {' '.join(str(p) for p in added_udp)}")
            if removed_udp:
                print(f"  UDP - {' '.join(str(p) for p in removed_udp)}")
            print("")

            tcp_procs = _lookup_port_procs("tcp", new_tcp)
            udp_procs = _lookup_port_procs("udp", new_udp)
            tcp_rates = _read_rate_map(syn_rate_map)
            udp_rates = _read_rate_map(udp_rate_map)
            print("TCP allow :")
            _print_port_lines("tcp", new_tcp, tcp_procs, tcp_rates)
            print("UDP allow :")
            _print_port_lines("udp", new_udp, udp_procs, udp_rates)

            prev_tcp = new_tcp
            prev_udp = new_udp
    except KeyboardInterrupt:
        return 0

    return 0


def _policy_snapshot(args: argparse.Namespace):
    cfg.apply_toml_config(_load_toml(Path(args.config)))
    observed = discovery.get_listening_ports()
    return observed, policy.resolve_desired_state(observed)


def _active_backend_name(args: argparse.Namespace) -> str:
    ifaces = (args.iface or "").split()
    if not ifaces:
        try:
            ifaces = [_autodetect_iface()]
        except RuntimeError:
            ifaces = []
    try:
        return _detect_backend(
            Path(args.bpf_pin_dir), Path(args.run_state_dir), ifaces,
            args.nft_family, args.nft_table,
        )
    except RuntimeError:
        return "unavailable"


def _owner_text(endpoint: Any) -> str:
    if endpoint.container_runtime:
        return f"{endpoint.container_runtime}:{endpoint.container_name or endpoint.container_id[:12]}"
    owner = endpoint.subject or "unknown"
    if endpoint.attribution_source.startswith("systemd") and not owner.endswith(".service"):
        owner += ".service"
    return owner


def _service_label(protocol: str, port: int) -> str:
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return f"{protocol}{port}"


def _grant_label(decision: Any) -> str:
    return f"{decision.subject}.{decision.endpoint.ingress_zone}_{_service_label(decision.endpoint.protocol, decision.endpoint.host_port)}"


def _endpoint_text(endpoint: Any) -> str:
    address = f"[{endpoint.host_address}]" if ":" in endpoint.host_address else endpoint.host_address
    return f"{address}:{endpoint.host_port}"


def _cmd_exposure(args: argparse.Namespace) -> int:
    try:
        _observed, desired = _policy_snapshot(args)
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    backend = _active_backend_name(args)
    decisions = sorted(
        desired.exposure_decisions,
        key=lambda item: (
            item.endpoint.ingress_zone, item.endpoint.host_port,
            item.endpoint.protocol, item.endpoint.host_address,
        ),
    )
    if not decisions:
        print("No externally reachable runtime endpoints.")
        return 0
    current_zone = None
    for decision in decisions:
        zone = decision.endpoint.ingress_zone.upper()
        if zone != current_zone:
            if current_zone is not None:
                print("")
            print(zone)
            print("")
            current_zone = zone
        endpoint = decision.endpoint
        print(f"{endpoint.host_port}/{endpoint.protocol}")
        print(f"  subject: {decision.subject or 'unknown'}")
        if decision.action == "allow":
            print(f"  owner: {_owner_text(endpoint)}")
            print(f"  grant: {_grant_label(decision)}")
            print(f"  backend: {backend}")
            print("  status: allowed")
        else:
            print("  status: blocked")
            print(f"  reason: {decision.reason}")
        print("")
    return 0


def _render_explanation(decision: Any, backend: str) -> None:
    endpoint = decision.endpoint
    print("ALLOW" if decision.action == "allow" else "BLOCK")
    print("")
    print("runtime endpoint:")
    print(f"  {_endpoint_text(endpoint)}")
    print("")
    print("owner:")
    print(f"  {_owner_text(endpoint)}")
    print("")
    print("subject:")
    print(f"  {decision.subject or 'unknown'}")
    print("")
    if decision.action == "allow":
        print("matched grant:")
        print(f"  {endpoint.ingress_zone}/{endpoint.protocol}/{endpoint.host_port}")
    else:
        print("reason:")
        print(f"  {decision.reason}")
    print("")
    print("backend:")
    print(f"  {backend.upper()}")


def _cmd_explain(args: argparse.Namespace) -> int:
    try:
        protocol, raw_port = args.endpoint.lower().split("/", 1)
        port = int(raw_port)
    except (AttributeError, ValueError):
        print("endpoint must be PROTOCOL/PORT, for example tcp/443", file=sys.stderr)
        return 1
    if protocol not in {"tcp", "udp", "sctp"} or not 1 <= port <= 65535:
        print("endpoint must use tcp, udp, or sctp and a port from 1 to 65535", file=sys.stderr)
        return 1
    try:
        _observed, desired = _policy_snapshot(args)
    except (OSError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    backend = _active_backend_name(args)
    matches = [
        item for item in desired.exposure_decisions
        if item.endpoint.protocol == protocol and item.endpoint.host_port == port
    ]
    if not matches:
        print("BLOCK")
        print("\nruntime endpoint:\n  not listening")
        print("\nreason:\n  no live runtime endpoint")
        print(f"\nbackend:\n  {backend.upper()}")
        return 0
    for index, decision in enumerate(matches):
        if index:
            print("\n---\n")
        _render_explanation(decision, backend)
    return 0


def _cmd_exclude_list(args: argparse.Namespace) -> int:
    _, data = _load_config(args.config)
    discovery = data.get("discovery", {})
    ports = sorted({int(p) for p in discovery.get("exclude_ports", [])})
    cidrs = sorted(_normalize_cidr(c) for c in discovery.get("exclude_bind_cidrs", []))
    if not ports and not cidrs:
        print("  (none)")
        return 0
    for port in ports:
        print(f"  port  {port}")
    for cidr in cidrs:
        print(f"  src   {cidr}")
    return 0


def _cmd_exclude_port_add(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    new_ports = _normalize_ports(args.ports)
    discovery = data.setdefault("discovery", {})
    existing = sorted({int(p) for p in discovery.get("exclude_ports", [])} | set(new_ports))
    discovery["exclude_ports"] = existing
    _write_toml(path, data)
    for port in new_ports:
        print(f"Excluded port: {port}")
    return 0


def _cmd_exclude_port_del(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    del_ports = set(_normalize_ports(args.ports))
    discovery = data.setdefault("discovery", {})
    existing = sorted({int(p) for p in discovery.get("exclude_ports", [])} - del_ports)
    discovery["exclude_ports"] = existing
    _write_toml(path, data)
    for port in sorted(del_ports):
        print(f"Un-excluded port: {port}")
    return 0


def _cmd_exclude_src_add(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    new_cidrs = [_normalize_cidr(c) for c in args.cidrs]
    discovery = data.setdefault("discovery", {})
    existing = sorted(
        set(_normalize_cidr(c) for c in discovery.get("exclude_bind_cidrs", [])) | set(new_cidrs)
    )
    discovery["exclude_bind_cidrs"] = existing
    _write_toml(path, data)
    for cidr in new_cidrs:
        print(f"Excluded src: {cidr}")
    return 0


def _cmd_exclude_src_del(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    del_cidrs = {_normalize_cidr(c) for c in args.cidrs}
    discovery = data.setdefault("discovery", {})
    existing = sorted(
        _normalize_cidr(c)
        for c in discovery.get("exclude_bind_cidrs", [])
        if _normalize_cidr(c) not in del_cidrs
    )
    discovery["exclude_bind_cidrs"] = existing
    _write_toml(path, data)
    for cidr in sorted(del_cidrs):
        print(f"Un-excluded src: {cidr}")
    return 0


def _approval_store(args: argparse.Namespace) -> Path:
    return approvals.store_path(args.run_state_dir)


def _render_approval(request: dict[str, Any]) -> None:
    ports = " ".join(str(port) for port in request.get("ports", []))
    print(
        f"  #{request['id']} {request['status']:<8} "
        f"{request['subject']} {request['zone']} {str(request['protocol']).upper()} "
        f"ports: {ports}  reason: {request.get('reason', '-') }"
    )


def _cmd_approval_list(args: argparse.Namespace) -> int:
    requests = approvals.list_requests(_approval_store(args), args.status)
    if args.json:
        print(json.dumps(requests, indent=2, sort_keys=True))
    elif not requests:
        print("  (none)")
    else:
        for request in requests:
            _render_approval(request)
    return 0


def _cmd_approval_history(args: argparse.Namespace) -> int:
    revision, history = approvals.list_history(_approval_store(args))
    if args.json:
        print(json.dumps({"revision": revision, "history": history}, indent=2, sort_keys=True))
    elif not history:
        print(f"revision {revision}: (none)")
    else:
        for item in history:
            when = _dt.datetime.fromtimestamp(float(item["at"])).isoformat(timespec="seconds")
            print(f"  r{item['revision']} #{item['request_id']} {item['action']:<7} {item['status']:<8} {item['actor']} {when}")
    return 0


def _cmd_approval_request(args: argparse.Namespace) -> int:
    request = approvals.create_request(
        _approval_store(args),
        args.config,
        subject=args.subject,
        zone=args.zone,
        protocol=args.protocol,
        ports=args.ports,
        reason=args.reason,
        systemd_unit=args.systemd_unit,
        process_name=args.process_name,
        container_runtime=args.container_runtime,
        container_id=args.container_id,
        container_name=args.container_name,
        container_label=args.container_label,
        protection_profile=args.profile,
        actor=args.actor,
    )
    print(f"Created approval request #{request['id']}")
    return 0


def _cmd_approval_approve(args: argparse.Namespace) -> int:
    request = approvals.approve_request(_approval_store(args), args.config, args.request_id, actor=args.actor)
    approvals.reload_daemon()
    print(f"Approved request #{request['id']} and updated exposure grant")
    return 0


def _cmd_approval_reject(args: argparse.Namespace) -> int:
    request = approvals.reject_request(_approval_store(args), args.request_id, reason=args.reason, actor=args.actor)
    print(f"Rejected request #{request['id']}")
    return 0


def _cmd_approval_revoke(args: argparse.Namespace) -> int:
    request = approvals.revoke_request(_approval_store(args), args.config, args.request_id, actor=args.actor)
    approvals.reload_daemon()
    print(f"Revoked request #{request['id']} exposure contribution")
    return 0


def _cmd_policy_grants(args: argparse.Namespace) -> int:
    grants = approvals.list_grants(args.config)
    if args.json:
        print(json.dumps(grants, indent=2, sort_keys=True))
    elif not grants:
        print("  (none)")
    else:
        for grant in grants:
            ports = " ".join(str(port) for port in grant["ports"])
            resolver = (
                grant["resolve"].get("systemd_unit")
                or grant["resolve"].get("process_name")
                or grant["resolve"].get("container_name")
                or grant["resolve"].get("container_id")
                or grant["resolve"].get("container_label")
                or "-"
            )
            profile = grant.get("protection_profile") or "-"
            print(f"  {grant['subject']:<20} {grant['zone']:<10} {grant['protocol'].upper():<5} ports: {ports} resolver: {resolver} profile: {profile}")
    return 0


def _cmd_port_handler_unload(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, _ = _slot_paths(args)
    proto = str(args.proto).lower()
    port = _normalize_handler_port(int(args.port))

    _cleanup_existing_port_handler(bpf_pin_dir, proto, port)
    print(f"Unloaded {proto.upper()} handler for port {port}")
    if not args.no_config_update and path.exists():
        _port_handler_config_update(path, proto, port, None)
        print(f"  config: {path}")
    return 0


_NFT_CHAIN = "input"

_XDP_COUNTER_NAMES = [
    "TCP_NEW_ALLOW",
    "TCP_PASS",
    "TCP_DROP",
    "UDP_PASS",
    "UDP_DROP",
    "IPv4_OTHER",
    "IPv6_ICMP",
    "FRAG_DROP",
    "ARP_NON_IP",
    "TCP_RESERVED",
    "ICMP_DROP",
    "SYN_RATE_DROP",
    "UDP_RATE_DROP",
    "UDP_GBL_DROP",
    "TCP_NULL",
    "TCP_XMAS",
    "TCP_SYN_FIN",
    "TCP_SYN_RST",
    "TCP_RST_FIN",
    "TCP_BAD_DOFF",
    "TCP_PORT0",
    "VLAN_DROP",
    "SLOT_CALL",
    "SLOT_PASS",
    "SLOT_DROP",
    "UDP_PORT0",
    "UDP_BAD_LEN",
    "BOGON_DROP",
    "RESERVED_28",
    "SYN_AGG_RATE_DROP",
    "UDP_AGG_RATE_DROP",
    "HANDLER_BLOCK_DROP",
    "RESERVED_32",
    "RESERVED_33",
    "ABUSEIPDB_DROP",
]

_XDP_DROP_INDEXES = {
    idx
    for idx, name in enumerate(_XDP_COUNTER_NAMES)
    if name.endswith("_DROP") or name.endswith("_GBL_DROP")
}


def _human_bytes(value: int) -> str:
    if value == -1:
        return "-"
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    val = float(value)
    idx = 0
    while val >= 1024 and idx < len(units) - 1:
        val /= 1024
        idx += 1
    if idx == 0:
        return f"{val:.0f} {units[idx]}"
    return f"{val:.2f} {units[idx]}"


def _human_bps(value: int) -> str:
    if value == -1:
        return "-"
    units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]
    val = float(value)
    idx = 0
    while val >= 1000 and idx < len(units) - 1:
        val /= 1000
        idx += 1
    if idx == 0:
        return f"{val:.0f} {units[idx]}"
    return f"{val:.2f} {units[idx]}"


def _format_rate(packet_delta: int, byte_delta: int, elapsed: float) -> str:
    if packet_delta == -1 or elapsed == 0:
        return "-"
    pps = packet_delta / elapsed
    if byte_delta == -1:
        return f"{pps:.2f} pps / -"
    bps = int(byte_delta * 8 / elapsed)
    return f"{pps:.2f} pps / {_human_bps(bps)}"


def _read_byte_counters(bpf_pin_dir: str) -> tuple[int, int, int, int]:
    """Return (total_bytes, drop_bytes, total_pkts, drop_pkts); -1 when unavailable."""
    map_path = Path(bpf_pin_dir) / "byte_counters"
    if not map_path.exists():
        return -1, -1, -1, -1
    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", str(map_path)],
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(out)
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError):
        return -1, -1, -1, -1

    key_vals: dict[int, int] = {}
    for row in data:
        k = row.get("key")
        if isinstance(k, int):
            idx = k
        elif isinstance(k, list):
            b = bytes((int(x, 0) if isinstance(x, str) else x) & 0xFF for x in k[:4])
            idx = int.from_bytes(b, "little")
        else:
            continue
        v = row.get("values", row.get("value", 0))
        if isinstance(v, list):
            total = 0
            for e in v:
                if isinstance(e, dict):
                    val = e.get("value", 0)
                    if isinstance(val, list):
                        raw = bytes((int(b, 0) if isinstance(b, str) else int(b)) & 0xFF for b in val)
                        total += int.from_bytes(raw, "little")
                    elif isinstance(val, int):
                        total += val
                    elif isinstance(val, str):
                        try:
                            total += int(val, 0)
                        except ValueError:
                            pass
                elif isinstance(e, str):
                    try:
                        total += int(e, 0)
                    except ValueError:
                        pass
                elif isinstance(e, int):
                    total += e
        elif isinstance(v, int):
            total = v
        else:
            total = 0
        key_vals[idx] = key_vals.get(idx, 0) + total

    total_bytes = key_vals.get(0, 0)
    drop_bytes = key_vals.get(1, 0)
    # Indices 2/3 (total_pkts/drop_pkts) present only in BPF objects built after
    # byte_counters was expanded from 2 to 4 entries.
    total_pkts = key_vals.get(2, -1)
    drop_pkts = key_vals.get(3, -1)
    return total_bytes, drop_bytes, total_pkts, drop_pkts


def _read_xdp_rows(bpf_pin_dir: str) -> list[tuple[str, int, int]]:
    map_path = Path(bpf_pin_dir) / "pkt_counters"
    if not map_path.exists():
        raise RuntimeError(f"XDP counters not found at {map_path}")

    if not shutil.which("bpftool"):
        raise RuntimeError("bpftool not found; cannot read XDP counters")

    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", str(map_path)],
            stderr=subprocess.DEVNULL,
        )
        data = json.loads(out)
    except (subprocess.CalledProcessError, json.JSONDecodeError, OSError) as exc:
        hint = ""
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            hint = " (reading pinned BPF maps needs root; try: sudo axdp stats)"
        raise RuntimeError(f"Failed to read XDP counters: {exc}{hint}") from exc

    def _bytelist_to_int(lst: list) -> int:
        try:
            raw = bytes((int(b, 0) if isinstance(b, str) else int(b)) & 0xFF for b in lst)
            return int.from_bytes(raw, "little")
        except (ValueError, TypeError):
            return 0

    def _sum_percpu(v: Any) -> int:
        if isinstance(v, list):
            total = 0
            for e in v:
                if isinstance(e, dict):
                    val = e.get("value", 0)
                    if isinstance(val, list):
                        total += _bytelist_to_int(val)
                    elif isinstance(val, int):
                        total += val
                    elif isinstance(val, str):
                        try:
                            total += int(val, 0)
                        except ValueError:
                            pass
                elif isinstance(e, str):
                    try:
                        total += int(e, 0)
                    except ValueError:
                        pass
                elif isinstance(e, int):
                    total += e
            return total
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            try:
                return int(v, 0)
            except ValueError:
                return 0
        return 0

    def _parse_key(key: Any) -> int:
        if isinstance(key, int):
            return key
        if isinstance(key, str):
            try:
                return int(key, 0)
            except ValueError:
                return -1
        if isinstance(key, list):
            b = bytes((int(b, 0) if isinstance(b, str) else b) & 0xFF for b in key[:4])
            return int.from_bytes(b, "little")
        return -1

    key_packets: dict[int, int] = {}
    for row in data:
        v = row.get("values", row.get("value", 0))
        packets = _sum_percpu(v)
        k = _parse_key(row.get("key", -1))
        if k >= 0:
            key_packets[k] = key_packets.get(k, 0) + packets

    rows: list[tuple[str, int, int]] = []
    total = 0
    drop_total = 0
    for idx in range(len(_XDP_COUNTER_NAMES)):
        packets = key_packets.get(idx, 0)
        total += packets
        if idx in _XDP_DROP_INDEXES:
            drop_total += packets
        rows.append((_XDP_COUNTER_NAMES[idx], packets, -1))

    for idx in sorted(key_packets.keys()):
        if idx >= len(_XDP_COUNTER_NAMES):
            rows.append((f"COUNTER_{idx}", key_packets[idx], -1))

    total_bytes, drop_bytes, total_pkts, drop_pkts = _read_byte_counters(bpf_pin_dir)
    # Use byte_counters packet counts when available: they are incremented exactly
    # once per packet, unlike pkt_counters where some paths fire two count() calls.
    xdp_total = total_pkts if total_pkts >= 0 else total
    xdp_drop = drop_pkts if drop_pkts >= 0 else drop_total
    rows.append(("XDP_TOTAL", xdp_total, total_bytes))
    rows.append(("XDP_DROP_TOTAL", xdp_drop, drop_bytes))
    return rows


def _read_xdp_map_id(bpf_pin_dir: str) -> str:
    map_path = str(Path(bpf_pin_dir) / "pkt_counters")
    try:
        result = subprocess.run(
            ["bpftool", "map", "show", "pinned", map_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return "-"
        first_line = result.stdout.splitlines()[0] if result.stdout.strip() else ""
        m = re.match(r"^(\d+):", first_line)
        if m:
            return m.group(1)
    except OSError:
        pass
    return "-"


def _read_nft_rows(nft_family: str, nft_table: str, nft_chain: str) -> list[tuple[str, int, int]]:
    try:
        result = subprocess.run(
            ["nft", "-a", "list", "chain", nft_family, nft_table, nft_chain],
            capture_output=True,
            text=True,
        )
        text = result.stdout
    except OSError:
        text = ""
    m = re.search(r"counter packets (\d+) bytes (\d+) drop", text)
    if not m:
        return [("NFT_DROP", 0, 0)]
    return [("NFT_DROP", int(m.group(1)), int(m.group(2)))]


def _read_iface_row(iface: str) -> tuple[str, int, int] | None:
    stats_dir = Path(f"/sys/class/net/{iface}/statistics")
    rx_pkt = stats_dir / "rx_packets"
    rx_bytes = stats_dir / "rx_bytes"
    try:
        packets = int(rx_pkt.read_text().strip())
        b = int(rx_bytes.read_text().strip())
        return ("IFACE_RX", packets, b)
    except OSError:
        return None


def _load_stats_state(state_file: Path) -> dict:
    try:
        return json.loads(state_file.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save_stats_state(state_file: Path, data: dict) -> None:
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(str(state_file) + f".tmp.{os.getpid()}")
        tmp.write_text(json.dumps(data))
        tmp.replace(state_file)
    except OSError:
        pass


def _apply_xdp_accumulator(
    rows: list[tuple[str, int, int]],
    backend: str,
    iface: str,
    map_id: str,
    state_file: Path,
) -> list[tuple[str, int, int]]:
    if backend != "xdp":
        return rows

    # Find current totals
    current_total: int | None = None
    current_drop: int | None = None
    current_total_bytes: int = -1
    current_drop_bytes: int = -1
    for name, packets, b in rows:
        if name == "XDP_TOTAL":
            current_total = packets
            current_total_bytes = b
        elif name == "XDP_DROP_TOTAL":
            current_drop = packets
            current_drop_bytes = b

    if current_total is None or current_drop is None:
        return rows

    state = _load_stats_state(state_file)
    prev_backend = state.get("backend", "")
    prev_iface = state.get("iface", "")
    prev_map_id = state.get("map_id", "")
    prev_raw_total = state.get("raw_total")
    prev_raw_drop = state.get("raw_drop")
    prev_acc_total = state.get("acc_total")
    prev_acc_drop = state.get("acc_drop")
    prev_raw_total_bytes = state.get("raw_total_bytes")
    prev_raw_drop_bytes = state.get("raw_drop_bytes")
    prev_acc_total_bytes = state.get("acc_total_bytes")
    prev_acc_drop_bytes = state.get("acc_drop_bytes")

    acc_total = current_total
    acc_drop = current_drop
    acc_total_bytes = current_total_bytes
    acc_drop_bytes = current_drop_bytes

    same_context = (
        prev_backend == backend
        and prev_iface == iface
        and prev_map_id == map_id
        and prev_map_id != "-"
        and map_id != "-"
        and isinstance(prev_raw_total, int)
        and isinstance(prev_raw_drop, int)
        and isinstance(prev_acc_total, int)
        and isinstance(prev_acc_drop, int)
    )
    # map_id changed (BPF reload) or bpftool failed — preserve history if same iface
    same_iface = (
        prev_backend == backend
        and prev_iface == iface
        and isinstance(prev_acc_total, int)
        and isinstance(prev_acc_drop, int)
    )

    if same_context:
        # same_context already verified these are ints via isinstance above.
        assert isinstance(prev_raw_total, int) and isinstance(prev_acc_total, int)
        assert isinstance(prev_raw_drop, int) and isinstance(prev_acc_drop, int)
        if current_total >= prev_raw_total:
            acc_total = prev_acc_total + (current_total - prev_raw_total)
        else:
            acc_total = prev_acc_total + current_total
        if current_drop >= prev_raw_drop:
            acc_drop = prev_acc_drop + (current_drop - prev_raw_drop)
        else:
            acc_drop = prev_acc_drop + current_drop

        if (
            current_total_bytes >= 0
            and isinstance(prev_raw_total_bytes, int) and prev_raw_total_bytes >= 0
            and isinstance(prev_acc_total_bytes, int) and prev_acc_total_bytes >= 0
        ):
            if current_total_bytes >= prev_raw_total_bytes:
                acc_total_bytes = prev_acc_total_bytes + (current_total_bytes - prev_raw_total_bytes)
            else:
                acc_total_bytes = prev_acc_total_bytes + current_total_bytes

        if (
            current_drop_bytes >= 0
            and isinstance(prev_raw_drop_bytes, int) and prev_raw_drop_bytes >= 0
            and isinstance(prev_acc_drop_bytes, int) and prev_acc_drop_bytes >= 0
        ):
            if current_drop_bytes >= prev_raw_drop_bytes:
                acc_drop_bytes = prev_acc_drop_bytes + (current_drop_bytes - prev_raw_drop_bytes)
            else:
                acc_drop_bytes = prev_acc_drop_bytes + current_drop_bytes

    elif same_iface:
        # map_id changed (BPF reload) or bpftool couldn't get map_id:
        # treat current raw as new counts on top of previous accumulated total
        # same_iface already verified these are ints via isinstance above.
        assert isinstance(prev_acc_total, int) and isinstance(prev_acc_drop, int)
        acc_total = prev_acc_total + current_total
        acc_drop = prev_acc_drop + current_drop

        if (
            current_total_bytes >= 0
            and isinstance(prev_acc_total_bytes, int) and prev_acc_total_bytes >= 0
        ):
            acc_total_bytes = prev_acc_total_bytes + current_total_bytes

        if (
            current_drop_bytes >= 0
            and isinstance(prev_acc_drop_bytes, int) and prev_acc_drop_bytes >= 0
        ):
            acc_drop_bytes = prev_acc_drop_bytes + current_drop_bytes

    # Don't persist state when map_id is unknown — we can't detect future context changes
    if map_id == "-":
        updated = []
        for name, packets, b in rows:
            if name == "XDP_TOTAL":
                updated.append(("XDP_TOTAL", acc_total, acc_total_bytes))
            elif name == "XDP_DROP_TOTAL":
                updated.append(("XDP_DROP_TOTAL", acc_drop, acc_drop_bytes))
            else:
                updated.append((name, packets, b))
        return updated

    _save_stats_state(
        state_file,
        {
            "backend": backend,
            "iface": iface,
            "map_id": map_id,
            "raw_total": current_total,
            "raw_drop": current_drop,
            "acc_total": acc_total,
            "acc_drop": acc_drop,
            "raw_total_bytes": current_total_bytes,
            "raw_drop_bytes": current_drop_bytes,
            "acc_total_bytes": acc_total_bytes,
            "acc_drop_bytes": acc_drop_bytes,
        },
    )

    updated = []
    for name, packets, b in rows:
        if name == "XDP_TOTAL":
            updated.append(("XDP_TOTAL", acc_total, acc_total_bytes))
        elif name == "XDP_DROP_TOTAL":
            updated.append(("XDP_DROP_TOTAL", acc_drop, acc_drop_bytes))
        else:
            updated.append((name, packets, b))
    return updated


def _collect_stats_rows(
    backend: str,
    bpf_pin_dir: str,
    iface: str,
    nft_family: str,
    nft_table: str,
    state_file: Path,
) -> tuple[list[tuple[str, int, int]], str]:
    map_id = "-"
    if backend == "xdp":
        rows = _read_xdp_rows(bpf_pin_dir)
        map_id = _read_xdp_map_id(bpf_pin_dir)
        iface_row = _read_iface_row(iface)
        rows = _apply_xdp_accumulator(rows, backend, iface, map_id, state_file)
    else:
        rows = _read_nft_rows(nft_family, nft_table, _NFT_CHAIN)
        iface_row = _read_iface_row(iface)

    if iface_row is not None:
        rows = list(rows) + [iface_row]

    return rows, map_id


def _render_stats(
    rows: list[tuple[str, int, int]],
    prev: dict[str, tuple[int, int]],
    backend: str,
    iface: str,
    map_id: str,
    show_rates: bool,
    elapsed: float,
) -> None:
    import datetime as _datetime

    print(f"Backend   : {backend}")
    print(f"Interface : {iface}")
    if backend == "xdp":
        print(f"Map ID    : {map_id}")
    print(f"Updated   : {_datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")
    print("")

    # Header
    header = f"{'Metric':<12}  {'Packets':<15}  {'Bytes':<12}"
    sep = f"{'------------':<12}  {'---------------':<15}  {'------------':<12}"
    if show_rates:
        header += f"  {'Rate':<24}"
        sep += f"  {'------------------------':<24}"
    print(header)
    print(sep)

    reset_hints: list[str] = []
    for name, packets, b in rows:
        prev_packets, prev_bytes = prev.get(name, (-1, -1))

        # Detect reset
        if prev_packets >= 0 and packets < prev_packets:
            reset_hints.append(f"{name}:{prev_packets}->{packets}")

        line = f"{name:<12}  {packets:<15}  {_human_bytes(b):<12}"

        if show_rates:
            if prev_packets >= 0:
                packet_delta = packets - prev_packets
                if packet_delta < 0:
                    packet_delta = -1
                if b == -1 or prev_bytes == -1:
                    byte_delta = -1
                else:
                    byte_delta = b - prev_bytes
                    if byte_delta < 0:
                        byte_delta = -1
                rate = _format_rate(packet_delta, byte_delta, elapsed)
            else:
                rate = "-"
            line += f"  {rate:<24}"

        print(line)

    if reset_hints:
        print(f"\nResetHint : {', '.join(reset_hints)}")


def _cmd_stats(args: argparse.Namespace) -> int:
    import time as _time

    ifaces: list[str] = (args.iface or "").split() or []
    if not ifaces:
        try:
            ifaces = [_autodetect_iface()]
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1

    iface = ifaces[0]

    try:
        backend = _detect_backend(Path(args.bpf_pin_dir), Path(args.run_state_dir), ifaces, args.nft_family, args.nft_table)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    state_file = Path(args.run_state_dir) / "axdp_stats.json"
    interval: float = args.interval
    show_rates: bool = args.rates
    watch: bool = args.watch
    render_mode: str = args.render  # "append" or "screen"

    def collect() -> tuple[list[tuple[str, int, int]], str]:
        return _collect_stats_rows(backend, args.bpf_pin_dir, iface, args.nft_family, args.nft_table, state_file)

    def rows_to_prev(rows: list[tuple[str, int, int]]) -> dict[str, tuple[int, int]]:
        return {name: (packets, b) for name, packets, b in rows}

    if watch:
        try:
            rows, map_id = collect()
            prev = rows_to_prev(rows)
            prev_ts = _time.monotonic()

            if render_mode == "screen":
                print("\033[H\033[2J", end="", flush=True)

            while True:
                _time.sleep(interval)
                cur_ts = _time.monotonic()
                elapsed = cur_ts - prev_ts if show_rates else 0.0
                try:
                    rows, map_id = collect()
                except RuntimeError as exc:
                    print(str(exc), file=sys.stderr)
                    _time.sleep(interval)
                    continue

                if render_mode == "screen":
                    print("\033[H", end="", flush=True)
                else:
                    import datetime as _dt
                    print(f"===== {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} =====")

                _render_stats(rows, prev if show_rates else {}, backend, iface, map_id, show_rates, elapsed)

                if render_mode == "screen":
                    print("\033[J", end="", flush=True)
                else:
                    print("")

                prev = rows_to_prev(rows)
                prev_ts = cur_ts
        except KeyboardInterrupt:
            return 0
        return 0

    if show_rates:
        try:
            rows, map_id = collect()
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        prev = rows_to_prev(rows)
        prev_ts = _time.monotonic()
        _time.sleep(interval)
        cur_ts = _time.monotonic()
        elapsed = cur_ts - prev_ts
        try:
            rows, map_id = collect()
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        _render_stats(rows, prev, backend, iface, map_id, show_rates, elapsed)
        return 0

    try:
        rows, map_id = collect()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    _render_stats(rows, {}, backend, iface, map_id, show_rates=False, elapsed=0.0)
    return 0


def _cmd_tui(args: argparse.Namespace) -> int:
    from auto_xdp.tui import run_tui

    try:
        return run_tui(args)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m auto_xdp.admin_cli")
    parser.add_argument("--config", required=True)
    parser.add_argument("--bpf-pin-dir", default="/sys/fs/bpf/xdp_fw")
    parser.add_argument("--install-dir", default="/usr/local/lib/auto_xdp/current")
    parser.add_argument("--handlers-dir", default="/etc/auto_xdp/handlers")
    parser.add_argument("--run-state-dir", default="/run/auto_xdp")
    parser.add_argument("--nft-family", default="inet")
    parser.add_argument("--nft-table", default="auto_xdp")
    parser.add_argument("--iface", default="")
    subparsers = parser.add_subparsers(dest="command", required=True)

    config_cmd = subparsers.add_parser("config")
    config_sub = config_cmd.add_subparsers(dest="subcommand", required=True)
    config_show = config_sub.add_parser("show")
    config_show.set_defaults(func=_cmd_config_show)
    config_init = config_sub.add_parser("init")
    config_init.set_defaults(func=_cmd_config_init)

    log_level = subparsers.add_parser("log-level")
    log_level.add_argument("level", nargs="?")
    log_level.set_defaults(func=_cmd_log_level)

    under_attack = subparsers.add_parser("under-attack")
    under_attack.add_argument("mode", nargs="?")
    under_attack.set_defaults(func=_cmd_under_attack)

    trust = subparsers.add_parser("trust")
    trust_sub = trust.add_subparsers(dest="subcommand", required=True)
    trust_list = trust_sub.add_parser("list")
    trust_list.set_defaults(func=_cmd_trust_list)
    trust_add = trust_sub.add_parser("add")
    trust_add.add_argument("cidr")
    trust_add.add_argument("label", nargs="?", default="manual")
    trust_add.set_defaults(func=_cmd_trust_add)
    trust_del = trust_sub.add_parser("del")
    trust_del.add_argument("cidr")
    trust_del.set_defaults(func=_cmd_trust_del)

    acl = subparsers.add_parser("acl")
    acl_sub = acl.add_subparsers(dest="subcommand", required=True)
    acl_list = acl_sub.add_parser("list")
    acl_list.set_defaults(func=_cmd_acl_list)
    acl_add = acl_sub.add_parser("add")
    acl_add.add_argument("proto", choices=["tcp", "udp"])
    acl_add.add_argument("cidr")
    acl_add.add_argument("ports", nargs="+", type=int)
    acl_add.set_defaults(func=_cmd_acl_add)
    acl_del = acl_sub.add_parser("del")
    acl_del.add_argument("proto", choices=["tcp", "udp"])
    acl_del.add_argument("cidr")
    acl_del.set_defaults(func=_cmd_acl_del)

    slot = subparsers.add_parser("slot")
    slot_sub = slot.add_subparsers(dest="subcommand", required=True)
    slot_list = slot_sub.add_parser("list")
    slot_list.set_defaults(func=_cmd_slot_list)
    slot_load = slot_sub.add_parser("load")
    slot_load.add_argument("name_or_proto")
    slot_load.add_argument("path", nargs="?")
    slot_load.set_defaults(func=_cmd_slot_load)
    slot_unload = slot_sub.add_parser("unload")
    slot_unload.add_argument("name_or_proto")
    slot_unload.set_defaults(func=_cmd_slot_unload)

    slot_builtin = subparsers.add_parser("slot-enable-builtin")
    slot_builtin.add_argument("name", choices=["gre", "esp", "sctp"])
    slot_builtin.set_defaults(func=_cmd_slot_enable_builtin)

    slot_custom = subparsers.add_parser("slot-enable-custom")
    slot_custom.add_argument("proto", type=int)
    slot_custom.add_argument("path")
    slot_custom.set_defaults(func=_cmd_slot_enable_custom)

    slot_disable = subparsers.add_parser("slot-disable")
    slot_disable.add_argument("proto", type=int)
    slot_disable.set_defaults(func=_cmd_slot_disable)

    port_handler = subparsers.add_parser("port-handler")
    port_handler_sub = port_handler.add_subparsers(dest="subcommand", required=True)
    port_handler_list = port_handler_sub.add_parser("list")
    port_handler_list.set_defaults(func=_cmd_port_handler_list)
    port_handler_load = port_handler_sub.add_parser("load")
    port_handler_load.add_argument("proto", choices=["tcp", "udp"])
    port_handler_load.add_argument("port", type=int)
    port_handler_load.add_argument("path")
    port_handler_load.add_argument("--no-config-update", action="store_true")
    port_handler_load.set_defaults(func=_cmd_port_handler_load)
    port_handler_unload = port_handler_sub.add_parser("unload")
    port_handler_unload.add_argument("proto", choices=["tcp", "udp"])
    port_handler_unload.add_argument("port", type=int)
    port_handler_unload.add_argument("--no-config-update", action="store_true")
    port_handler_unload.set_defaults(func=_cmd_port_handler_unload)

    exclude = subparsers.add_parser("exclude")
    exclude_sub = exclude.add_subparsers(dest="subcommand", required=True)
    exclude_list = exclude_sub.add_parser("list")
    exclude_list.set_defaults(func=_cmd_exclude_list)
    exclude_port = exclude_sub.add_parser("port")
    exclude_port_sub = exclude_port.add_subparsers(dest="subsubcommand", required=True)
    exclude_port_add = exclude_port_sub.add_parser("add")
    exclude_port_add.add_argument("ports", nargs="+", type=int)
    exclude_port_add.set_defaults(func=_cmd_exclude_port_add)
    exclude_port_del = exclude_port_sub.add_parser("del")
    exclude_port_del.add_argument("ports", nargs="+", type=int)
    exclude_port_del.set_defaults(func=_cmd_exclude_port_del)
    exclude_src = exclude_sub.add_parser("src")
    exclude_src_sub = exclude_src.add_subparsers(dest="subsubcommand", required=True)
    exclude_src_add = exclude_src_sub.add_parser("add")
    exclude_src_add.add_argument("cidrs", nargs="+")
    exclude_src_add.set_defaults(func=_cmd_exclude_src_add)
    exclude_src_del = exclude_src_sub.add_parser("del")
    exclude_src_del.add_argument("cidrs", nargs="+")
    exclude_src_del.set_defaults(func=_cmd_exclude_src_del)

    approval = subparsers.add_parser("approval")
    approval_sub = approval.add_subparsers(dest="subcommand", required=True)
    approval_list = approval_sub.add_parser("list")
    approval_list.add_argument("--status", choices=["all", "pending", "approved", "rejected", "revoked"], default="all")
    approval_list.add_argument("--json", action="store_true")
    approval_list.set_defaults(func=_cmd_approval_list)
    approval_history = approval_sub.add_parser("history")
    approval_history.add_argument("--json", action="store_true")
    approval_history.set_defaults(func=_cmd_approval_history)
    approval_request = approval_sub.add_parser("request")
    approval_request.add_argument("subject")
    approval_request.add_argument("zone")
    approval_request.add_argument("protocol", choices=["tcp", "udp", "sctp"])
    approval_request.add_argument("ports", nargs="+", type=int)
    approval_request.add_argument("--reason", required=True)
    approval_request.add_argument("--systemd-unit", default="")
    approval_request.add_argument("--process-name", default="")
    approval_request.add_argument("--container-runtime", choices=["docker", "podman"], default="")
    approval_request.add_argument("--container-id", default="")
    approval_request.add_argument("--container-name", default="")
    approval_request.add_argument("--container-label", default="")
    approval_request.add_argument("--profile", default="")
    approval_request.add_argument("--actor")
    approval_request.set_defaults(func=_cmd_approval_request)
    approval_approve = approval_sub.add_parser("approve")
    approval_approve.add_argument("request_id", type=int)
    approval_approve.add_argument("--actor")
    approval_approve.set_defaults(func=_cmd_approval_approve)
    approval_reject = approval_sub.add_parser("reject")
    approval_reject.add_argument("request_id", type=int)
    approval_reject.add_argument("--reason", required=True)
    approval_reject.add_argument("--actor")
    approval_reject.set_defaults(func=_cmd_approval_reject)
    approval_revoke = approval_sub.add_parser("revoke")
    approval_revoke.add_argument("request_id", type=int)
    approval_revoke.add_argument("--actor")
    approval_revoke.set_defaults(func=_cmd_approval_revoke)

    policy = subparsers.add_parser("policy")
    policy_sub = policy.add_subparsers(dest="subcommand", required=True)
    grants = policy_sub.add_parser("grants")
    grants.add_argument("--json", action="store_true")
    grants.set_defaults(func=_cmd_policy_grants)

    ports_cmd = subparsers.add_parser("ports")
    ports_cmd.add_argument("--watch", action="store_true")
    ports_cmd.add_argument("--interval", type=float, default=2.0)
    ports_cmd.set_defaults(func=_cmd_ports)

    exposure_cmd = subparsers.add_parser("exposure")
    exposure_cmd.set_defaults(func=_cmd_exposure)

    explain_cmd = subparsers.add_parser("explain")
    explain_cmd.add_argument("endpoint", help="runtime endpoint, for example tcp/443")
    explain_cmd.set_defaults(func=_cmd_explain)

    stats_cmd = subparsers.add_parser("stats")
    stats_cmd.add_argument("--watch", action="store_true")
    stats_cmd.add_argument("--rates", action="store_true")
    stats_cmd.add_argument("--interval", type=float, default=1.0)
    stats_cmd.add_argument("--render", choices=["append", "screen"], default="append")
    stats_cmd.add_argument("--interface", dest="iface")
    stats_cmd.set_defaults(func=_cmd_stats)

    tui_cmd = subparsers.add_parser("tui")
    tui_cmd.add_argument("--interval", type=float, default=2.0)
    tui_cmd.add_argument("--socket")
    tui_cmd.add_argument("--max-events", dest="tui_max_events", type=int)
    tui_cmd.add_argument("--interface", dest="iface")
    tui_cmd.set_defaults(func=_cmd_tui)

    approval_api = subparsers.add_parser("approval-api")
    approval_api.add_argument("--socket-path")
    approval_api.set_defaults(func=lambda args: approvals.run_api(
        args.config,
        args.run_state_dir,
        args.socket_path or str(Path(args.run_state_dir) / "approval.sock"),
    ))

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {"approval", "approval-api"} and os.geteuid() != 0:
        print("approval management requires root; try re-running with sudo", file=sys.stderr)
        return 77
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Permission denied: {exc}", file=sys.stderr)
        print("This command needs root; try re-running with sudo.", file=sys.stderr)
        return 77


if __name__ == "__main__":
    sys.exit(main())
