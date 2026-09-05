from __future__ import annotations

import curses
import datetime as _dt
import hashlib
import json
import os
import select
import shutil
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from auto_xdp.admin_cli import (
    _collect_ports,
    _collect_stats_rows,
    _detect_backend,
    _format_rate,
    _human_bytes,
    _lookup_port_procs,
    _read_xdp_map_id,
    _read_xdp_ports,
    _autodetect_iface,
)
from auto_xdp import approvals
from auto_xdp.bpf.maps import BpfGlobalRlMap, BpfPortPolicyMap
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.discovery import get_listening_ports
from auto_xdp.policy import resolve_desired_state


DEFAULT_SOCKET = "/var/run/auto_xdp/pkt_events.sock"
DEFAULT_TUI_MAX_EVENTS = 500
MAP_INFO_INTERVAL = 10.0
MAP_COUNT_INTERVAL = 10.0
HIGH_CHURN_MAP_COUNT_INTERVAL = 30.0
TUI_IDLE_REDRAW_INTERVAL = 1.0

# curses color pair indices
_CP_GREEN = 2
_CP_RED = 3
_CP_YELLOW = 4
_CP_BLACK_ON_GREEN = 5
_CP_BLACK_ON_YELLOW = 6
_CP_WHITE_ON_RED = 7
_CP_CYAN = 8
_CP_BLACK_ON_CYAN = 9

_HIGH_CHURN_MAPS = {
    "hblk4",
    "hblk6",
    "udp_hv4",
    "udp_hv6",
    "syn4",
    "syn6",
    "synag4",
    "synag6",
    "udprt4",
    "udprt6",
    "udpag4",
    "udpag6",
}

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


@dataclass
class MapUsage:
    name: str
    kind: str
    current: int | None
    maximum: int | None
    pct: float | None
    note: str = ""
    map_id: int | None = None
    memlock: int | None = None


@dataclass
class TuiSnapshot:
    backend: str = "-"
    iface: str = "-"
    map_id: str = "-"
    attach_mode: str = "-"
    attach_target: str = "-"
    attach_targets: list[tuple[str, str]] = field(default_factory=list)
    collected_at: float = 0.0
    stats: list[tuple[str, int, int, str]] = field(default_factory=list)
    maps: list[MapUsage] = field(default_factory=list)
    ports: list[tuple[str, int, str, str, str]] = field(default_factory=list)
    excluded: tuple[int, int] = (0, 0)
    under_attack: bool = False
    audit_rows: list[dict[str, Any]] = field(default_factory=list)
    audit_fingerprint: str = ""
    approval_rows: list[dict[str, Any]] = field(default_factory=list)
    audit_status: str = ""
    status: str = ""


@dataclass
class TrafficRow:
    ip: str
    proto: str
    port: str
    packets: int
    bytes_: int | None
    verdict: str
    last_seen: float


@dataclass
class MapUsageCache:
    counts: dict[str, int] = field(default_factory=dict)
    refreshed_at: dict[str, float] = field(default_factory=dict)
    map_info: dict[str, dict[str, Any]] = field(default_factory=dict)
    map_info_refreshed_at: float = 0.0


class RelayClient:
    def __init__(self, path: str, max_events: int = 500) -> None:
        self.path = path
        self.max_events = max_events
        self.events: list[dict[str, Any]] = []
        self.events_offset = 0
        self.status = "relay: disconnected"
        self._sock: socket.socket | None = None
        self._buf = bytearray()
        self._next_retry = 0.0
        self.ports_dirty: bool = False
        self.reason_totals: dict[str, int] = {}

    @property
    def events_end(self) -> int:
        return self.events_offset + len(self.events)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._sock = None

    def poll(self) -> None:
        now = time.monotonic()
        if self._sock is None:
            if now < self._next_retry:
                return
            self._next_retry = now + 2.0
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.setblocking(False)
                sock.connect(self.path)
            except BlockingIOError:
                self._sock = sock
                self.status = "relay: connecting"
            except OSError as exc:
                if exc.errno == 2:
                    self.status = "relay: socket missing; run `sudo systemctl restart auto-xdp-relay`"
                else:
                    self.status = f"relay: {exc.strerror or exc}"
                return
            else:
                self._sock = sock
                self.status = "relay: connected"

        sock = self._sock
        if sock is None:
            return
        try:
            readable, _, _ = select.select([sock], [], [], 0)
        except OSError:
            self.close()
            self.status = "relay: disconnected"
            return
        if not readable:
            return

        while True:
            try:
                chunk = sock.recv(65536)
            except BlockingIOError:
                break
            except OSError:
                self.close()
                self.status = "relay: disconnected"
                break
            if not chunk:
                self.close()
                self.status = "relay: disconnected"
                break
            self._buf += chunk

        while True:
            nl = self._buf.find(b"\n")
            if nl < 0:
                break
            line = self._buf[:nl]
            del self._buf[:nl + 1]
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("type") == "history":
                history = msg.get("events", [])
                if isinstance(history, list):
                    history = history[-self.max_events:]
                else:
                    history = []
                for ev in history:
                    self._append(ev)
            elif msg.get("type") == "event":
                self._append(msg)
            self.status = "relay: connected"

    def _append(self, event: dict[str, Any]) -> None:
        event.setdefault("seen_at", time.time())
        if event.get("type") == "port_change":
            self.ports_dirty = True
        elif str(event.get("verdict", "")) == "DROP":
            reason = str(event.get("reason") or "unknown")
            self.reason_totals[reason] = self.reason_totals.get(reason, 0) + 1
        self.events.append(event)
        if len(self.events) > self.max_events:
            drop_count = len(self.events) - self.max_events
            del self.events[:drop_count]
            self.events_offset += drop_count


def _load_toml(path: str) -> dict[str, Any]:
    if tomllib is None:
        return {}
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (FileNotFoundError, OSError):
        return {}


def _ringbuf_cfg(path: str) -> dict[str, Any]:
    cfg = _load_toml(path).get("ringbuf", {})
    return cfg if isinstance(cfg, dict) else {}


def _under_attack_enabled(path: str) -> bool:
    cfg = _load_toml(path).get("under_attack", {})
    return bool(cfg.get("enabled", False)) if isinstance(cfg, dict) else False


def _excluded_counts(path: str) -> tuple[int, int]:
    """Return (excluded_ports, excluded_cidrs) from discovery config."""
    discovery = _load_toml(path).get("discovery", {})
    if not isinstance(discovery, dict):
        return 0, 0
    ports = len(discovery.get("exclude_ports", []) or [])
    cidrs = len(discovery.get("exclude_bind_cidrs", []) or [])
    return ports, cidrs


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _run_json(cmd: list[str]) -> Any:
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
    return json.loads(out)


def _all_map_info() -> dict[str, dict[str, Any]]:
    """Single bpftool call → map name → metadata dict."""
    if not shutil.which("bpftool"):
        return {}
    try:
        data = _run_json(["bpftool", "-j", "map"])
    except (subprocess.CalledProcessError, OSError, json.JSONDecodeError):
        return {}
    result: dict[str, dict[str, Any]] = {}
    if isinstance(data, list):
        for entry in data:
            if isinstance(entry, dict) and "name" in entry:
                name = str(entry["name"])
                if name not in result:
                    result[name] = entry
    return result


def _dump_count(path: Path) -> int | None:
    try:
        out = subprocess.check_output(
            ["bpftool", "-j", "map", "dump", "pinned", str(path)],
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    # bpftool -j emits a compact JSON array with one object per entry, each
    # wrapped as {"key":...,"value":...} (or "values" for per-CPU maps). For a
    # large LRU map json.loads would build an
    # equally large list of dicts just so we can take its length. Counting the
    # per-entry "key" wrapper over the raw bytes yields the same number without
    # materializing any of it — nested per-CPU/struct objects use other field
    # names ("value"/"cpu"/struct members), never the wrapper key.
    n = out.count(b'"key":')
    if n:
        return n
    # Empty map ("[]") or an unexpected format: fall back to a real parse.
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    return len(data) if isinstance(data, list) else None


def _collect_map_usage(
    bpf_pin_dir: str,
    *,
    under_attack: bool = False,
    cache: MapUsageCache | None = None,
    now: float | None = None,
    count_interval: float = MAP_COUNT_INTERVAL,
    high_churn_interval: float = HIGH_CHURN_MAP_COUNT_INTERVAL,
    map_info_interval: float = MAP_INFO_INTERVAL,
    sample_counts: bool = True,
) -> list[MapUsage]:
    pin_dir = Path(bpf_pin_dir)
    if not pin_dir.exists():
        return [MapUsage(str(pin_dir), "-", None, None, None, "missing")]
    now = time.monotonic() if now is None else now
    cache = cache or MapUsageCache()

    try:
        tcp_ports, udp_ports = _read_xdp_ports(bpf_pin_dir)
    except Exception:
        tcp_ports, udp_ports = [], []

    if cache.map_info and now - cache.map_info_refreshed_at < map_info_interval:
        all_info = cache.map_info
    else:
        all_info = _all_map_info()
        if all_info:
            cache.map_info = all_info
            cache.map_info_refreshed_at = now
    bpftool_ok = bool(shutil.which("bpftool")) or bool(all_info)
    rows: list[MapUsage] = []

    def _sample_count(path: Path, interval: float) -> tuple[int | None, str]:
        last = cache.refreshed_at.get(path.name, 0.0)
        if path.name in cache.counts and now - last < interval:
            return cache.counts[path.name], "cached"
        count = _dump_count(path)
        if count is None:
            cached = cache.counts.get(path.name)
            return cached, "cached" if cached is not None else "live"
        cache.counts[path.name] = count
        cache.refreshed_at[path.name] = now
        return count, "sampled"

    for path in sorted(p for p in pin_dir.iterdir() if p.is_file()):
        info = all_info.get(path.name, {})
        if not bpftool_ok and not info:
            continue
        name = str(info.get("name") or path.name)
        kind = str(info.get("type") or "-")
        maximum = info.get("max_entries")
        maximum = int(maximum) if isinstance(maximum, int) else None
        current: int | None
        note = ""
        if path.name == "tcp_whitelist":
            current = len(tcp_ports)
            note = "open tcp"
        elif path.name == "udp_whitelist":
            current = len(udp_ports)
            note = "open udp"
        elif not sample_counts:
            current = cache.counts.get(path.name)
            note = "cached" if current is not None else "deferred"
        elif path.name in _HIGH_CHURN_MAPS:
            last = cache.refreshed_at.get(path.name, 0.0)
            if under_attack:
                current = cache.counts.get(path.name)
                note = "attack cached" if current is not None else "attack skip"
            elif path.name in cache.counts and now - last < high_churn_interval:
                current = cache.counts[path.name]
                note = "cached"
            else:
                current, note = _sample_count(path, high_churn_interval)
        elif kind in {"array", "percpu_array"} and maximum is not None:
            # Array maps are dense — every index always exists, so the live
            # entry count is exactly max_entries. Use the metadata instead of
            # dumping every array map on every cycle.
            current = maximum
            note = "array"
        elif kind in {"ringbuf", "prog_array"}:
            current = None
        else:
            current, note = _sample_count(path, count_interval)
        pct = (current / maximum * 100.0) if current is not None and maximum else None
        map_id_val = info.get("id")
        map_id = int(map_id_val) if isinstance(map_id_val, int) else None
        memlock_val = info.get("bytes_memlock")
        memlock = int(memlock_val) if isinstance(memlock_val, int) else None
        rows.append(MapUsage(name, kind, current, maximum, pct, note, map_id=map_id, memlock=memlock))

    def sort_key(row: MapUsage) -> tuple[float, str]:
        return (-(row.pct or -1.0), row.name)

    return sorted(rows, key=sort_key)


_service_cache: dict[tuple[int, str], str] = {}


def _safe_service(port: int, proto: str) -> str:
    key = (port, proto)
    cached = _service_cache.get(key)
    if cached is not None:
        return cached
    try:
        name = socket.getservbyport(port, proto.lower())
    except OSError:
        name = "-"
    _service_cache[key] = name
    return name


def _read_policy(path: str) -> dict[int, tuple[int, ...]]:
    if not Path(path).exists():
        return {}
    try:
        m = BpfPortPolicyMap(path)
    except OSError:
        return {}
    try:
        return m.active_structs()
    finally:
        m.close()


def _read_global_udp_rate(path: str) -> int:
    if not Path(path).exists():
        return 0
    try:
        m = BpfGlobalRlMap(path)
    except OSError:
        return 0
    try:
        return m.get()
    finally:
        m.close()


def _xdp_attach_mode(iface: str) -> str:
    try:
        result = subprocess.run(
            ["ip", "-d", "link", "show", "dev", iface],
            capture_output=True,
            text=True,
        )
    except OSError:
        return "unknown"
    if result.returncode != 0:
        return "missing"
    text = result.stdout
    if "xdpgeneric" in text:
        return "xdp generic"
    if "xdpoffload" in text:
        return "xdp offload"
    if "xdp" in text:
        return "xdp native"
    return "xdp off"


def _display_mode(mode: str) -> str:
    labels = {
        "auto": "AUTO",
        "xdp native": "XDP Native",
        "xdp generic": "XDP Generic",
        "xdp offload": "XDP Offload",
        "xdp off": "XDP Off",
        "missing": "Missing",
        "unknown": "Unknown",
    }
    if mode.startswith("nftables fallback"):
        return "nftables Fallback"
    return labels.get(mode, mode or "-")


def _mode_attr(mode: str) -> int:
    if mode in {"xdp native", "xdp offload"}:
        return curses.color_pair(_CP_GREEN)
    if mode == "xdp generic":
        return curses.color_pair(_CP_YELLOW)
    if mode.startswith("nftables fallback"):
        return curses.color_pair(_CP_RED)
    if mode == "auto":
        return curses.color_pair(_CP_CYAN)
    if mode in {"xdp off", "missing"}:
        return curses.color_pair(_CP_RED)
    return curses.A_NORMAL


def _mode_badge_attr(mode: str) -> int:
    if mode in {"xdp native", "xdp offload"}:
        return curses.color_pair(_CP_BLACK_ON_GREEN) | curses.A_BOLD
    if mode == "xdp generic":
        return curses.color_pair(_CP_BLACK_ON_YELLOW) | curses.A_BOLD
    if mode.startswith("nftables fallback"):
        return curses.color_pair(_CP_WHITE_ON_RED) | curses.A_BOLD
    if mode == "auto":
        return curses.color_pair(_CP_BLACK_ON_CYAN) | curses.A_BOLD
    if mode in {"xdp off", "missing"}:
        return curses.color_pair(_CP_WHITE_ON_RED) | curses.A_BOLD
    return curses.A_BOLD


def _limit_text(proto: str, port: int, tcp_policy: dict[int, tuple[int, ...]], udp_policy: dict[int, tuple[int, ...]], global_udp: int) -> str:
    if proto == "TCP":
        fields = tcp_policy.get(port)
        if not fields:
            return "-"
        parts = []
        if fields[0]:
            parts.append(f"syn {fields[0]}/s")
        if fields[1]:
            parts.append(f"agg {fields[1]}/s")
        return ", ".join(parts) or "-"
    fields = udp_policy.get(port)
    parts = []
    if fields:
        if fields[0]:
            parts.append(f"src {fields[0]}/s")
        if fields[1]:
            parts.append(f"agg {_human_bytes(fields[1])}/s")
    if global_udp:
        parts.append(f"global {_human_bytes(global_udp)}/s")
    return ", ".join(parts) or "-"


def _collect_port_rows(
    backend: str,
    bpf_pin_dir: str,
    nft_family: str,
    nft_table: str,
    *,
    include_processes: bool = True,
) -> list[tuple[str, int, str, str, str]]:
    tcp_ports, udp_ports = _collect_ports(backend, bpf_pin_dir, nft_family, nft_table)
    tcp_procs = _lookup_port_procs("tcp", tcp_ports) if include_processes else {}
    udp_procs = _lookup_port_procs("udp", udp_ports) if include_processes else {}
    tcp_policy = _read_policy(str(Path(bpf_pin_dir) / "tcp_port_policies"))
    udp_policy = _read_policy(str(Path(bpf_pin_dir) / "udp_port_policies"))
    global_udp = _read_global_udp_rate(str(Path(bpf_pin_dir) / "udp_global_rl"))

    rows: list[tuple[str, int, str, str, str]] = []
    for proto, ports, procs in (("TCP", tcp_ports, tcp_procs), ("UDP", udp_ports, udp_procs)):
        for port in sorted(ports):
            proc_text = ",".join(sorted(procs.get(port, set()))) or "-"
            rows.append((proto, port, _safe_service(port, proto), proc_text, _limit_text(proto, port, tcp_policy, udp_policy, global_udp)))
    return rows


def _collect_audit_rows(config_path: str) -> list[dict[str, Any]]:
    apply_toml_config(load_toml_config(config_path, strict=True))
    desired = resolve_desired_state(get_listening_ports())
    rows = []
    for decision in desired.exposure_decisions:
        endpoint = decision.endpoint
        rows.append({
            "action": decision.action,
            "address": endpoint.host_address,
            "port": endpoint.host_port,
            "protocol": endpoint.protocol,
            "bind_scope": endpoint.bind_scope,
            "zone": endpoint.ingress_zone,
            "subject": decision.subject or endpoint.subject or "unknown",
            "attribution": endpoint.attribution_state,
            "source": endpoint.attribution_source,
            "profile": decision.protection_profile or "-",
            "reason": decision.reason,
        })
    return sorted(
        rows,
        key=lambda row: (row["action"], row["protocol"], row["port"], row["address"], row["subject"]),
    )


def _audit_fingerprint(rows: list[dict[str, Any]]) -> str:
    payload = json.dumps(rows, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _audit_marker_path(args: Any) -> Path:
    return Path(args.run_state_dir) / "axdp_audit_tui.json"


def _audit_needs_review(path: Path, fingerprint: str) -> bool:
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, ValueError):
        return True
    return saved.get("fingerprint") != fingerprint


def _mark_audit_reviewed(path: Path, fingerprint: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"schema": 1, "fingerprint": fingerprint, "reviewed_at": time.time()}
    tmp = Path(f"{path}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(data, sort_keys=True) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def _initial_tui_page(args: Any) -> str:
    try:
        rows = _collect_audit_rows(args.config)
        fingerprint = _audit_fingerprint(rows)
    except Exception:
        return "audit"
    path = _audit_marker_path(args)
    needs_review = _audit_needs_review(path, fingerprint)
    if needs_review:
        try:
            _mark_audit_reviewed(path, fingerprint)
        except OSError:
            pass
        return "audit"
    return "overview"


def _rows_to_prev(rows: list[tuple[str, int, int]]) -> dict[str, tuple[int, int]]:
    return {name: (packets, bytes_) for name, packets, bytes_ in rows}


def _collect_snapshot(
    args: Any,
    prev_stats: dict[str, tuple[int, int]],
    prev_ts: float,
    map_cache: MapUsageCache | None = None,
    *,
    fast: bool = False,
) -> tuple[TuiSnapshot, dict[str, tuple[int, int]], float]:
    ifaces = (args.iface or "").split() or []
    if not ifaces:
        ifaces = [_autodetect_iface()]
    iface = ifaces[0]
    backend = _detect_backend(Path(args.bpf_pin_dir), Path(args.run_state_dir), ifaces, args.nft_family, args.nft_table)
    map_id = _read_xdp_map_id(args.bpf_pin_dir) if backend == "xdp" else "-"
    state_file = Path(args.run_state_dir) / "axdp_stats_tui.json"
    rows, map_id = _collect_stats_rows(backend, args.bpf_pin_dir, iface, args.nft_family, args.nft_table, state_file)
    now = time.monotonic()
    elapsed = max(now - prev_ts, 0.001)
    stats_rows = []
    for name, packets, bytes_ in rows:
        old_packets, old_bytes = prev_stats.get(name, (-1, -1))
        if old_packets >= 0:
            packet_delta = packets - old_packets
            byte_delta = -1 if bytes_ == -1 or old_bytes == -1 else bytes_ - old_bytes
            if packet_delta < 0:
                packet_delta = -1
            if byte_delta < 0:
                byte_delta = -1
            rate = _format_rate(packet_delta, byte_delta, elapsed)
        else:
            rate = "-"
        stats_rows.append((name, packets, bytes_, rate))
    if backend == "xdp":
        attach_targets = [(name, _xdp_attach_mode(name)) for name in ifaces]
        modes = {mode for _, mode in attach_targets}
        attach_mode = attach_targets[0][1] if len(modes) == 1 else "auto"
        attach_target = " ".join(name for name, _ in attach_targets)
    else:
        attach_mode = f"nftables fallback ({args.nft_family} {args.nft_table})"
        attach_targets = [(name, attach_mode) for name in ifaces]
        attach_target = " ".join(ifaces)

    audit_rows: list[dict[str, Any]] = []
    audit_error = ""
    try:
        audit_rows = _collect_audit_rows(args.config)
    except Exception as exc:
        audit_error = f"audit: {exc}"
    try:
        approval_rows = approvals.list_requests(approvals.store_path(args.run_state_dir))
    except Exception as exc:
        approval_rows = []
        audit_error = audit_error or f"approvals: {exc}"

    snap = TuiSnapshot(
        backend=backend,
        iface=iface,
        map_id=map_id,
        attach_mode=attach_mode,
        attach_target=attach_target,
        attach_targets=attach_targets,
        collected_at=now,
        stats=stats_rows,
        maps=_collect_map_usage(
            args.bpf_pin_dir,
            under_attack=_under_attack_enabled(args.config),
            cache=map_cache,
            sample_counts=not fast,
        ),
        ports=_collect_port_rows(
            backend,
            args.bpf_pin_dir,
            args.nft_family,
            args.nft_table,
            include_processes=not fast,
        ),
        excluded=_excluded_counts(args.config),
        under_attack=_under_attack_enabled(args.config),
        audit_rows=audit_rows,
        audit_fingerprint=_audit_fingerprint(audit_rows),
        approval_rows=approval_rows,
        audit_status=audit_error,
    )
    return snap, _rows_to_prev(rows), now


class SnapshotWorker:
    def __init__(self, args: Any) -> None:
        self._args = args
        self._interval = max(float(args.interval), 0.5)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wakeup = threading.Event()
        self._thread = threading.Thread(target=self._run, name="auto-xdp-tui-collector", daemon=True)
        self._snapshot = TuiSnapshot(status="collecting")
        self._error = ""
        self._prev_stats: dict[str, tuple[int, int]] = {}
        self._prev_ts = time.monotonic()
        self._map_cache = MapUsageCache()
        self._first_collect = True

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wakeup.set()
        self._thread.join(timeout=1.0)

    def wakeup(self) -> None:
        self._wakeup.set()

    def get(self) -> tuple[TuiSnapshot, str]:
        with self._lock:
            return self._snapshot, self._error

    def _set_result(self, snapshot: TuiSnapshot, error: str) -> None:
        with self._lock:
            self._snapshot = snapshot
            self._error = error

    def _run(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                snap, self._prev_stats, self._prev_ts = _collect_snapshot(
                    self._args,
                    self._prev_stats,
                    self._prev_ts,
                    self._map_cache,
                    fast=self._first_collect,
                )
                self._first_collect = False
                snap.status = f"updated {_dt.datetime.now().strftime('%H:%M:%S')}"
                self._set_result(snap, "")
            except Exception as exc:
                with self._lock:
                    self._error = str(exc)
            
            elapsed = time.monotonic() - started
            min_interval = 0.5
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
                elapsed = time.monotonic() - started
            
            remaining = self._interval - elapsed
            if remaining > 0:
                self._wakeup.wait(remaining)
            self._wakeup.clear()


@dataclass
class _WinSet:
    h: int
    w: int
    maps: Any
    events: Any
    summary: Any
    ports: Any


def _make_win_set(stdscr: Any) -> _WinSet | None:
    h, w = stdscr.getmaxyx()
    if h < 20 or w < 80:
        return None
    left_w = max(48, int(w * 0.56))
    right_w = w - left_w
    top_h = max(8, int((h - 1) * 0.36))
    summary_h = 8
    return _WinSet(
        h=h, w=w,
        maps=stdscr.derwin(top_h, left_w, 1, 0),
        events=stdscr.derwin(h - top_h - 1, left_w, 1 + top_h, 0),
        summary=stdscr.derwin(summary_h, right_w, 1, left_w),
        ports=stdscr.derwin(h - summary_h - 1, right_w, 1 + summary_h, left_w),
    )


def _make_full_win(stdscr: Any) -> Any | None:
    h, w = stdscr.getmaxyx()
    if h < 20 or w < 80:
        return None
    return stdscr.derwin(h - 1, w, 1, 0)


def _clip(text: str, width: int) -> str:
    if width <= 0:
        return ""
    return text[: max(0, width - 1)]


def _box(win: Any, title: str) -> None:
    h, w = win.getmaxyx()
    if h < 2 or w < 2:
        return
    win.box()
    win.addstr(0, 2, _clip(f" {title} ", max(0, w - 4)), curses.A_BOLD)


def _add(win: Any, y: int, x: int, text: str, attr: int = 0) -> None:
    h, w = win.getmaxyx()
    if 0 <= y < h and x < w:
        try:
            win.addstr(y, x, _clip(text, w - x), attr)
        except curses.error:
            pass


def _draw_maps(win: Any, rows: list[MapUsage], scroll: int, focused: bool) -> None:
    total_mem = sum(r.memlock for r in rows if r.memlock is not None)
    mem_label = f"  total {_human_bytes(total_mem)}" if total_mem else ""
    _box(win, f"BPF maps{mem_label}" + (" *" if focused else ""))
    _add(win, 1, 1, f"{'id':>7} {'map':<18} {'type':<10} {'used':>7} {'max':>7} {'%':>5} {'mem':>8}")
    visible = max(0, win.getmaxyx()[0] - 3)
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    for idx, row in enumerate(rows[scroll: scroll + visible], start=2):
        id_str = str(row.map_id) if row.map_id is not None else "-"
        used = "-" if row.current is None else str(row.current)
        maximum = "-" if row.maximum is None else str(row.maximum)
        pct = "-" if row.pct is None else f"{row.pct:5.1f}"
        mem = "-" if row.memlock is None else _human_bytes(row.memlock)
        attr = curses.A_NORMAL
        if row.pct is not None and row.pct >= 80:
            attr = curses.color_pair(_CP_RED) | curses.A_BOLD
        _add(win, idx, 1, f"{id_str:>7} {row.name:<18.18} {row.kind:<10.10} {used:>7} {maximum:>7} {pct:>5} {mem:>8}", attr)
    if len(rows) > visible:
        _add(win, win.getmaxyx()[0] - 1, 2, f"{scroll + 1}-{min(scroll + visible, len(rows))}/{len(rows)}  tab focus", curses.A_DIM)


def _draw_summary(win: Any, snap: TuiSnapshot) -> None:
    _box(win, "stats")
    _add(win, 1, 1, "Mode: ")
    _add(win, 1, 7, f"[{_display_mode(snap.attach_mode)}]", _mode_attr(snap.attach_mode))
    _add(win, 2, 1, "Attach: ")
    x = 9
    targets = snap.attach_targets or [(snap.attach_target, snap.attach_mode)]
    for idx, (target, mode) in enumerate(targets):
        if idx:
            _add(win, 2, x, " ")
            x += 1
        _add(win, 2, x, target, _mode_badge_attr(mode))
        x += len(target)
    _add(win, win.getmaxyx()[0] - 1, 2, snap.status, curses.A_DIM)
    drops = next((r for r in snap.stats if r[0] == "XDP_DROP_TOTAL"), None)
    total = next((r for r in snap.stats if r[0] == "XDP_TOTAL"), None)
    iface = next((r for r in snap.stats if r[0] == "IFACE_RX"), None)
    y = 3
    for row in (total, drops, iface):
        if row is None:
            continue
        name, packets, bytes_, rate = row
        _add(win, y, 1, f"{name:<14} {packets:<12} {_human_bytes(bytes_):<11} {rate}")
        y += 1


def _event_bottom_top(relay: RelayClient, visible: int) -> int:
    return max(relay.events_offset, relay.events_end - visible)


def _clamp_event_top(relay: RelayClient, visible: int, top: int) -> int:
    if not relay.events:
        return relay.events_offset
    return max(relay.events_offset, min(top, _event_bottom_top(relay, visible)))


def _event_window(relay: RelayClient, visible: int, top: int) -> tuple[int, int, list[dict[str, Any]]]:
    top = _clamp_event_top(relay, visible, top)
    start = max(0, top - relay.events_offset)
    events = relay.events[start:start + visible] if visible else []
    return top, start, events


def _draw_event_row(win: Any, i: int, ev: dict[str, Any]) -> None:
    ts = float(ev.get("seen_at", time.time()))
    tstr = _dt.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
    verdict = str(ev.get("verdict", "DROP"))
    attr = curses.color_pair(_CP_GREEN) if verdict == "ALLOW" else curses.color_pair(_CP_RED)
    source = f"{ev.get('src', '-')}/{ev.get('sport', '-')}"
    line = f"{tstr:<8} {verdict:<5} {str(ev.get('proto', '-')):<8.8} {source:<36.36} {str(ev.get('dport', '-')):>5} {ev.get('reason', '-')}"
    _add(win, i, 1, line, attr)


def _draw_events(
    win: Any,
    relay: RelayClient,
    snap: TuiSnapshot,
    top: int,
    focused: bool,
    dport_filter: int | None = None,
    filter_scroll: int = 0,
) -> None:
    header = f"{'time':<8} {'v':<5} {'protocol':<8} {'source':<36} {'dport':>5} reason"
    visible = max(0, win.getmaxyx()[0] - 3)

    if dport_filter is not None:
        filtered = [ev for ev in relay.events
                    if ev.get("type") != "port_change"
                    and str(ev.get("dport")) == str(dport_filter)]
        _box(win, f"events [port {dport_filter}]" + (" *" if focused else ""))
        _add(win, 1, 1, header)
        scroll = max(0, min(filter_scroll, max(0, len(filtered) - visible)))
        for i, ev in enumerate(filtered[scroll:scroll + visible], start=2):
            _draw_event_row(win, i, ev)
        count_str = f"{scroll + 1}-{min(scroll + visible, len(filtered))}/{len(filtered)}" if filtered else "0"
        _add(win, win.getmaxyx()[0] - 1, 2,
             f"{count_str}  enter:clear filter  {relay.status}", curses.A_DIM)
        return

    _box(win, "events" + (" *" if focused else ""))
    _add(win, 1, 1, header)
    # Fix: clamp top to valid range but never advance it automatically when paused.
    bottom_top = _event_bottom_top(relay, visible)
    follow = top >= bottom_top
    clamped_top = max(relay.events_offset, min(top, bottom_top))
    start = max(0, clamped_top - relay.events_offset)
    events = relay.events[start:start + visible] if visible else []
    for i, ev in enumerate(events, start=2):
        _draw_event_row(win, i, ev)
    footer = relay.status
    if visible > 0 and len(relay.events) > visible:
        oldest = start + 1
        newest = min(start + len(events), len(relay.events))
        live_tag = " [LIVE]" if follow else " [PAUSED ↑↓]"
        footer = f"{oldest}-{newest}/{len(relay.events)}{live_tag}  tab focus  {relay.status}"
    _add(win, win.getmaxyx()[0] - 1, 2, footer, curses.A_DIM)
    if snap.under_attack:
        note = "drop events suppressed (under-attack mode)"
        _add(win, win.getmaxyx()[0] - 1, win.getmaxyx()[1] - len(note) - 2, note,
             curses.color_pair(_CP_RED) | curses.A_BOLD)


def _event_bytes(ev: dict[str, Any]) -> int | None:
    for key in ("bytes", "size", "len", "pkt_len", "packet_len"):
        try:
            value = int(ev.get(key, 0))
        except (TypeError, ValueError):
            continue
        if value > 0:
            return value
    return None


def _collect_top_traffic(events: list[dict[str, Any]], limit: int = 10) -> list[TrafficRow]:
    totals: dict[tuple[str, str, str], dict[str, Any]] = {}
    for ev in events:
        if ev.get("type") == "port_change":
            continue
        ip = str(ev.get("src") or "-")
        proto = str(ev.get("proto") or "-")
        port = str(ev.get("dport") or "-")
        key = (ip, proto, port)
        row = totals.setdefault(
            key,
            {
                "packets": 0,
                "bytes": 0,
                "has_bytes": False,
                "verdict": str(ev.get("verdict") or "-"),
                "last_seen": 0.0,
            },
        )
        row["packets"] += 1
        byte_count = _event_bytes(ev)
        if byte_count is not None:
            row["bytes"] += byte_count
            row["has_bytes"] = True
        last_seen = float(ev.get("seen_at") or 0.0)
        if last_seen >= row["last_seen"]:
            row["last_seen"] = last_seen
            row["verdict"] = str(ev.get("verdict") or "-")

    rows = [
        TrafficRow(
            ip=ip,
            proto=proto,
            port=port,
            packets=int(data["packets"]),
            bytes_=int(data["bytes"]) if data["has_bytes"] else None,
            verdict=str(data["verdict"]),
            last_seen=float(data["last_seen"]),
        )
        for (ip, proto, port), data in totals.items()
    ]
    return sorted(
        rows,
        key=lambda row: (-(row.bytes_ or 0), -row.packets, row.ip, row.proto, row.port),
    )[:limit]


def _draw_drop_reasons(win: Any, relay: RelayClient, scroll: int = 0) -> None:
    rows = sorted(relay.reason_totals.items(), key=lambda x: -x[1])
    total = sum(c for _, c in rows)
    _box(win, f"drop reasons  {total} total")
    h, w = win.getmaxyx()
    bar_w = max(1, w - 48)
    _add(win, 1, 1, f"{'reason':<28} {'count':>6}  {'%':>5}   bar")
    visible = max(0, h - 3)
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    for idx, (reason, count) in enumerate(rows[scroll:scroll + visible], start=2):
        pct = count / total * 100.0 if total else 0.0
        bar = "█" * max(0, int(pct / 100.0 * bar_w))
        _add(win, idx, 1,
             f"{reason:<28} {count:>6}  {pct:>5.1f}%  {bar}",
             curses.color_pair(_CP_RED))
    if len(rows) > visible:
        _add(win, h - 1, 2, f"{scroll + 1}-{min(scroll + visible, len(rows))}/{len(rows)}  ↑↓ scroll", curses.A_DIM)


def _draw_top_traffic(win: Any, relay: RelayClient) -> None:
    _box(win, "top traffic by source ip / protocol / port")
    _add(win, 1, 1, f"{'#':>2} {'source ip':<39} {'proto':<8} {'port':>5} {'packets':>10} {'bytes':>10} {'last':<8} verdict")
    rows = _collect_top_traffic(relay.events, limit=10)
    visible = max(0, win.getmaxyx()[0] - 3)
    for idx, row in enumerate(rows[:visible], start=2):
        tstr = "-"
        if row.last_seen > 0:
            tstr = _dt.datetime.fromtimestamp(row.last_seen).strftime("%H:%M:%S")
        bytes_text = "-" if row.bytes_ is None else _human_bytes(row.bytes_)
        attr = curses.color_pair(_CP_GREEN) if row.verdict == "ALLOW" else curses.color_pair(_CP_RED)
        line = (
            f"{idx - 1:>2} {row.ip:<39.39} {row.proto:<8.8} {row.port:>5.5} "
            f"{row.packets:>10} {bytes_text:>10} {tstr:<8} {row.verdict}"
        )
        _add(win, idx, 1, line, attr)
    footer = f"{len(relay.events)} retained events  v:overview  q:quit  {relay.status}"
    _add(win, win.getmaxyx()[0] - 1, 2, footer, curses.A_DIM)


def _draw_audit_page(stdscr: Any, snap: TuiSnapshot, scroll: int, last_error: str) -> None:
    win = _make_full_win(stdscr)
    if win is None:
        _add(stdscr, 0, 0, "terminal too small; need at least 80x20")
        stdscr.refresh()
        return
    _box(win, f"authorization audit  {sum(row['action'] == 'allow' for row in snap.audit_rows)} allowed / {sum(row['action'] == 'drop' for row in snap.audit_rows)} denied")
    _add(win, 1, 1, "act  proto bind/address:port                         zone       subject              attribution reason")
    visible = max(0, win.getmaxyx()[0] - 3)
    scroll = max(0, min(scroll, max(0, len(snap.audit_rows) - visible)))
    for idx, row in enumerate(snap.audit_rows[scroll:scroll + visible], start=2):
        action = str(row["action"]).upper()
        attr = curses.color_pair(_CP_GREEN) if action == "ALLOW" else curses.color_pair(_CP_RED) | curses.A_BOLD
        endpoint = f"{row['bind_scope']}/{row['address']}:{row['port']}"
        line = (
            f"{action:<5} {str(row['protocol']).upper():<5} {endpoint:<46.46} "
            f"{row['zone']:<10.10} {row['subject']:<20.20} {row['attribution']:<10.10} {row['reason']}"
        )
        _add(win, idx, 1, line, attr)
    footer = "↑↓/PgUp/PgDn scroll  o:overview  p:approvals  v:traffic  q:quit"
    if len(snap.audit_rows) > visible:
        footer = f"{scroll + 1}-{min(scroll + visible, len(snap.audit_rows))}/{len(snap.audit_rows)}  " + footer
    _add(win, win.getmaxyx()[0] - 1, 2, footer, curses.A_DIM)
    error = last_error or snap.audit_status
    if error:
        _add(stdscr, stdscr.getmaxyx()[0] - 1, 0, _clip(error, stdscr.getmaxyx()[1]), curses.color_pair(_CP_RED) | curses.A_BOLD)
    stdscr.refresh()


def _draw_approvals_page(stdscr: Any, snap: TuiSnapshot, cursor: int, scroll: int, last_error: str) -> None:
    win = _make_full_win(stdscr)
    if win is None:
        _add(stdscr, 0, 0, "terminal too small; need at least 80x20")
        stdscr.refresh()
        return
    privileged = os.geteuid() == 0
    _box(win, f"approval workflow  {'root actions enabled' if privileged else 'read-only'}")
    _add(win, 1, 1, "id   status    proto subject              zone       ports             reason")
    visible = max(0, win.getmaxyx()[0] - 3)
    rows = snap.approval_rows
    cursor = max(0, min(cursor, len(rows) - 1)) if rows else -1
    scroll = max(0, min(scroll, max(0, len(rows) - visible)))
    if cursor >= 0:
        if cursor < scroll:
            scroll = cursor
        elif cursor >= scroll + visible:
            scroll = cursor - visible + 1
    for idx, row in enumerate(rows[scroll:scroll + visible], start=2):
        status = str(row.get("status", "-"))
        attr = curses.color_pair(_CP_YELLOW) if status == "pending" else curses.A_NORMAL
        if status in {"rejected", "revoked"}:
            attr = curses.color_pair(_CP_RED)
        row_idx = scroll + idx - 2
        if row_idx == cursor:
            attr |= curses.A_REVERSE
        ports = ",".join(str(port) for port in row.get("ports", []))
        line = f"{row['id']:>3}  {status:<8} {str(row['protocol']).upper():<5} {row['subject']:<20.20} {row['zone']:<10.10} {ports:<17.17} {row.get('reason', '-') }"
        _add(win, idx, 1, line, attr)
    footer = "↑↓ select  n:new  enter:approve  d:reject  x:revoke  a:audit  o:overview  q:quit"
    if not privileged:
        footer = "↑↓ select  root required for changes  a:audit  o:overview  q:quit"
    _add(win, win.getmaxyx()[0] - 1, 2, footer, curses.A_DIM)
    if last_error:
        _add(stdscr, stdscr.getmaxyx()[0] - 1, 0, _clip(last_error, stdscr.getmaxyx()[1]), curses.color_pair(_CP_RED) | curses.A_BOLD)
    stdscr.refresh()


def _tui_prompt(stdscr: Any, label: str) -> str:
    h, w = stdscr.getmaxyx()
    stdscr.nodelay(False)
    curses.echo()
    curses.curs_set(1)
    try:
        _add(stdscr, h - 1, 0, _clip(label, w - 1), curses.A_REVERSE)
        stdscr.refresh()
        return stdscr.getstr(h - 1, min(len(label), max(0, w - 2)), max(1, w - len(label) - 2)).decode(errors="replace").strip()
    finally:
        curses.noecho()
        curses.curs_set(0)
        stdscr.nodelay(True)


def _port_key(row: tuple[str, int, str, str, str]) -> tuple[str, int]:
    return row[0], row[1]


def _filter_port_rows(
    rows: list[tuple[str, int, str, str, str]],
    proto_filter: str,
) -> list[tuple[str, int, str, str, str]]:
    if proto_filter not in {"TCP", "UDP"}:
        return rows
    return [row for row in rows if row[0] == proto_filter]


def _port_filter_title(proto_filter: str) -> str:
    label = proto_filter if proto_filter in ("TCP", "UDP") else "all"
    return f"ports / services / limits [{label}]"


def _draw_ports(
    win: Any,
    rows: list[tuple[str, int, str, str, str]],
    port_marks: dict[tuple[str, int], tuple[str, float, tuple[str, int, str, str, str]]],
    proto_filter: str = "all",
    cursor: int = -1,
    event_dport_filter: int | None = None,
    focused: bool = False,
    excluded: tuple[int, int] = (0, 0),
) -> None:
    title = _port_filter_title(proto_filter) + (" *" if focused else "")
    _box(win, title)
    _add(win, 1, 1, f"{'p':<3} {'port':>5} {'service':<12} {'process':<16} limit")
    now = time.monotonic()
    display_rows = list(rows)
    current_keys = {_port_key(row) for row in rows}
    removed_rows = [
        marked_row
        for key, (kind, expires_at, marked_row) in port_marks.items()
        if kind == "removed" and expires_at > now and key not in current_keys
    ]
    display_rows.extend(sorted(removed_rows, key=lambda row: (row[0], row[1])))
    display_rows = _filter_port_rows(display_rows, proto_filter)

    for idx, (proto, port, svc, proc, limit) in enumerate(display_rows[: max(0, win.getmaxyx()[0] - 3)], start=2):
        mark = port_marks.get((proto, port))
        attr = curses.A_NORMAL
        if mark and mark[1] > now:
            if mark[0] == "added":
                attr = curses.color_pair(_CP_YELLOW) | curses.A_BOLD
            elif mark[0] == "removed":
                attr = curses.color_pair(_CP_RED) | curses.A_BOLD
        if idx - 2 == cursor:
            attr |= curses.A_REVERSE
        if port == event_dport_filter:
            attr |= curses.A_BOLD
        _add(win, idx, 1, f"{proto:<3} {port:>5} {svc:<12.12} {proc:<16.16} {limit}", attr)
    excl_ports, excl_cidrs = excluded
    excl_parts = []
    if excl_ports:
        excl_parts.append(f"{excl_ports} port{'s' if excl_ports != 1 else ''}")
    if excl_cidrs:
        excl_parts.append(f"{excl_cidrs} src CIDR{'s' if excl_cidrs != 1 else ''}")
    excl_hint = f"  excluded: {', '.join(excl_parts)}  (axdp exclude list)" if excl_parts else ""
    if focused:
        _add(win, win.getmaxyx()[0] - 1, 2, f"↑↓ move  enter: filter events{excl_hint}", curses.A_DIM)
    elif excl_hint:
        _add(win, win.getmaxyx()[0] - 1, 2, excl_hint.strip(), curses.A_DIM)


def _draw(
    stdscr: Any,
    snap: TuiSnapshot,
    relay: RelayClient,
    last_error: str,
    map_scroll: int,
    event_top: int,
    focus: str,
    port_marks: dict[tuple[str, int], tuple[str, float, tuple[str, int, str, str, str]]],
    wins: _WinSet | None,
    port_filter: str,
    page: str = "overview",
    reasons_scroll: int = 0,
    port_cursor: int = -1,
    event_dport_filter: int | None = None,
    event_filter_scroll: int = 0,
    audit_scroll: int = 0,
    approval_cursor: int = -1,
) -> None:
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if page == "audit":
        now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _add(stdscr, 0, 0, _clip(f"Auto XDP TUI  audit  backend={snap.backend} mode={snap.attach_mode}  {now}  a:overview p:approvals v:traffic q:quit", w), curses.A_REVERSE)
        _draw_audit_page(stdscr, snap, audit_scroll, last_error)
        return
    if page == "approvals":
        now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _add(stdscr, 0, 0, _clip(f"Auto XDP TUI  approvals  backend={snap.backend}  {now}  a:audit o:overview v:traffic q:quit", w), curses.A_REVERSE)
        _draw_approvals_page(stdscr, snap, approval_cursor, 0, last_error)
        return
    if page == "traffic":
        full_win = _make_full_win(stdscr)
        if full_win is None:
            _add(stdscr, 0, 0, "terminal too small; need at least 80x20")
            stdscr.refresh()
            return
        fh, fw = full_win.getmaxyx()
        top_h = max(8, int(fh * 0.60))
        bot_h = fh - top_h
        top_win = full_win.derwin(top_h, fw, 0, 0)
        now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        title = f"Auto XDP TUI  top traffic  backend={snap.backend} mode={snap.attach_mode}  {now}  v:overview a:audit p:approvals q:quit"
        _add(stdscr, 0, 0, _clip(title, w), curses.A_REVERSE)
        if snap.under_attack:
            badge = " UNDER ATTACK "
            _add(stdscr, 0, max(0, w - len(badge)), badge, curses.color_pair(_CP_WHITE_ON_RED) | curses.A_BOLD)
        if last_error:
            _add(stdscr, h - 1, 0, _clip(last_error, w), curses.color_pair(_CP_RED) | curses.A_BOLD)
        _draw_top_traffic(top_win, relay)
        if bot_h >= 4:
            bot_win = full_win.derwin(bot_h, fw, top_h, 0)
            _draw_drop_reasons(bot_win, relay, reasons_scroll)
            if snap.under_attack:
                note = " drop events suppressed (under-attack mode) "
                bh, bw = bot_win.getmaxyx()
                _add(bot_win, bh - 1, max(0, bw - len(note) - 2), note,
                     curses.color_pair(_CP_WHITE_ON_RED) | curses.A_BOLD)
        stdscr.refresh()
        return
    if wins is None:
        _add(stdscr, 0, 0, "terminal too small; need at least 80x20")
        stdscr.refresh()
        return
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = f"Auto XDP TUI  backend={snap.backend} mode={snap.attach_mode} map={snap.map_id} ports={port_filter}  {now}  v:traffic a:audit p:approvals tab:focus t/u:filter enter:filter-events-by-port q:quit"
    _add(stdscr, 0, 0, _clip(title, w), curses.A_REVERSE)
    if snap.under_attack:
        badge = " UNDER ATTACK "
        badge_x = max(0, w - len(badge))
        _add(stdscr, 0, badge_x, badge, curses.color_pair(_CP_WHITE_ON_RED) | curses.A_BOLD)
    if last_error:
        _add(stdscr, h - 1, 0, _clip(last_error, w), curses.color_pair(_CP_RED) | curses.A_BOLD)
    _draw_maps(wins.maps, snap.maps, map_scroll, focus == "maps")
    _draw_events(wins.events, relay, snap, event_top, focus == "events",
                 dport_filter=event_dport_filter, filter_scroll=event_filter_scroll)
    _draw_summary(wins.summary, snap)
    _draw_ports(wins.ports, snap.ports, port_marks, port_filter,
                cursor=port_cursor if focus == "ports" else -1,
                event_dport_filter=event_dport_filter,
                focused=focus == "ports",
                excluded=snap.excluded)
    stdscr.refresh()


def _curses_main(stdscr: Any, args: Any) -> int:
    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(_CP_GREEN, curses.COLOR_GREEN, -1)
    curses.init_pair(_CP_RED, curses.COLOR_RED, -1)
    curses.init_pair(_CP_YELLOW, curses.COLOR_YELLOW, -1)
    curses.init_pair(_CP_BLACK_ON_GREEN, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(_CP_BLACK_ON_YELLOW, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    curses.init_pair(_CP_WHITE_ON_RED, curses.COLOR_WHITE, curses.COLOR_RED)
    curses.init_pair(_CP_CYAN, curses.COLOR_CYAN, -1)
    curses.init_pair(_CP_BLACK_ON_CYAN, curses.COLOR_BLACK, curses.COLOR_CYAN)
    stdscr.nodelay(True)
    stdscr.timeout(200)

    relay = RelayClient(args.socket, max_events=int(args.tui_max_events))
    page = _initial_tui_page(args)
    worker = SnapshotWorker(args)
    worker.start()
    map_scroll = 0
    event_top = 0
    focus = "maps"
    last_ports_snapshot_at = 0.0
    previous_port_rows: dict[tuple[str, int], tuple[str, int, str, str, str]] | None = None
    port_marks: dict[tuple[str, int], tuple[str, float, tuple[str, int, str, str, str]]] = {}
    port_filter = "all"
    reasons_scroll = 0
    port_cursor = 0
    event_dport_filter: int | None = None
    event_filter_scroll = 0
    audit_scroll = 0
    approval_cursor = 0
    ui_error = ""
    wins: _WinSet | None = None
    last_draw_at = 0.0
    last_draw_state: tuple[Any, ...] | None = None

    def _refresh_wins() -> bool:
        nonlocal wins
        h, w = stdscr.getmaxyx()
        if wins is not None and wins.h == h and wins.w == w:
            return False
        stdscr.clear()
        wins = _make_win_set(stdscr)
        return True

    _refresh_wins()

    try:
        while True:
            ui_dirty = False
            ch = stdscr.getch()
            if ch in (ord("q"), ord("Q")):
                return 0
            if ch == curses.KEY_RESIZE:
                ui_dirty = _refresh_wins() or ui_dirty
            elif ch in (ord("t"), ord("T")):
                port_filter = "all" if port_filter == "TCP" else "TCP"
                ui_dirty = True
            elif ch in (ord("u"), ord("U")):
                port_filter = "all" if port_filter == "UDP" else "UDP"
                ui_dirty = True
            elif ch in (ord("a"), ord("A")):
                page = "audit"
                audit_scroll = 0
                ui_dirty = True
            elif ch in (ord("p"), ord("P")):
                page = "approvals"
                ui_dirty = True
            elif ch in (ord("o"), ord("O")):
                page = "overview"
                ui_dirty = True
            elif ch in (ord("v"), ord("V")):
                page = "traffic" if page != "traffic" else "overview"
                ui_dirty = True
            snap, worker_error = worker.get()
            last_error = ui_error or worker_error
            now = time.monotonic()
            before_marks = set(port_marks)
            port_marks = {
                key: mark
                for key, mark in port_marks.items()
                if mark[1] > now
            }
            if set(port_marks) != before_marks:
                ui_dirty = True
            if snap.collected_at > last_ports_snapshot_at:
                current_port_rows = {_port_key(row): row for row in snap.ports}
                if previous_port_rows is not None:
                    expires_at = now + 2.0
                    previous_keys = set(previous_port_rows)
                    current_keys = set(current_port_rows)
                    for key in current_keys - previous_keys:
                        port_marks[key] = ("added", expires_at, current_port_rows[key])
                    for key in previous_keys - current_keys:
                        port_marks[key] = ("removed", expires_at, previous_port_rows[key])
                previous_port_rows = current_port_rows
                last_ports_snapshot_at = snap.collected_at
                ui_dirty = True
            if wins is not None:
                map_visible = max(1, wins.maps.getmaxyx()[0] - 3)
                event_visible = max(1, wins.events.getmaxyx()[0] - 3)
            else:
                map_visible = 1
                event_visible = 1
            map_scroll_max = max(0, len(snap.maps) - map_visible)
            event_top = _clamp_event_top(relay, event_visible, event_top)
            if ch == 9:
                if focus == "maps":
                    focus = "events"
                elif focus == "events":
                    focus = "ports"
                else:
                    focus = "maps"
                ui_dirty = True
            display_port_rows = _filter_port_rows(snap.ports, port_filter)
            port_cursor = max(0, min(port_cursor, len(display_port_rows) - 1))
            approval_cursor = max(0, min(approval_cursor, len(snap.approval_rows) - 1)) if snap.approval_rows else -1
            if page == "approvals" and ch in (10, 13, curses.KEY_ENTER, ord("d"), ord("D"), ord("x"), ord("X"), ord("n"), ord("N")):
                if os.geteuid() != 0:
                    ui_error = "approval changes require root"
                elif ch in (ord("n"), ord("N")):
                    try:
                        target = _tui_prompt(stdscr, "new request (subject zone proto port): ")
                        subject, zone, protocol, raw_port = target.split()
                        reason = _tui_prompt(stdscr, "request reason: ")
                        approvals.create_request(
                            approvals.store_path(args.run_state_dir), args.config,
                            subject=subject, zone=zone, protocol=protocol, ports=[int(raw_port)], reason=reason, actor="tui",
                        )
                        ui_error = "created approval request"
                    except (ValueError, RuntimeError, OSError) as exc:
                        ui_error = str(exc)
                    worker.wakeup()
                    ui_dirty = True
                elif approval_cursor < 0:
                    ui_error = "no approval request selected"
                else:
                    selected = snap.approval_rows[approval_cursor]
                    request_id = int(selected["id"])
                    try:
                        if ch in (10, 13, curses.KEY_ENTER) and selected.get("status") == "pending":
                            approvals.approve_request(approvals.store_path(args.run_state_dir), args.config, request_id, actor="tui")
                            approvals.reload_daemon()
                            ui_error = f"approved request #{request_id}"
                        elif ch in (ord("d"), ord("D")) and selected.get("status") == "pending":
                            reason = _tui_prompt(stdscr, "reject reason: ")
                            approvals.reject_request(approvals.store_path(args.run_state_dir), request_id, reason=reason, actor="tui")
                            ui_error = f"rejected request #{request_id}"
                        elif ch in (ord("x"), ord("X")) and selected.get("status") == "approved":
                            approvals.revoke_request(approvals.store_path(args.run_state_dir), args.config, request_id, actor="tui")
                            approvals.reload_daemon()
                            ui_error = f"revoked request #{request_id}"
                    except (ValueError, RuntimeError, OSError) as exc:
                        ui_error = str(exc)
                    worker.wakeup()
                    ui_dirty = True
            if ch in (10, 13, curses.KEY_ENTER):
                if page == "approvals":
                    pass
                elif focus == "ports" and display_port_rows:
                    selected_port = display_port_rows[port_cursor][1]
                    if event_dport_filter == selected_port:
                        event_dport_filter = None
                    else:
                        event_dport_filter = selected_port
                        event_filter_scroll = 0
                    ui_dirty = True
                elif focus == "events" and event_dport_filter is not None:
                    event_dport_filter = None
                    ui_dirty = True
            if page == "audit":
                if ch == curses.KEY_UP:
                    audit_scroll = max(0, audit_scroll - 1)
                    ui_dirty = True
                elif ch == curses.KEY_DOWN:
                    audit_scroll += 1
                    ui_dirty = True
                elif ch == curses.KEY_PPAGE:
                    audit_scroll = max(0, audit_scroll - max(1, event_visible))
                    ui_dirty = True
                elif ch == curses.KEY_NPAGE:
                    audit_scroll += max(1, event_visible)
                    ui_dirty = True
            elif page == "approvals":
                if ch == curses.KEY_UP:
                    approval_cursor = max(0, approval_cursor - 1)
                    ui_dirty = True
                elif ch == curses.KEY_DOWN:
                    approval_cursor = min(len(snap.approval_rows) - 1, approval_cursor + 1)
                    ui_dirty = True
                elif ch == curses.KEY_PPAGE:
                    approval_cursor = max(0, approval_cursor - max(1, event_visible))
                    ui_dirty = True
                elif ch == curses.KEY_NPAGE:
                    approval_cursor = min(len(snap.approval_rows) - 1, approval_cursor + max(1, event_visible))
                    ui_dirty = True
            elif page == "traffic":
                if ch == curses.KEY_UP:
                    reasons_scroll = max(0, reasons_scroll - 1)
                    ui_dirty = True
                elif ch == curses.KEY_DOWN:
                    reasons_scroll += 1
                    ui_dirty = True
                elif ch == curses.KEY_PPAGE:
                    reasons_scroll = max(0, reasons_scroll - 5)
                    ui_dirty = True
                elif ch == curses.KEY_NPAGE:
                    reasons_scroll += 5
                    ui_dirty = True
            elif focus == "ports":
                if ch == curses.KEY_UP:
                    port_cursor = max(0, port_cursor - 1)
                    ui_dirty = True
                elif ch == curses.KEY_DOWN:
                    port_cursor = min(len(display_port_rows) - 1, port_cursor + 1)
                    ui_dirty = True
            else:
                if ch == curses.KEY_UP:
                    if focus == "events":
                        if event_dport_filter is not None:
                            event_filter_scroll = max(0, event_filter_scroll - 1)
                        else:
                            event_top = max(relay.events_offset, event_top - 1)
                    else:
                        map_scroll = max(0, map_scroll - 1)
                    ui_dirty = True
                elif ch == curses.KEY_DOWN:
                    if focus == "events":
                        if event_dport_filter is not None:
                            event_filter_scroll += 1
                        else:
                            event_top = min(_event_bottom_top(relay, event_visible), event_top + 1)
                    else:
                        map_scroll = min(map_scroll_max, map_scroll + 1)
                    ui_dirty = True
                elif ch == curses.KEY_PPAGE:
                    if focus == "events":
                        if event_dport_filter is not None:
                            event_filter_scroll = max(0, event_filter_scroll - event_visible)
                        else:
                            event_top = max(relay.events_offset, event_top - event_visible)
                    else:
                        map_scroll = max(0, map_scroll - map_visible)
                    ui_dirty = True
                elif ch == curses.KEY_NPAGE:
                    if focus == "events":
                        if event_dport_filter is not None:
                            event_filter_scroll += event_visible
                        else:
                            event_top = min(_event_bottom_top(relay, event_visible), event_top + event_visible)
                    else:
                        map_scroll = min(map_scroll_max, map_scroll + map_visible)
                    ui_dirty = True
            follow_events = event_top >= _event_bottom_top(relay, event_visible)
            relay_state_before = (relay.events_offset, relay.events_end, relay.status)
            relay.poll()
            if (relay.events_offset, relay.events_end, relay.status) != relay_state_before:
                ui_dirty = True
            if relay.ports_dirty:
                relay.ports_dirty = False
                worker.wakeup()
                ui_dirty = True
            ui_dirty = _refresh_wins() or ui_dirty
            map_scroll = min(map_scroll, max(0, len(snap.maps) - map_visible))
            if follow_events:
                event_top = _event_bottom_top(relay, event_visible)
            else:
                event_top = _clamp_event_top(relay, event_visible, event_top)
            draw_state = (
                snap.collected_at,
                last_error,
                relay.events_offset,
                relay.events_end,
                relay.status,
                map_scroll,
                event_top,
                focus,
                port_filter,
                page,
                reasons_scroll,
                port_cursor,
                event_dport_filter,
                event_filter_scroll,
                audit_scroll,
                approval_cursor,
                snap.audit_fingerprint,
                len(snap.approval_rows),
                wins.h if wins is not None else 0,
                wins.w if wins is not None else 0,
            )
            now = time.monotonic()
            if ui_dirty or draw_state != last_draw_state or now - last_draw_at >= TUI_IDLE_REDRAW_INTERVAL:
                _draw(stdscr, snap, relay, last_error, map_scroll, event_top, focus, port_marks, wins, port_filter, page, reasons_scroll, port_cursor, event_dport_filter, event_filter_scroll, audit_scroll, approval_cursor)
                last_draw_at = now
                last_draw_state = draw_state
    finally:
        worker.stop()
        relay.close()


def run_tui(args: Any) -> int:
    if os.name != "posix":
        raise RuntimeError("TUI requires a POSIX terminal")
    rb_cfg = _ringbuf_cfg(args.config)
    if not args.socket:
        args.socket = str(rb_cfg.get("socket_path", DEFAULT_SOCKET))
    args.tui_max_events = _positive_int(
        getattr(args, "tui_max_events", None) or rb_cfg.get("tui_max_events", DEFAULT_TUI_MAX_EVENTS),
        DEFAULT_TUI_MAX_EVENTS,
    )
    try:
        return curses.wrapper(_curses_main, args)
    except curses.error as exc:
        raise RuntimeError("TUI requires an interactive terminal") from exc
