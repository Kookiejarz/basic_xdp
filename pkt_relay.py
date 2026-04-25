#!/usr/bin/env python3
"""BPF ring buffer relay daemon for auto_xdp DROP events.

Consumes pkt_ringbuf, maintains a configurable retention window,
and fans out to Textual TUI clients via a Unix domain socket.

Protocol: line-delimited JSON.
  On connect: {"type":"history","events":[...]}  (up to max_history_on_connect)
  Live:       {"type":"event",...}
"""
from __future__ import annotations

import argparse
import collections
import ctypes
import ctypes.util
import json
import logging
import mmap
import os
import platform
import select
import signal
import socket
import struct
import sys
import time

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

# ── paths & defaults ────────────────────────────────────────────────────────

TOML_CONFIG_PATH   = "/etc/auto_xdp/config.toml"
RINGBUF_PIN_PATH   = "/sys/fs/bpf/xdp_fw/pkt_ringbuf"
SOCKET_PATH        = "/var/run/auto_xdp/pkt_events.sock"
PID_FILE           = "/var/run/auto_xdp/pkt_relay.pid"
RINGBUF_MAX_ENTRIES = 1 << 22   # 4 MiB — must match C definition
RETENTION_SECONDS  = 300
MAX_EVENTS         = 100_000
MAX_HISTORY_SEND   = 5_000      # cap history batch sent on client connect

PAGE_SIZE = mmap.PAGESIZE

# ── ring buffer record constants ─────────────────────────────────────────────

_BUSY_BIT    = 1 << 31
_DISCARD_BIT = 1 << 30
_HDR_SZ      = 8               # u32 hdr + u32 pad

# ── event decoding tables ────────────────────────────────────────────────────

_PROTO_NAMES: dict[int, str] = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    58:  "ICMPv6",
    132: "SCTP",
}

# xdp_counter_idx values that appear as the reason field
_REASON_NAMES: dict[int, str] = {
    2:  "TCP_DROP",
    4:  "UDP_DROP",
    7:  "FRAG_DROP",
    9:  "TCP_CT_MISS",
    10: "ICMP_DROP",
    11: "SYN_RATE_DROP",
    12: "UDP_RATE_DROP",
    13: "UDP_GLOBAL_RATE_DROP",
    14: "TCP_MALFORM_NULL",
    15: "TCP_MALFORM_XMAS",
    16: "TCP_MALFORM_SYN_FIN",
    17: "TCP_MALFORM_SYN_RST",
    18: "TCP_MALFORM_RST_FIN",
    19: "TCP_MALFORM_DOFF",
    20: "TCP_MALFORM_PORT0",
    21: "VLAN_DROP",
    24: "SLOT_DROP",
    25: "UDP_MALFORM_PORT0",
    26: "UDP_MALFORM_LEN",
    27: "BOGON_DROP",
}

_PKT_EVENT_SIZE = 48   # sizeof(struct pkt_event)
_AF_INET        = 2
_AF_INET6       = 10

# ── BPF syscall helpers (mirrors xdp_port_sync.py) ───────────────────────────

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
_NR_BPF: int = {
    "x86_64":  321,
    "aarch64": 280,
    "armv7l":  386,
    "armv6l":  386,
}.get(platform.machine(), 321)

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


# ── logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── config ───────────────────────────────────────────────────────────────────

def _load_toml(path: str) -> dict:
    if tomllib is None:
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        log.warning("Failed to load %s: %s", path, exc)
        return {}


def _ringbuf_cfg(toml: dict) -> dict:
    return toml.get("ringbuf", {})


# ── event decoder ────────────────────────────────────────────────────────────

def decode_event(raw: bytes) -> dict | None:
    """Decode a 48-byte pkt_event struct into a JSON-serialisable dict."""
    if len(raw) < _PKT_EVENT_SIZE:
        return None
    ts_ns = struct.unpack_from("<Q", raw, 0)[0]
    src_raw = raw[8:24]
    dst_raw = raw[24:40]
    src_port = struct.unpack_from(">H", raw, 40)[0]
    dst_port = struct.unpack_from(">H", raw, 42)[0]
    proto, family, _verdict, reason = struct.unpack_from("BBBB", raw, 44)

    if family == _AF_INET:
        src_ip = socket.inet_ntoa(src_raw[0:4])
        dst_ip = socket.inet_ntoa(dst_raw[0:4])
        ip_ver = 4
    else:
        try:
            src_ip = socket.inet_ntop(socket.AF_INET6, bytes(src_raw))
            dst_ip = socket.inet_ntop(socket.AF_INET6, bytes(dst_raw))
        except Exception:
            src_ip = src_raw.hex()
            dst_ip = dst_raw.hex()
        ip_ver = 6

    return {
        "ts_ns":     ts_ns,
        "src":       src_ip,
        "dst":       dst_ip,
        "sport":     src_port,
        "dport":     dst_port,
        "proto":     _PROTO_NAMES.get(proto, str(proto)),
        "family":    ip_ver,
        "reason":    _REASON_NAMES.get(reason, str(reason)),
        "reason_id": reason,
    }


# ── ring buffer reader ────────────────────────────────────────────────────────

class RingBufReader:
    """Consumes a pinned BPF_MAP_TYPE_RINGBUF via mmap."""

    def __init__(self, pin_path: str, max_entries: int = RINGBUF_MAX_ENTRIES) -> None:
        self._max = max_entries
        self._mask = max_entries - 1
        self._fd = _obj_get(pin_path)

        # Consumer page: read+write — we store the consumer position here.
        self._consumer = mmap.mmap(
            self._fd, PAGE_SIZE, access=mmap.ACCESS_WRITE, offset=0
        )
        # Producer page: read-only — kernel updates producer position here.
        self._producer = mmap.mmap(
            self._fd, PAGE_SIZE, access=mmap.ACCESS_READ, offset=PAGE_SIZE
        )
        # Data area: double-mapped (2 × max_entries) so wraparound is transparent.
        self._data = mmap.mmap(
            self._fd, 2 * max_entries, access=mmap.ACCESS_READ, offset=2 * PAGE_SIZE
        )

    def _cpos(self) -> int:
        return struct.unpack_from("<Q", self._consumer, 0)[0]

    def _ppos(self) -> int:
        return struct.unpack_from("<Q", self._producer, 0)[0]

    def _set_cpos(self, pos: int) -> None:
        struct.pack_into("<Q", self._consumer, 0, pos)

    def drain(self) -> list[bytes]:
        """Return raw payloads for all available non-discarded records."""
        records: list[bytes] = []
        cpos = self._cpos()
        ppos = self._ppos()

        while cpos != ppos:
            off = cpos & self._mask
            (hdr,) = struct.unpack_from("<I", self._data, off)

            if hdr & _BUSY_BIT:
                break   # producer still writing this record

            data_len = hdr & ~(_BUSY_BIT | _DISCARD_BIT)
            if not (hdr & _DISCARD_BIT) and data_len == _PKT_EVENT_SIZE:
                records.append(bytes(self._data[off + _HDR_SZ: off + _HDR_SZ + data_len]))

            cpos += _HDR_SZ + ((data_len + 7) & ~7)
            self._set_cpos(cpos)

        return records

    def fileno(self) -> int:
        return self._fd

    def close(self) -> None:
        self._consumer.close()
        self._producer.close()
        self._data.close()
        os.close(self._fd)


# ── relay server ──────────────────────────────────────────────────────────────

class RelayServer:
    """Accepts Unix socket clients and streams DROP events to them."""

    def __init__(
        self,
        ringbuf: RingBufReader,
        *,
        sock_path: str = SOCKET_PATH,
        retention_seconds: float = RETENTION_SECONDS,
        max_events: int = MAX_EVENTS,
        max_history_send: int = MAX_HISTORY_SEND,
    ) -> None:
        self._rb = ringbuf
        self._sock_path = sock_path
        self._retention_ns = int(retention_seconds * 1e9)
        self._history: collections.deque[dict] = collections.deque(maxlen=max_events)
        self._max_history_send = max_history_send
        self._clients: dict[int, socket.socket] = {}   # fd → socket
        self._server: socket.socket | None = None
        self._running = False

    # ── internal helpers ──────────────────────────────────────────────────

    def _open_server(self) -> None:
        os.makedirs(os.path.dirname(self._sock_path) or ".", exist_ok=True)
        try:
            os.unlink(self._sock_path)
        except FileNotFoundError:
            pass
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.setblocking(False)
        srv.bind(self._sock_path)
        srv.listen(32)
        self._server = srv
        log.info("Listening on %s", self._sock_path)

    def _trim_history(self) -> None:
        cutoff = time.time_ns() - self._retention_ns
        while self._history and self._history[0]["ts_ns"] < cutoff:
            self._history.popleft()

    def _send_line(self, sock: socket.socket, obj: object) -> bool:
        try:
            sock.sendall((json.dumps(obj, separators=(",", ":")) + "\n").encode())
            return True
        except OSError:
            return False

    def _accept_client(self) -> None:
        assert self._server is not None
        try:
            conn, _ = self._server.accept()
        except OSError:
            return
        conn.setblocking(False)
        self._trim_history()
        history_slice = list(self._history)[-self._max_history_send:]
        if not self._send_line(conn, {"type": "history", "events": history_slice}):
            conn.close()
            return
        fd = conn.fileno()
        self._clients[fd] = conn
        log.debug("client connected fd=%d total=%d", fd, len(self._clients))

    def _drop_client(self, fd: int) -> None:
        conn = self._clients.pop(fd, None)
        if conn:
            try:
                conn.close()
            except OSError:
                pass
            log.debug("client disconnected fd=%d total=%d", fd, len(self._clients))

    def _broadcast(self, event: dict) -> None:
        msg = {"type": "event", **event}
        dead: list[int] = []
        for fd, conn in list(self._clients.items()):
            if not self._send_line(conn, msg):
                dead.append(fd)
        for fd in dead:
            self._drop_client(fd)

    # ── main loop ─────────────────────────────────────────────────────────

    def run(self) -> None:
        self._open_server()
        assert self._server is not None
        self._running = True
        log.info("pkt_relay running  retention=%.0fs", self._retention_ns / 1e9)

        try:
            while self._running:
                rfds: list[int] = [
                    self._rb.fileno(),
                    self._server.fileno(),
                    *self._clients.keys(),
                ]
                try:
                    readable, _, _ = select.select(rfds, [], [], 1.0)
                except (InterruptedError, ValueError):
                    continue

                srv_fd = self._server.fileno()
                rb_fd  = self._rb.fileno()

                for rfd in readable:
                    if rfd == srv_fd:
                        self._accept_client()
                    elif rfd == rb_fd:
                        for raw in self._rb.drain():
                            ev = decode_event(raw)
                            if ev:
                                self._history.append(ev)
                                self._broadcast(ev)
                    elif rfd in self._clients:
                        conn = self._clients[rfd]
                        try:
                            data = conn.recv(256)
                        except OSError:
                            data = b""
                        if not data:
                            self._drop_client(rfd)
        finally:
            self._cleanup()

    def stop(self) -> None:
        self._running = False

    def _cleanup(self) -> None:
        for conn in list(self._clients.values()):
            try:
                conn.close()
            except OSError:
                pass
        self._clients.clear()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        try:
            os.unlink(self._sock_path)
        except FileNotFoundError:
            pass
        log.info("pkt_relay stopped")


# ── PID file ─────────────────────────────────────────────────────────────────

def _write_pid(path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write(f"{os.getpid()}\n")


def _remove_pid(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="BPF ring buffer relay — streams DROP events to TUI clients",
    )
    ap.add_argument("--config",    default=TOML_CONFIG_PATH, metavar="PATH",
                    help="TOML config file (default: %(default)s)")
    ap.add_argument("--pin-path",  default=RINGBUF_PIN_PATH, metavar="PATH",
                    help="pinned pkt_ringbuf map (default: %(default)s)")
    ap.add_argument("--socket",    default=None, metavar="PATH",
                    help="Unix socket path (overrides config)")
    ap.add_argument("--retention", default=None, type=float, metavar="SECS",
                    help="event retention window in seconds (overrides config)")
    ap.add_argument("--max-events", default=None, type=int, metavar="N",
                    help="in-memory event cap (overrides config)")
    ap.add_argument("--pid-file",  default=PID_FILE, metavar="PATH")
    ap.add_argument("--debug",     action="store_true")
    args = ap.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    toml = _load_toml(args.config)
    cfg  = _ringbuf_cfg(toml)

    sock_path  = args.socket    or cfg.get("socket_path",       SOCKET_PATH)
    retention  = args.retention or cfg.get("retention_seconds", RETENTION_SECONDS)
    max_events = args.max_events or cfg.get("max_events",       MAX_EVENTS)

    try:
        rb = RingBufReader(args.pin_path)
    except OSError as exc:
        log.error("Cannot open ring buffer %s: %s", args.pin_path, exc)
        sys.exit(1)

    relay = RelayServer(
        rb,
        sock_path=sock_path,
        retention_seconds=float(retention),
        max_events=int(max_events),
    )

    _write_pid(args.pid_file)

    def _on_signal(signum: int, _frame: object) -> None:
        log.info("received signal %d, shutting down", signum)
        relay.stop()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT,  _on_signal)

    try:
        relay.run()
    finally:
        rb.close()
        _remove_pid(args.pid_file)


if __name__ == "__main__":
    main()
