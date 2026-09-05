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
import fcntl
import json
import logging
import mmap
import os
import platform
import queue
import select
import signal
import socket
import stat
import struct
import sys
import threading
import time

from auto_xdp.bpf.syscall import obj_get
from auto_xdp.config import load_toml_config
from auto_xdp.sock_state import SOCK_STATE_EVENT_SIZE, SockStateReader

# paths & defaults

TOML_CONFIG_PATH        = "/etc/auto_xdp/config.toml"
RINGBUF_PIN_PATH        = "/sys/fs/bpf/xdp_fw/pkt_ringbuf"
SOCK_STATE_RB_PIN_PATH  = "/sys/fs/bpf/xdp_fw/sock_state_rb"
SOCK_STATE_PROG_PIN_PATH = "/sys/fs/bpf/xdp_fw/sock_state_prog"
SOCK_STATE_LINK_PIN_PATH = "/sys/fs/bpf/xdp_fw/sock_state_link"
SOCK_STATE_TRACEPOINT   = "sock/inet_sock_set_state"
SOCK_STATE_RB_MAX_ENTRIES = 1 << 16   # 64 KiB — must match C definition
SOCKET_PATH        = "/var/run/auto_xdp/pkt_events.sock"
PID_FILE           = "/var/run/auto_xdp/pkt_relay.pid"
RUNTIME_DIR_MODE   = 0o750
SOCKET_MODE        = 0o660
PID_FILE_MODE      = 0o600
RINGBUF_MAX_ENTRIES = 1 << 22   # 4 MiB — must match C definition
RETENTION_SECONDS  = 300
MAX_EVENTS         = 100_000
MAX_HISTORY_SEND   = 5_000      # cap history batch sent on client connect
EVENT_QUEUE_MAX    = 20_000     # reader→broadcaster queue depth before dropping

PAGE_SIZE = mmap.PAGESIZE

# ring buffer record constants

_BUSY_BIT    = 1 << 31
_DISCARD_BIT = 1 << 30
_HDR_SZ      = 8               # u32 hdr + u32 pad

# event decoding tables

_PROTO_NAMES: dict[int, str] = {
    1:   "ICMP",
    6:   "TCP",
    17:  "UDP",
    58:  "ICMPv6",
    132: "SCTP",
}

# xdp_counter_idx values that appear as the reason field
_REASON_NAMES: dict[int, str] = {
    0:  "TCP_NEW_ALLOW",
    2:  "TCP_DROP",
    4:  "UDP_DROP",
    7:  "FRAG_DROP",
    9:  "TCP_RESERVED",
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
    28: "RESERVED_28",
    29: "SYN_AGG_RATE_DROP",
    30: "UDP_AGG_RATE_DROP",
    31: "HANDLER_BLOCK_DROP",
    32: "RESERVED_32",
    33: "RESERVED_33",
    34: "ABUSEIPDB_DROP",
}

_PKT_EVENT_SIZE = 48   # sizeof(struct pkt_event)
_AF_INET        = 2
_AF_INET6       = 10


def _secure_parent_dir(path: str) -> str:
    """Create and validate a private runtime directory for a control file."""
    parent = os.path.abspath(os.path.dirname(path) or ".")
    os.makedirs(parent, mode=RUNTIME_DIR_MODE, exist_ok=True)
    try:
        info = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError(f"cannot inspect runtime directory {parent}: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"runtime path is not a directory: {parent}")
    if info.st_uid not in (0, os.geteuid()):
        raise RuntimeError(f"runtime directory is not owned by root or the service user: {parent}")
    # Group read/execute is allowed for the dedicated operator group; writes
    # by group/other and all other-world permissions are never safe here.
    if info.st_mode & 0o022:
        raise RuntimeError(f"runtime directory is writable by group or other: {parent}")
    os.chmod(parent, RUNTIME_DIR_MODE)
    return parent


def _peer_credentials(conn: socket.socket) -> tuple[int, int, int] | None:
    """Return Linux SO_PEERCRED (pid, uid, gid), or None if unavailable."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return None
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("=3i"))
    except OSError:
        return None
    if len(raw) != struct.calcsize("=3i"):
        return None
    return struct.unpack("=3i", raw)


def _peer_groups(pid: int) -> set[int]:
    """Read supplementary groups for a peer when procfs exposes them."""
    if sys.platform != "linux":
        return set()
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as handle:
            for line in handle:
                if line.startswith("Groups:"):
                    return {int(value) for value in line.split()[1:]}
    except (OSError, ValueError):
        pass
    return set()


def _peer_is_authorized(conn: socket.socket) -> bool:
    credentials = _peer_credentials(conn)
    if credentials is None:
        return False
    pid, uid, gid = credentials
    service_uid = os.geteuid()
    service_gid = os.getegid()
    if uid == service_uid:
        return True
    if gid == service_gid:
        return True
    return service_gid in _peer_groups(pid)

# perf_event_open-based tracepoint attachment (fallback when bpftool link create
# is unavailable). Attachment lifetime is tied to the returned fds.

_PERF_EVENT_OPEN_NR: dict[str, int] = {
    "x86_64": 298, "aarch64": 241, "armv7l": 364, "i386": 336,
}
_PERF_TYPE_TRACEPOINT   = 2
_PERF_FLAG_FD_CLOEXEC   = 1 << 3
_PERF_EVENT_IOC_ENABLE  = 0x2400
_PERF_EVENT_IOC_SET_BPF = 0x40042408

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)


def _tp_id(tracepoint: str) -> int | None:
    for base in ("/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"):
        try:
            with open(f"{base}/{tracepoint}/id") as f:
                return int(f.read().strip())
        except OSError:
            continue
    return None


def attach_tracepoint(prog_pin: str, tracepoint: str) -> list[int]:
    """Attach pinned BPF prog to tracepoint on all CPUs via perf_event_open.

    Returns open perf fds — caller must keep them open for the attachment to
    remain active.
    """
    nr = _PERF_EVENT_OPEN_NR.get(platform.machine())
    if nr is None:
        return []

    tp_id = _tp_id(tracepoint)
    if tp_id is None:
        return []

    try:
        prog_fd = obj_get(prog_pin)
    except OSError:
        return []

    # perf_event_attr: 128-byte struct; only type/size/config matter here.
    attr = bytearray(128)
    struct.pack_into("<IIQ", attr, 0, _PERF_TYPE_TRACEPOINT, 128, tp_id)
    attr_c = (ctypes.c_char * 128).from_buffer(attr)

    import fcntl
    n_cpus = os.cpu_count() or 1
    perf_fds: list[int] = []
    for cpu in range(n_cpus):
        ret = _libc.syscall(
            ctypes.c_long(nr),
            ctypes.byref(attr_c),
            ctypes.c_int(-1),
            ctypes.c_int(cpu),
            ctypes.c_int(-1),
            ctypes.c_long(_PERF_FLAG_FD_CLOEXEC),
        )
        if ret < 0:
            continue
        pfd = int(ret)
        try:
            fcntl.ioctl(pfd, _PERF_EVENT_IOC_SET_BPF, prog_fd)
            fcntl.ioctl(pfd, _PERF_EVENT_IOC_ENABLE, 0)
            perf_fds.append(pfd)
        except OSError:
            os.close(pfd)

    os.close(prog_fd)
    return perf_fds


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# event decoder

_DECODE_STRUCT = struct.Struct("<Q16s16sHHBBBB")

def decode_event(raw: bytes) -> dict | None:
    if len(raw) < _PKT_EVENT_SIZE:
        return None
    ts_ns, src_raw, dst_raw, src_port, dst_port, proto, family, verdict, reason = \
        _DECODE_STRUCT.unpack_from(raw, 0)
    src_port = socket.ntohs(src_port)
    dst_port = socket.ntohs(dst_port)

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
        "verdict":   "ALLOW" if verdict == 2 else "DROP",
        "verdict_id": verdict,
        "reason":    _REASON_NAMES.get(reason, str(reason)),
        "reason_id": reason,
    }


# ring buffer reader

class RingBufReader:
    """Consumes a pinned BPF_MAP_TYPE_RINGBUF via mmap."""

    def __init__(
        self,
        pin_path: str,
        max_entries: int = RINGBUF_MAX_ENTRIES,
        event_size: int = _PKT_EVENT_SIZE,
    ) -> None:
        self._max = max_entries
        self._mask = max_entries - 1
        self._event_size = event_size
        self._fd = obj_get(pin_path)

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

    def drain(self):
        cpos = self._cpos()
        ppos = self._ppos()

        while cpos != ppos:
            off = cpos & self._mask
            (hdr,) = struct.unpack_from("<I", self._data, off)

            if hdr & _BUSY_BIT:
                break

            data_len = hdr & ~(_BUSY_BIT | _DISCARD_BIT)
            if not (hdr & _DISCARD_BIT) and data_len == self._event_size:
                yield bytes(self._data[off + _HDR_SZ: off + _HDR_SZ + data_len])

            cpos += _HDR_SZ + ((data_len + 7) & ~7)
            self._set_cpos(cpos)

    def fileno(self) -> int:
        return self._fd

    def close(self) -> None:
        self._consumer.close()
        self._producer.close()
        self._data.close()
        os.close(self._fd)


# relay server

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
        sock_state_reader: SockStateReader | None = None,
    ) -> None:
        self._rb = ringbuf
        self._ss = sock_state_reader
        self._sock_path = sock_path
        self._retention_ns = int(retention_seconds * 1e9)
        self._history: collections.deque[dict] = collections.deque(maxlen=max_events)
        self._max_history_send = max_history_send
        self._clients: dict[int, socket.socket] = {}   # fd → socket
        self._server: socket.socket | None = None
        self._running = False
        self._queue: queue.Queue[dict] = queue.Queue(maxsize=EVENT_QUEUE_MAX)

    # internal helpers

    def _open_server(self) -> None:
        _secure_parent_dir(self._sock_path)
        try:
            existing = os.lstat(self._sock_path)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode) or not stat.S_ISSOCK(existing.st_mode):
                raise RuntimeError(f"refusing to replace non-socket path: {self._sock_path}")
            if existing.st_uid not in (0, os.geteuid()):
                raise RuntimeError(f"socket is not owned by root or the service user: {self._sock_path}")
            os.unlink(self._sock_path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            srv.setblocking(False)
            srv.bind(self._sock_path)
            os.chmod(self._sock_path, SOCKET_MODE, follow_symlinks=False)
            srv.listen(32)
            self._server = srv
        except Exception:
            srv.close()
            raise
        log.info("Listening on %s", self._sock_path)

    def _trim_history(self) -> None:
        cutoff = time.time() - (self._retention_ns / 1e9)
        while self._history and self._history[0].get("seen_at", 0.0) < cutoff:
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
        if not _peer_is_authorized(conn):
            log.warning("Rejected unauthorized relay client")
            conn.close()
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
        if not self._clients:
            return
        msg = event if "type" in event else {"type": "event", **event}
        line = (json.dumps(msg, separators=(",", ":")) + "\n").encode()
        dead: list[int] = []
        for fd, conn in list(self._clients.items()):
            try:
                conn.sendall(line)
            except OSError:
                dead.append(fd)
        for fd in dead:
            self._drop_client(fd)

    # main loop

    def _reader_loop(self) -> None:
        watch_fds = [self._rb.fileno()]
        if self._ss is not None:
            watch_fds.append(self._ss.fileno())
        while self._running:
            try:
                select.select(watch_fds, [], [], 0.5)
            except (ValueError, OSError):
                break
            for raw in self._rb.drain():
                ev = decode_event(raw)
                if ev:
                    ev["seen_at"] = time.time()
                    try:
                        self._queue.put_nowait(ev)
                    except queue.Full:
                        pass
            if self._ss is not None:
                for ev in self._ss.drain():
                    try:
                        self._queue.put_nowait(ev)
                    except queue.Full:
                        pass

    def run(self) -> None:
        self._open_server()
        assert self._server is not None
        self._running = True
        log.info("pkt_relay running  retention=%.0fs", self._retention_ns / 1e9)

        reader = threading.Thread(target=self._reader_loop, name="rb-reader", daemon=True)
        reader.start()

        srv_fd = self._server.fileno()
        last_trim = time.monotonic()

        try:
            while self._running:
                rfds: list[int] = [srv_fd, *self._clients.keys()]
                try:
                    readable, _, _ = select.select(rfds, [], [], 0.05)
                except (InterruptedError, ValueError):
                    readable = []

                for rfd in readable:
                    if rfd == srv_fd:
                        self._accept_client()
                    else:
                        conn = self._clients.get(rfd)
                        if conn:
                            try:
                                data = conn.recv(256)
                            except OSError:
                                data = b""
                            if not data:
                                self._drop_client(rfd)

                while True:
                    try:
                        ev = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    self._history.append(ev)
                    self._broadcast(ev)

                now = time.monotonic()
                if now - last_trim >= 1.0:
                    self._trim_history()
                    last_trim = now
        finally:
            reader.join(timeout=2.0)
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


# PID file

def _write_pid(path: str) -> int:
    """Create and lock a PID file without following symlinks.

    The returned descriptor must remain open for the lifetime of the process;
    the advisory lock is the authoritative single-instance guard.
    """
    _secure_parent_dir(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("secure PID files require O_NOFOLLOW")
    flags = os.O_RDWR | os.O_CREAT | nofollow | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags, PID_FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fchmod(fd, PID_FILE_MODE)
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("ascii"))
        return fd
    except Exception:
        os.close(fd)
        raise


def _remove_pid(path: str, fd: int) -> None:
    try:
        if fd >= 0:
            expected = os.fstat(fd)
            try:
                actual = os.lstat(path)
            except FileNotFoundError:
                actual = None
            if (
                actual is not None
                and actual.st_dev == expected.st_dev
                and actual.st_ino == expected.st_ino
            ):
                os.unlink(path)
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
    except FileNotFoundError:
        if fd >= 0:
            os.close(fd)


# entry point

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
    ap.add_argument("--wait-for-ringbuf", action="store_true",
                    help="wait and retry until the pinned ring buffer map is available")
    ap.add_argument("--retry-interval", default=2.0, type=float, metavar="SECS",
                    help="retry interval for --wait-for-ringbuf (default: %(default)s)")
    ap.add_argument(
        "--sock-state-rb",
        default=SOCK_STATE_RB_PIN_PATH,
        metavar="PATH",
        help="pinned sock_state_rb map path (default: %(default)s)",
    )
    ap.add_argument("--debug",     action="store_true")
    args = ap.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    toml = load_toml_config(args.config)
    cfg  = toml.get("ringbuf", {})

    sock_path  = args.socket    or cfg.get("socket_path",       SOCKET_PATH)
    retention  = args.retention or cfg.get("retention_seconds", RETENTION_SECONDS)
    max_events = args.max_events or cfg.get("max_events",       MAX_EVENTS)

    while True:
        try:
            rb = RingBufReader(args.pin_path)
            break
        except OSError as exc:
            if not args.wait_for_ringbuf:
                log.error("Cannot open ring buffer %s: %s", args.pin_path, exc)
                sys.exit(1)
            log.warning(
                "Cannot open ring buffer %s: %s; retrying in %.1fs",
                args.pin_path,
                exc,
                args.retry_interval,
            )
            time.sleep(max(args.retry_interval, 0.1))

    # If sock_state_rb is pinned but no bpftool link was created, attach the
    # tracepoint ourselves so the ring buffer actually receives events.
    _perf_fds: list[int] = []
    if (
        not os.path.exists(SOCK_STATE_LINK_PIN_PATH)
        and os.path.exists(args.sock_state_rb)
        and os.path.exists(SOCK_STATE_PROG_PIN_PATH)
    ):
        _perf_fds = attach_tracepoint(SOCK_STATE_PROG_PIN_PATH, SOCK_STATE_TRACEPOINT)
        if _perf_fds:
            log.info("sock_state tracepoint attached via perf_event_open (%d CPUs).", len(_perf_fds))
        else:
            log.info("perf_event_open attachment failed; port_change events disabled.")

    ss_reader: SockStateReader | None = None
    try:
        ss_rb = RingBufReader(
            args.sock_state_rb,
            SOCK_STATE_RB_MAX_ENTRIES,
            SOCK_STATE_EVENT_SIZE,
        )
        ss_reader = SockStateReader(ss_rb)
        log.info("sock_state_rb opened; port_change events enabled.")
    except (OSError, FileNotFoundError):
        log.info("sock_state_rb not found; port_change events disabled.")

    max_history_send = cfg.get("max_history_send", MAX_HISTORY_SEND)

    relay = RelayServer(
        rb,
        sock_path=sock_path,
        retention_seconds=float(retention),
        max_events=int(max_events),
        max_history_send=int(max_history_send),
        sock_state_reader=ss_reader,
    )

    def _on_signal(signum: int, _frame: object) -> None:
        log.info("received signal %d, shutting down", signum)
        relay.stop()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT,  _on_signal)

    pid_fd = -1
    try:
        pid_fd = _write_pid(args.pid_file)
        relay.run()
    finally:
        _remove_pid(args.pid_file, pid_fd)
        rb.close()
        for _pfd in _perf_fds:
            try:
                os.close(_pfd)
            except OSError:
                pass


if __name__ == "__main__":
    main()
