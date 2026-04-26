"""Linux Netlink Process Connector — event-driven sync trigger."""
from __future__ import annotations

import logging
import os
import select
import socket
import struct

log = logging.getLogger(__name__)

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


def open_proc_connector() -> socket.socket | None:
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_CONNECTOR)
        sock.bind((os.getpid(), _CN_IDX_PROC))
        sock.send(_make_subscribe_msg(os.getpid()))
        log.info("Netlink proc connector active -> event-driven mode.")
        return sock
    except OSError as exc:
        log.warning("Netlink unavailable (%s); live reconciliation paused until proc connector is available.", exc)
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
