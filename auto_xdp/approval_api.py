"""Local root-only HTTP API for the exposure approval workflow."""
from __future__ import annotations

import json
import os
import socket
import socketserver
import struct
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any

from auto_xdp import approvals


class _UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True

    def __init__(self, path: Path, handler: type[BaseHTTPRequestHandler], config_path: Path, store_path: Path) -> None:
        self.socket_path = path
        self.config_path = config_path
        self.approval_store = store_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not path.is_socket():
                raise RuntimeError(f"refusing to replace non-socket API path: {path}")
            path.unlink()
        super().__init__(str(path), handler)
        path.chmod(0o600)

    def server_close(self) -> None:
        super().server_close()
        try:
            self.socket_path.unlink()
        except FileNotFoundError:
            pass


def _peer_uid(connection: socket.socket) -> int | None:
    if hasattr(socket, "SO_PEERCRED"):
        try:
            raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            return uid
        except OSError:
            return None
    getpeereid = getattr(socket, "getpeereid", None)
    if getpeereid is not None:
        try:
            _uid, _gid = getpeereid(connection)
            return int(_uid)
        except OSError:
            return None
    return os.geteuid()


class ApprovalHandler(BaseHTTPRequestHandler):
    server: _UnixHTTPServer

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _authorized(self) -> bool:
        if _peer_uid(self.connection) == 0:
            return True
        self._json(HTTPStatus.FORBIDDEN, {"error": "root peer required"})
        return False

    def _json(self, status: HTTPStatus, payload: Any) -> None:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        value = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(value, dict):
            raise ValueError("JSON body must be an object")
        return value

    def do_GET(self) -> None:
        if not self._authorized():
            return
        if self.path.startswith("/v1/approvals"):
            status = "all"
            if "?status=" in self.path:
                status = self.path.split("?status=", 1)[1].split("&", 1)[0]
            self._json(HTTPStatus.OK, {"requests": approvals.list_requests(self.server.approval_store, status)})
            return
        if self.path == "/v1/audit":
            revision, history = approvals.list_history(self.server.approval_store)
            self._json(HTTPStatus.OK, {"revision": revision, "history": history})
            return
        if self.path == "/v1/grants":
            self._json(HTTPStatus.OK, {"grants": approvals.list_grants(self.server.config_path)})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authorized():
            return
        try:
            body = self._body()
            path = self.path.rstrip("/").split("/")
            if self.path == "/v1/approvals":
                request = approvals.create_request(
                    self.server.approval_store,
                    self.server.config_path,
                    subject=str(body.get("subject", "")),
                    zone=str(body.get("zone", "")),
                    protocol=str(body.get("protocol", "")),
                    ports=[int(port) for port in body.get("ports", [])],
                    reason=str(body.get("reason", "")),
                    systemd_unit=str(body.get("systemd_unit", "")),
                    process_name=str(body.get("process_name", "")),
                    container_runtime=str(body.get("container_runtime", "")),
                    container_id=str(body.get("container_id", "")),
                    container_name=str(body.get("container_name", "")),
                    container_label=body.get("container_label", ""),
                    resolve=body.get("resolve") if isinstance(body.get("resolve"), dict) else None,
                    protection_profile=str(body.get("protection_profile", "")),
                    actor="uid:0/api",
                )
                self._json(HTTPStatus.CREATED, request)
                return
            if len(path) == 5 and path[:3] == ["", "v1", "approvals"]:
                request_id = int(path[3])
                action = path[4]
                if action == "approve":
                    result = approvals.approve_request(self.server.approval_store, self.server.config_path, request_id, actor="uid:0/api")
                    approvals.reload_daemon()
                elif action == "reject":
                    result = approvals.reject_request(self.server.approval_store, request_id, reason=str(body.get("reason", "")), actor="uid:0/api")
                elif action == "revoke":
                    result = approvals.revoke_request(self.server.approval_store, self.server.config_path, request_id, actor="uid:0/api")
                    approvals.reload_daemon()
                else:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "unknown action"})
                    return
                self._json(HTTPStatus.OK, result)
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except (ValueError, RuntimeError, OSError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})


def serve(config_path: Path, store_path: Path, socket_path: Path) -> None:
    server = _UnixHTTPServer(socket_path, ApprovalHandler, config_path, store_path)
    try:
        server.serve_forever()
    finally:
        server.server_close()
