"""Root-owned exposure approval workflow and management API primitives."""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


APPROVAL_SCHEMA = 1
_SUBJECT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_PROTOCOLS = {"tcp", "udp", "sctp"}
_STATUSES = {"pending", "approved", "rejected", "revoked"}


def store_path(run_state_dir: str | Path) -> Path:
    return Path(run_state_dir) / "approval_requests.json"


def _empty_state() -> dict[str, Any]:
    return {"schema": APPROVAL_SCHEMA, "revision": 0, "next_id": 1, "requests": [], "history": []}


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_state()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"cannot read approval store {path}: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema") != APPROVAL_SCHEMA:
        raise RuntimeError(f"unsupported approval store schema: {path}")
    data.setdefault("requests", [])
    data.setdefault("history", [])
    data.setdefault("revision", 0)
    data.setdefault("next_id", 1)
    return data


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, encoding="utf-8", delete=False) as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
        tmp_path = Path(fh.name)
    tmp_path.chmod(0o600)
    tmp_path.replace(path)
    path.chmod(0o600)


@contextmanager
def _locked(path: Path) -> Iterator[dict[str, Any]]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = Path(f"{path}.lock")
    lock_path.touch(mode=0o600, exist_ok=True)
    lock_path.chmod(0o600)
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield _load(path)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _actor(value: str | None) -> str:
    return value or f"uid:{os.getuid()}"


def _ports(values: list[int]) -> list[int]:
    result = sorted({int(value) for value in values})
    if not result or any(port < 1 or port > 65535 for port in result):
        raise ValueError("ports must contain values from 1 to 65535")
    return result


def _validate_request(data: dict[str, Any], *, config: dict[str, Any]) -> None:
    subject = str(data.get("subject", ""))
    if not _SUBJECT_RE.fullmatch(subject):
        raise ValueError("subject must contain only letters, digits, _, ., or -")
    zone = str(data.get("zone", ""))
    zones = config.get("zones", {})
    if zone != "public" and zone not in zones:
        raise ValueError(f"unknown ingress zone: {zone}")
    protocol = str(data.get("protocol", "")).lower()
    if protocol not in _PROTOCOLS:
        raise ValueError(f"unsupported protocol: {protocol}")
    data["protocol"] = protocol
    data["ports"] = _ports([int(value) for value in data.get("ports", [])])
    resolution = data.get("resolve", {})
    if not isinstance(resolution, dict):
        raise ValueError("resolve must be an object")
    allowed = {
        "systemd_unit", "process_name", "container_runtime", "container_id",
        "container_name", "container_label",
    }
    if set(resolution) - allowed:
        raise ValueError("resolve contains an unsupported identity field")
    identity_keys = {"systemd_unit", "process_name", "container_id", "container_name", "container_label"}
    if len([key for key in identity_keys if resolution.get(key)]) > 1:
        raise ValueError("resolve may contain only one identity")
    runtime = str(resolution.get("container_runtime", "")).strip().lower()
    if runtime and runtime not in {"docker", "podman"}:
        raise ValueError("container_runtime must be docker or podman")
    if runtime and not any(resolution.get(key) for key in identity_keys & {"container_id", "container_name", "container_label"}):
        raise ValueError("container_runtime requires a container identity")
    if "container_label" in resolution and not isinstance(resolution["container_label"], (str, dict)):
        raise ValueError("container_label must be a string or object")
    existing = config.get("subjects", {}).get(subject, {})
    if not isinstance(existing, dict):
        existing = {}
    if not resolution and not isinstance(existing.get("resolve"), dict):
        raise ValueError("new subjects require --systemd-unit or --process-name")
    profile = str(data.get("protection_profile", "")).strip()
    if len(profile) > 128:
        raise ValueError("protection profile is too long")
    data["protection_profile"] = profile


def _history(data: dict[str, Any], request: dict[str, Any], action: str, actor: str) -> None:
    data["history"].append(
        {
            "revision": data["revision"],
            "request_id": request["id"],
            "action": action,
            "actor": actor,
            "at": time.time(),
            "status": request["status"],
        }
    )


def _request(data: dict[str, Any], request_id: int) -> dict[str, Any]:
    for request in data["requests"]:
        if int(request.get("id", -1)) == request_id:
            return request
    raise ValueError(f"approval request not found: {request_id}")


def create_request(
    path: Path,
    config_path: str | Path,
    *,
    subject: str,
    zone: str,
    protocol: str,
    ports: list[int],
    reason: str,
    systemd_unit: str = "",
    process_name: str = "",
    container_runtime: str = "",
    container_id: str = "",
    container_name: str = "",
    container_label: str | dict[str, str] = "",
    resolve: dict[str, Any] | None = None,
    protection_profile: str = "",
    actor: str | None = None,
) -> dict[str, Any]:
    if not reason.strip():
        raise ValueError("approval reason is required")
    from auto_xdp.admin_cli import _load_toml

    config = _load_toml(Path(config_path))
    request: dict[str, Any] = {
        "subject": subject,
        "zone": zone,
        "protocol": protocol,
        "ports": ports,
        "reason": reason.strip(),
        "resolve": {key: value for key, value in {
            "systemd_unit": systemd_unit.strip(),
            "process_name": process_name.strip(),
            "container_runtime": container_runtime.strip(),
            "container_id": container_id.strip().lower(),
            "container_name": container_name.strip(),
            "container_label": container_label,
        }.items() if value},
        "protection_profile": protection_profile.strip(),
    }
    if resolve is not None:
        request["resolve"] = dict(resolve)
    _validate_request(request, config=config)
    request["requester"] = _actor(actor)
    request["requested_at"] = time.time()
    request["status"] = "pending"
    with _locked(path) as state:
        for existing in state["requests"]:
            if existing.get("status") == "pending" and all(
                existing.get(key) == request.get(key)
                for key in ("subject", "zone", "protocol", "ports")
            ):
                raise ValueError(f"matching approval request already pending: {existing['id']}")
        request["id"] = int(state["next_id"])
        state["next_id"] = request["id"] + 1
        state["revision"] = int(state["revision"]) + 1
        state["requests"].append(request)
        _history(state, request, "request", request["requester"])
        _save(path, state)
    return request


def list_requests(path: Path, status: str = "all") -> list[dict[str, Any]]:
    if status != "all" and status not in _STATUSES:
        raise ValueError(f"unsupported approval status: {status}")
    with _locked(path) as state:
        requests = [dict(item) for item in state["requests"]]
    if status != "all":
        requests = [item for item in requests if item.get("status") == status]
    return sorted(requests, key=lambda item: int(item["id"]))


def list_history(path: Path) -> tuple[int, list[dict[str, Any]]]:
    with _locked(path) as state:
        return int(state["revision"]), [dict(item) for item in state["history"]]


def list_grants(config_path: str | Path) -> list[dict[str, Any]]:
    from auto_xdp.admin_cli import _load_toml

    config = _load_toml(Path(config_path))
    rows: list[dict[str, Any]] = []
    for subject, spec in sorted(config.get("subjects", {}).items()):
        if not isinstance(spec, dict):
            continue
        resolve = spec.get("resolve", {})
        protection = spec.get("protection", {})
        profile = str(protection.get("profile", "")) if isinstance(protection, dict) else ""
        for zone, zone_spec in (spec.get("exposure", {}) or {}).items():
            if not isinstance(zone_spec, dict):
                continue
            for protocol in sorted(_PROTOCOLS):
                proto_spec = zone_spec.get(protocol, {})
                if not isinstance(proto_spec, dict) or not proto_spec.get("ports"):
                    continue
                rows.append({
                    "subject": subject,
                    "zone": str(zone),
                    "protocol": protocol,
                    "ports": sorted({int(port) for port in proto_spec["ports"]}),
                    "resolve": dict(resolve) if isinstance(resolve, dict) else {},
                    "protection_profile": profile,
                })
    return rows


def _apply_grant(config: dict[str, Any], request: dict[str, Any]) -> list[int]:
    subjects = config.setdefault("subjects", {})
    subject = subjects.setdefault(request["subject"], {})
    if not isinstance(subject, dict):
        raise ValueError(f"subjects.{request['subject']} must be a table")
    requested_resolve = request.get("resolve", {})
    existing_resolve = subject.get("resolve", {})
    if requested_resolve:
        if existing_resolve and existing_resolve != requested_resolve:
            raise ValueError("approval identity conflicts with the existing subject resolver")
        subject.setdefault("resolve", requested_resolve)
    exposure = subject.setdefault("exposure", {})
    zone = exposure.setdefault(request["zone"], {})
    protocol = zone.setdefault(request["protocol"], {})
    current = {int(port) for port in protocol.get("ports", [])}
    added = sorted(set(request["ports"]) - current)
    protocol["ports"] = sorted(current | set(request["ports"]))
    profile = str(request.get("protection_profile", ""))
    if profile:
        protection = subject.setdefault("protection", {})
        existing_profile = str(protection.get("profile", ""))
        if existing_profile and existing_profile != profile:
            raise ValueError("approval protection profile conflicts with the existing subject")
        protection["profile"] = profile
    return added


def approve_request(path: Path, config_path: str | Path, request_id: int, *, actor: str | None = None) -> dict[str, Any]:
    from auto_xdp.admin_cli import _load_toml, _write_toml

    with _locked(path) as state:
        request = _request(state, request_id)
        if request.get("status") != "pending":
            raise ValueError(f"approval request {request_id} is {request.get('status')}")
        config_path = Path(config_path)
        config = _load_toml(config_path)
        _validate_request(dict(request), config=config)
        added = _apply_grant(config, request)
        _write_toml(config_path, config)
        request.update({
            "status": "approved",
            "approver": _actor(actor),
            "approved_at": time.time(),
            "applied_ports": added,
        })
        state["revision"] = int(state["revision"]) + 1
        _history(state, request, "approve", request["approver"])
        _save(path, state)
        result = dict(request)
    return result


def reject_request(path: Path, request_id: int, *, reason: str, actor: str | None = None) -> dict[str, Any]:
    if not reason.strip():
        raise ValueError("rejection reason is required")
    with _locked(path) as state:
        request = _request(state, request_id)
        if request.get("status") != "pending":
            raise ValueError(f"approval request {request_id} is {request.get('status')}")
        request.update({"status": "rejected", "rejector": _actor(actor), "rejected_at": time.time(), "rejection_reason": reason.strip()})
        state["revision"] = int(state["revision"]) + 1
        _history(state, request, "reject", request["rejector"])
        _save(path, state)
        return dict(request)


def revoke_request(path: Path, config_path: str | Path, request_id: int, *, actor: str | None = None) -> dict[str, Any]:
    from auto_xdp.admin_cli import _load_toml, _write_toml

    with _locked(path) as state:
        request = _request(state, request_id)
        if request.get("status") != "approved":
            raise ValueError(f"approval request {request_id} is {request.get('status')}")
        config_path = Path(config_path)
        config = _load_toml(config_path)
        protocol_spec = (
            config.get("subjects", {})
            .get(request["subject"], {})
            .get("exposure", {})
            .get(request["zone"], {})
            .get(request["protocol"], {})
        )
        if isinstance(protocol_spec, dict):
            keep = set(int(port) for port in protocol_spec.get("ports", [])) - set(request.get("applied_ports", []))
            protocol_spec["ports"] = sorted(keep)
            _write_toml(config_path, config)
        request.update({"status": "revoked", "revoker": _actor(actor), "revoked_at": time.time()})
        state["revision"] = int(state["revision"]) + 1
        _history(state, request, "revoke", request["revoker"])
        _save(path, state)
        return dict(request)


def reload_daemon() -> None:
    """Best-effort SIGHUP after a policy write; absent daemons are allowed."""
    try:
        result = subprocess.run(
            ["systemctl", "show", "-p", "MainPID", "--value", "xdp-port-sync"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        pid = int(result.stdout.strip() or "0")
        if pid > 1:
            os.kill(pid, 1)
            return
    except (FileNotFoundError, OSError, ValueError, subprocess.SubprocessError):
        pass


def run_api(config_path: str | Path, run_state_dir: str | Path, socket_path: str | Path) -> int:
    if os.geteuid() != 0:
        raise PermissionError("approval API requires root")
    from auto_xdp.approval_api import serve

    serve(Path(config_path), store_path(run_state_dir), Path(socket_path))
    return 0
