"""Persistent install/runtime state and host-interface selection.

The installer and runtime launcher share this module so backend decisions do
not grow separate interpretations of the same machine.  Persistent state is
written atomically; /run remains reserved for locks and in-flight markers.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


STATE_SCHEMA = 1
_CONTAINER_NAMES = (
    "docker",
    "veth",
    "virbr",
    "cni",
    "flannel",
    "cali",
    "kube-ipvs",
    "podman",
)
_VIRTUAL_KINDS = {"veth", "dummy", "ifb"}


def _link_kind(link: dict[str, Any]) -> str:
    linkinfo = link.get("linkinfo")
    if isinstance(linkinfo, dict):
        kind = linkinfo.get("info_kind")
        if isinstance(kind, str):
            return kind.lower()
    kind = link.get("link_type")
    return kind.lower() if isinstance(kind, str) else ""


def exclusion_reason(link: dict[str, Any]) -> str | None:
    """Return why an interface is unsafe for automatic host attachment."""
    name = str(link.get("ifname", ""))
    lowered = name.lower()
    flags = {str(flag).upper() for flag in link.get("flags", []) if flag}
    kind = _link_kind(link)

    if name == "lo" or "LOOPBACK" in flags or kind == "loopback":
        return "loopback"
    if kind in _VIRTUAL_KINDS:
        return f"virtual {kind}"
    if re.fullmatch(r"br-[0-9a-f]{12,}", lowered):
        return "container bridge"
    if lowered.startswith(_CONTAINER_NAMES):
        return "container interface"
    return None


def select_interfaces(
    links: Iterable[dict[str, Any]],
    *,
    explicit: Iterable[str] = (),
    allow_container: bool = False,
    excluded_names: Iterable[str] = (),
) -> tuple[list[str], dict[str, str]]:
    """Select UP host interfaces while retaining observable exclusions.

    Explicit names may opt into container/virtual links, but loopback is never
    attachable.  Automatic selection excludes container plumbing by both link
    kind and conventional names; bridges/bonds/VLANs are otherwise retained
    because they can legitimately be a host's public ingress interface.
    """
    rows = {str(link.get("ifname", "")): link for link in links if link.get("ifname")}
    requested = list(dict.fromkeys(str(item) for item in explicit if item))
    excluded: dict[str, str] = {}
    configured_excludes = {str(item) for item in excluded_names if item}

    if requested:
        selected: list[str] = []
        for name in requested:
            if name in configured_excludes:
                raise ValueError(f"Interface '{name}' is present in both include and exclude.")
            link = rows.get(name)
            if link is None:
                raise ValueError(f"Interface '{name}' does not exist.")
            reason = exclusion_reason(link)
            if reason == "loopback":
                raise ValueError("Loopback interface 'lo' cannot run Auto XDP.")
            if reason and not allow_container:
                raise ValueError(
                    f"Interface '{name}' is classified as {reason}; "
                    "set interfaces.allow_container=true to opt in explicitly."
                )
            selected.append(name)
        return selected, excluded

    selected = []
    for name, link in rows.items():
        if name in configured_excludes:
            excluded[name] = "configured exclusion"
            continue
        reason = exclusion_reason(link)
        flags = {str(flag).upper() for flag in link.get("flags", []) if flag}
        operstate = str(link.get("operstate", "")).upper()
        if reason:
            excluded[name] = reason
            continue
        if "UP" not in flags and operstate not in {"UP", "UNKNOWN"}:
            excluded[name] = "interface down"
            continue
        selected.append(name)
    return sorted(selected), dict(sorted(excluded.items()))


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def atomic_write_json(path: Path, value: dict[str, Any], mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def atomic_symlink(target: str, link: Path) -> None:
    """Install or replace a symlink atomically."""
    link.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{link.name}.link.", dir=link.parent)
    os.close(fd)
    tmp = Path(raw_tmp)
    tmp.unlink()
    os.symlink(target, tmp)
    try:
        os.replace(tmp, link)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def merge_machine_state(
    previous: dict[str, Any],
    selected: Iterable[str],
    excluded: dict[str, str],
    *,
    selection: str,
    default_xdp_mode: str = "auto",
) -> dict[str, Any]:
    old_interfaces = previous.get("interfaces", {})
    if not isinstance(old_interfaces, dict):
        old_interfaces = {}
    interfaces: dict[str, dict[str, Any]] = {}
    for name in selected:
        old = old_interfaces.get(name, {})
        if not isinstance(old, dict):
            old = {}
        interfaces[name] = {
            "xdp_mode": old.get("xdp_mode", default_xdp_mode),
            "requested_mode": default_xdp_mode,
            "last_program_id": old.get("last_program_id"),
        }
    return {
        "schema": STATE_SCHEMA,
        "selection": selection,
        "interfaces": interfaces,
        "excluded": dict(sorted(excluded.items())),
    }


def summarize_xdp_mode(interface_states: dict[str, dict[str, Any]]) -> str:
    modes = {
        str(state.get("xdp_mode", ""))
        for state in interface_states.values()
        if state.get("xdp_mode") in {"native", "generic"}
    }
    if not modes:
        return "none"
    if len(modes) == 1:
        return next(iter(modes))
    return "mixed"


def runtime_state(
    *,
    requested_backend: str,
    active_backend: str,
    interfaces: dict[str, dict[str, Any]],
    generation: str,
    fallback_reason: str | None = None,
    healthy: bool = True,
) -> dict[str, Any]:
    return {
        "schema": STATE_SCHEMA,
        "requested_backend": requested_backend,
        "active_backend": active_backend,
        "xdp_mode": summarize_xdp_mode(interfaces),
        "interfaces": interfaces,
        "generation": generation,
        "fallback_reason": fallback_reason,
        "healthy": healthy,
    }


def _cmd_select(args: argparse.Namespace) -> int:
    if args.input == "-":
        links = json.load(sys.stdin)
    else:
        with open(args.input) as handle:
            links = json.load(handle)
    if not isinstance(links, list):
        raise ValueError("ip link JSON must be an array")
    selected, excluded = select_interfaces(
        links,
        explicit=args.interface,
        allow_container=args.allow_container,
        excluded_names=args.exclude,
    )
    previous = load_json(Path(args.machine_state)) if args.machine_state else {}
    state = merge_machine_state(
        previous,
        selected,
        excluded,
        selection="explicit" if args.interface else "auto",
        default_xdp_mode=args.default_xdp_mode,
    )
    if args.write:
        atomic_write_json(Path(args.write), state)
    print(json.dumps(state, sort_keys=True))
    return 0


def _parse_interface_state(raw: str) -> tuple[str, dict[str, Any]]:
    try:
        name, payload = raw.split("=", 1)
        mode, program_id = payload.split(":")
    except ValueError as exc:
        raise ValueError(f"invalid interface state: {raw}") from exc
    if mode not in {"native", "generic", "off"}:
        raise ValueError(f"invalid XDP mode for {name}: {mode}")
    return name, {
        "xdp_mode": mode,
        "program_id": None if program_id in {"", "-"} else int(program_id),
        "verified": mode == "off" or program_id not in {"", "-"},
    }


def _cmd_record(args: argparse.Namespace) -> int:
    interface_states = dict(_parse_interface_state(raw) for raw in args.interface_state)
    machine_path = Path(args.machine_state)
    machine = load_json(machine_path)
    old_interfaces = machine.get("interfaces", {})
    if not isinstance(old_interfaces, dict):
        old_interfaces = {}
    for name, state in interface_states.items():
        previous = old_interfaces.get(name, {})
        if not isinstance(previous, dict):
            previous = {}
        previous.update(
            {
                "xdp_mode": state["xdp_mode"],
                "last_program_id": state["program_id"],
            }
        )
        old_interfaces[name] = previous
    machine["schema"] = STATE_SCHEMA
    machine["interfaces"] = old_interfaces
    atomic_write_json(machine_path, machine)

    state = runtime_state(
        requested_backend=args.requested_backend,
        active_backend=args.active_backend,
        interfaces=interface_states,
        generation=args.generation,
        fallback_reason=args.fallback_reason,
        healthy=all(value["verified"] for value in interface_states.values()),
    )
    atomic_write_json(Path(args.runtime_state), state)
    print(json.dumps(state, sort_keys=True))
    return 0


def _cmd_link(args: argparse.Namespace) -> int:
    atomic_symlink(args.target, Path(args.link))
    return 0


def _cmd_transition(args: argparse.Namespace) -> int:
    path = Path(args.path)
    value = load_json(path)
    for key in ("transaction_id", "status", "phase", "previous", "candidate", "release"):
        item = getattr(args, key)
        if item is not None:
            value[key] = item
    value["schema"] = STATE_SCHEMA
    value["updated_at"] = datetime.now(timezone.utc).isoformat()
    atomic_write_json(path, value, mode=0o600)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m auto_xdp.install_state")
    subparsers = parser.add_subparsers(dest="command", required=True)
    select = subparsers.add_parser("select")
    select.add_argument("--input", default="-")
    select.add_argument("--interface", action="append", default=[])
    select.add_argument("--allow-container", action="store_true")
    select.add_argument("--exclude", action="append", default=[])
    select.add_argument("--machine-state")
    select.add_argument("--write")
    select.add_argument("--default-xdp-mode", choices=["auto", "native", "generic"], default="auto")
    select.set_defaults(func=_cmd_select)
    record = subparsers.add_parser("record")
    record.add_argument("--machine-state", required=True)
    record.add_argument("--runtime-state", required=True)
    record.add_argument("--requested-backend", required=True, choices=["auto", "xdp", "nftables"])
    record.add_argument("--active-backend", required=True, choices=["xdp", "nftables"])
    record.add_argument("--generation", default="verified")
    record.add_argument("--fallback-reason")
    record.add_argument("--interface-state", action="append", default=[])
    record.set_defaults(func=_cmd_record)
    link = subparsers.add_parser("link")
    link.add_argument("--target", required=True)
    link.add_argument("--link", required=True)
    link.set_defaults(func=_cmd_link)
    transition = subparsers.add_parser("transition")
    transition.add_argument("--path", required=True)
    transition.add_argument("--transaction-id")
    transition.add_argument("--status")
    transition.add_argument("--phase")
    transition.add_argument("--previous")
    transition.add_argument("--candidate")
    transition.add_argument("--release")
    transition.set_defaults(func=_cmd_transition)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
