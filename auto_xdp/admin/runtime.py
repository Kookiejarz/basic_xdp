from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from auto_xdp.admin.detect import detect_backend as _detect_backend_impl
from auto_xdp.admin.detect import iface_xdp_state as _iface_xdp_state


@dataclass
class RuntimeContext:
    env_config: Path
    bpf_pin_dir: Path
    run_state_dir: Path
    nft_family: str
    nft_table: str
    interface: str = ""


@dataclass
class BackendReport:
    backend: str
    preferred_backend: str
    interfaces: list[str]
    xdp_mode: str
    xdp_attach: dict[str, str]
    generation: str
    healthy: bool
    fallback_reason: str | None
    excluded_interfaces: dict[str, str]
    policy: str
    release: str
    install_transition: str | None


def _load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    data: dict[str, str] = {}
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        try:
            parsed = shlex.split(value, posix=True)
        except ValueError:
            parsed = [value.strip().strip('"').strip("'")]
        data[key.strip()] = parsed[0] if parsed else ""
    return data


def _command_exists(name: str) -> bool:
    return any(
        os.access(Path(entry) / name, os.X_OK)
        for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry
    )


def _run_text(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def _load_json_file(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _nft_policy_schema(family: str, table: str) -> str:
    if not _command_exists("nft"):
        return "unavailable"
    result = _run_text(["nft", "list", "table", family, table])
    if result.returncode != 0:
        return "missing"
    if "set tcp_ports" in result.stdout and "chain input" in result.stdout:
        return "policy_schema_v2"
    return "legacy"


def _ip_default_iface() -> str:
    result = _run_text(["ip", "route", "show", "default"])
    if result.returncode != 0:
        return ""
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == "default" and len(parts) >= 5:
            return parts[4]
    return ""


def _iface_xdp_program_id(iface: str) -> int | None:
    result = _run_text(["ip", "-j", "-d", "link", "show", "dev", iface])
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None

    def program_id(node: object) -> int | None:
        if isinstance(node, dict):
            for key, child in node.items():
                if (key == "id" or key.endswith("prog_id")) and isinstance(child, int):
                    return child
                found = program_id(child)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for child in node:
                found = program_id(child)
                if found is not None:
                    return found
        return None

    def find_xdp(node: object) -> int | None:
        if isinstance(node, dict):
            for key, child in node.items():
                if key == "xdp":
                    found = program_id(child)
                    if found is not None:
                        return found
                else:
                    found = find_xdp(child)
                    if found is not None:
                        return found
        elif isinstance(node, list):
            for child in node:
                found = find_xdp(child)
                if found is not None:
                    return found
        return None

    return find_xdp(value)


def _configured_ifaces(env: dict[str, str]) -> list[str]:
    if env.get("IFACES"):
        return env["IFACES"].split()
    if env.get("IFACE"):
        return [env["IFACE"]]
    return []


def _preferred_backend(env: dict[str, str]) -> str:
    default = env.get("PREFERRED_BACKEND", "auto")
    path = Path(env.get("TOML_CONFIG", "/etc/auto_xdp/config.toml"))
    if not path.exists():
        return default
    try:
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib

        with path.open("rb") as handle:
            value = str(tomllib.load(handle).get("daemon", {}).get("preferred_backend", default)).lower()
    except (ImportError, OSError, ValueError):
        return default
    return value if value in {"auto", "xdp", "nftables"} else default


def detect_backend(ctx: RuntimeContext, interfaces: list[str]) -> str:
    return _detect_backend_impl(
        ctx.bpf_pin_dir, ctx.run_state_dir, interfaces, ctx.nft_family, ctx.nft_table
    )


def collect_backend_report(ctx: RuntimeContext) -> BackendReport:
    env = _load_env_file(ctx.env_config)
    interfaces = _configured_ifaces(env)
    iface = ctx.interface or (interfaces[0] if interfaces else "") or _ip_default_iface()
    if not iface:
        raise RuntimeError("Could not detect interface. Use --interface IFACE.")
    if not interfaces:
        interfaces = [iface]

    check_ifaces = [ctx.interface] if ctx.interface else interfaces
    backend = detect_backend(ctx, check_ifaces)
    xdp_mode_path = ctx.run_state_dir / "xdp_mode"
    xdp_mode = xdp_mode_path.read_text().strip() if xdp_mode_path.exists() else "-"

    xdp_attach = {name: _iface_xdp_state(name) for name in interfaces}
    runtime_path = Path(env.get("RUNTIME_STATE", "/etc/auto_xdp/runtime-state.json"))
    machine_path = Path(env.get("MACHINE_STATE", "/etc/auto_xdp/machine-state.json"))
    persistent = _load_json_file(runtime_path)
    machine = _load_json_file(machine_path)
    install_dir = Path(env.get("INSTALL_DIR", "/usr/local/lib/auto_xdp/current"))
    release_meta = _load_json_file(install_dir / "release.json")
    release = str(release_meta.get("release", "legacy"))
    transition = _load_json_file(
        Path(env.get("INSTALL_TRANSACTION_FILE", "/etc/auto_xdp/install-transaction.json"))
    )
    transition_state = None
    transition_status = str(transition.get("status", ""))
    if transition_status == "active":
        transition_state = str(transition.get("phase", "unknown"))
    elif transition_status == "failed":
        transition_state = f"failed/{transition.get('phase', 'unknown')}"
    excluded = machine.get("excluded", {})
    if not isinstance(excluded, dict):
        excluded = {}
    clean_generation = not any(
        path.exists()
        for path in (
            Path(f"{ctx.bpf_pin_dir}_next"),
            Path(f"{ctx.bpf_pin_dir}_rollback"),
        )
    )
    if backend == "xdp":
        attachments_ok = all(value in {"native", "generic"} for value in xdp_attach.values())
        saved_interfaces = persistent.get("interfaces", {})
        ids_ok = True
        if isinstance(saved_interfaces, dict) and saved_interfaces:
            for name in interfaces:
                saved = saved_interfaces.get(name, {})
                expected = saved.get("program_id") if isinstance(saved, dict) else None
                if not isinstance(expected, int) or _iface_xdp_program_id(name) != expected:
                    ids_ok = False
                    break
        policy = "BPF maps pinned"
        healthy = attachments_ok and ids_ok and clean_generation
    else:
        schema = _nft_policy_schema(ctx.nft_family, ctx.nft_table)
        policy = f"{ctx.nft_family} {ctx.nft_table} / {schema}"
        healthy = schema == "policy_schema_v2" and clean_generation
    if persistent:
        healthy = healthy and bool(persistent.get("healthy", False))
        xdp_mode = str(persistent.get("xdp_mode", xdp_mode))
    generation = str(persistent.get("generation", "legacy"))
    if release != "legacy" and generation not in {release, "verified"}:
        healthy = False
    if transition_state:
        healthy = False

    return BackendReport(
        backend=backend,
        preferred_backend=_preferred_backend(env),
        interfaces=interfaces,
        xdp_mode=xdp_mode,
        xdp_attach=xdp_attach,
        generation=generation if clean_generation else "recovery-required",
        healthy=healthy,
        fallback_reason=(
            str(persistent["fallback_reason"])
            if persistent.get("fallback_reason")
            else None
        ),
        excluded_interfaces={str(key): str(value) for key, value in excluded.items()},
        policy=policy,
        release=release,
        install_transition=transition_state,
    )


def render_backend_text(report: BackendReport) -> str:
    interfaces = " ".join(report.interfaces)
    xdp_attach = " ".join(f"{iface}={state}" for iface, state in report.xdp_attach.items()) or "-"
    lines = [
            f"Backend   : {report.backend}",
            f"Preferred : {report.preferred_backend}",
            f"Health    : {'healthy' if report.healthy else 'degraded'}",
            f"Generation: {report.generation}",
            f"Release   : {report.release}",
            f"Policy    : {report.policy}",
            f"Interfaces: {interfaces}",
            f"XDP mode  : {report.xdp_mode}",
            f"XDP attach: {xdp_attach}",
        ]
    if report.fallback_reason:
        lines.append(f"Fallback  : {report.fallback_reason}")
    if report.install_transition:
        lines.append(f"Install   : transaction/{report.install_transition}")
    if report.excluded_interfaces:
        excluded = " ".join(
            f"{name}={reason.replace(' ', '-')}"
            for name, reason in sorted(report.excluded_interfaces.items())
        )
        lines.append(f"Excluded  : {excluded}")
    return "\n".join(lines)


def render_backend_json(report: BackendReport) -> str:
    return json.dumps(
        {
            "backend": report.backend,
            "preferred_backend": report.preferred_backend,
            "interfaces": report.interfaces,
            "xdp_mode": report.xdp_mode,
            "xdp_attach": report.xdp_attach,
            "generation": report.generation,
            "healthy": report.healthy,
            "fallback_reason": report.fallback_reason,
            "excluded_interfaces": report.excluded_interfaces,
            "policy": report.policy,
            "release": report.release,
            "install_transition": report.install_transition,
        },
        sort_keys=True,
    )
