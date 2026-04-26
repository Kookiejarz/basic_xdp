from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from auto_xdp import config as cfg

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_LOG_LEVELS = {"debug", "info", "warning", "error"}
_BUILTIN_SLOT_PROTO = {47: "gre", 50: "esp", 132: "sctp"}
_BUILTIN_SLOT_INFO = {
    "gre": (47, "gre_handler.o"),
    "esp": (50, "esp_handler.o"),
    "sctp": (132, "sctp_handler.o"),
}
_DEFAULT_CONFIG_TEMPLATE = """\
# Auto XDP configuration — /etc/auto_xdp/config.toml
# Manage via: axdp trust / axdp acl / axdp permanent
# The daemon reloads this file on SIGHUP (no restart needed).
# To apply changes immediately: axdp restart

[firewall]
# Set to false on private/internal networks where RFC1918 source addresses are legitimate.
bogon_filter = false

[daemon]
# Log verbosity for the Python sync daemon: debug, info, warning, error.
log_level = "warning"

# Event debounce window before reconciling after proc connector activity.
debounce_seconds = 0.4

# Preferred runtime backend: auto, xdp, nftables.
preferred_backend = "auto"

[discovery]
# Exclude loopback-only listeners from exposure discovery.
exclude_loopback = true

# Exclude listeners bound to these addresses/CIDRs from automatic exposure.
exclude_bind_cidrs = []

[permanent_ports]
# Ports always kept open regardless of which services are running.
# SCTP is config-managed only; it is not auto-discovered from listening sockets.
tcp = []
udp = []
sctp = []

[trusted_ips]
# Source IPs/CIDRs that bypass all firewall checks (rate limits, whitelist).
# Format:  "CIDR" = "label"
# "10.0.0.0/8" = "internal network"

# SYN rate limits (new connections per second per source IP).
# Lookup order: syn_by_proc (process name) → syn_by_service (IANA name).
# Ports absent from both tables are not rate-limited (e.g. HTTP/HTTPS).

[rate_limits.syn_by_proc]
sshd           = 2
vsftpd         = 10
proftpd        = 10
"pure-ftpd"    = 10
postfix        = 20
sendmail       = 20
dovecot        = 15
mysqld         = 2
mariadbd       = 2
postgres       = 2
"redis-server" = 2
mongod         = 2
xrdp           = 2
telnetd        = 2

[rate_limits.syn_by_service]
ssh             = 2
ftp             = 10
"ftp-data"      = 10
smtp            = 20
smtps           = 20
submission      = 20
pop3            = 15
pop3s           = 15
imap            = 15
imaps           = 15
mysql           = 2
postgresql      = 2
redis           = 2
mongodb         = 2
"ms-wbt-server" = 2
vnc             = 2
telnet          = 2

[rate_limits.syn_agg_by_proc]

[rate_limits.syn_agg_by_service]

[rate_limits.tcp_conn_by_proc]

[rate_limits.tcp_conn_by_service]


# UDP rate limits (packets per second per source IP).

[rate_limits.udp_by_proc]
named   = 5000
unbound = 5000
dnsmasq = 5000
openvpn = 200

[rate_limits.udp_by_service]
domain  = 5000
ntp     = 500
isakmp  = 100
openvpn = 200

[rate_limits.udp_agg_bytes_by_proc]

[rate_limits.udp_agg_bytes_by_service]

# Per-CIDR port ACL rules.
# These bypass rate limiting and take priority over the port whitelist.
# Ports do NOT need to be in the whitelist — ACL is a zero-trust path.

# [[acl]]
# proto = "tcp"
# cidr  = "10.0.0.0/8"
# ports = [5432, 6379]


# Protocol slot handlers (bpf_tail_call dispatch for non-TCP/UDP/ICMP traffic).

[slots]
# Action for protocols with no handler loaded.
# "pass" preserves existing behaviour; "drop" enforces an explicit allow-list.
default_action = "drop"

# Built-in handlers to load at startup: "gre" (proto 47), "esp" (proto 50),
# "sctp" (proto 132).  Custom handlers: { proto = N, path = "/path/to.o" }
# enabled = ["sctp", "gre", "esp"]
enabled = []

[xdp]
# Remove stale conntrack entries after N consecutive reconcile rounds miss them.
conntrack_stale_reconciles = 2
"""


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
            except Exception:
                return raw[1:-1]
        if raw.startswith("'"):
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


def _run_bpftool(cmd: list[str], fail_msg: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        if detail:
            print(detail, file=sys.stderr)
        raise RuntimeError(fail_msg)
    return result


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
    path.write_text(_DEFAULT_CONFIG_TEMPLATE)


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
    path.write_text(_DEFAULT_CONFIG_TEMPLATE)
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


def _cmd_permanent_list(args: argparse.Namespace) -> int:
    _, data = _load_config(args.config)
    perm = data.get("permanent_ports", {})
    tcp = _normalize_ports([int(port) for port in perm.get("tcp", [])])
    udp = _normalize_ports([int(port) for port in perm.get("udp", [])])
    sctp = _normalize_ports([int(port) for port in perm.get("sctp", [])])
    if not tcp and not udp and not sctp:
        print("  (none)")
        return 0
    for port in tcp:
        print(f"  TCP  {port}")
    for port in udp:
        print(f"  UDP  {port}")
    for port in sctp:
        print(f"  SCTP {port}")
    return 0


def _cmd_permanent_add(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    port = _normalize_ports([args.port])[0]
    perm = data.setdefault("permanent_ports", {"tcp": [], "udp": [], "sctp": []})
    values = _normalize_ports([int(item) for item in perm.setdefault(args.proto, [])] + [port])
    perm[args.proto] = values
    _write_toml(path, data)
    print(f"Added permanent: {args.proto}/{port}")
    return 0


def _cmd_permanent_del(args: argparse.Namespace) -> int:
    path, data = _load_config(args.config)
    port = _normalize_ports([args.port])[0]
    perm = data.setdefault("permanent_ports", {"tcp": [], "udp": [], "sctp": []})
    perm[args.proto] = [item for item in _normalize_ports([int(v) for v in perm.get(args.proto, [])]) if item != port]
    _write_toml(path, data)
    print(f"Removed permanent: {args.proto}/{port}")
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


def _cmd_slot_list(args: argparse.Namespace) -> int:
    bpf_pin_dir, _, handlers_dir = _slot_paths(args)
    slot_pin_dir = bpf_pin_dir / "handlers"
    proto_handlers = bpf_pin_dir / "proto_handlers"

    if not proto_handlers.exists():
        print("XDP not loaded (proto_handlers map not found).")
        return 1

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
    for name in ("gre", "esp", "sctp"):
        proto, obj_name = _BUILTIN_SLOT_INFO[name]
        obj_path = handlers_dir / obj_name
        pin_path = slot_pin_dir / f"proto_{proto}"
        if obj_path.exists():
            if pin_path.exists():
                print(f"  {name:<6} (proto {proto})  [loaded]")
            else:
                print(f"  {name:<6} (proto {proto})")
        else:
            print(f"  {name:<6} (proto {proto})  [.o not found: {obj_path}]")

    if handlers_dir.is_dir():
        for obj in sorted(handlers_dir.glob("*.o")):
            if obj.name in {"gre_handler.o", "esp_handler.o", "sctp_handler.o"}:
                continue
            print(f"  custom  {obj}")
    return 0


def _cmd_slot_load(args: argparse.Namespace) -> int:
    path = Path(args.config)
    bpf_pin_dir, _, handlers_dir = _slot_paths(args)
    slot_ctx_map = bpf_pin_dir / "slot_ctx_map"
    proto_handlers = bpf_pin_dir / "proto_handlers"
    slot_pin_dir = bpf_pin_dir / "handlers"

    builtin_name = ""
    if args.name_or_proto in _BUILTIN_SLOT_INFO:
        builtin_name = args.name_or_proto
        proto, obj_name = _BUILTIN_SLOT_INFO[builtin_name]
        obj_path = handlers_dir / obj_name
    elif args.name_or_proto.isdigit():
        proto = int(args.name_or_proto)
        if not args.path:
            print("Custom handler requires a .o path: axdp slot load PROTO /path/to/handler.o", file=sys.stderr)
            return 1
        obj_path = Path(args.path)
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
    load_cmd = [
        "bpftool",
        "prog",
        "load",
        str(obj_path),
        str(pin_path),
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
        sctp_conntrack = bpf_pin_dir / "sctp_conntrack"
        if not sctp_whitelist.exists():
            print("XDP not loaded completely (sctp_whitelist map not found).", file=sys.stderr)
            return 1
        if not sctp_conntrack.exists():
            print("XDP not loaded completely (sctp_conntrack map not found).", file=sys.stderr)
            return 1
        load_cmd.extend(
            [
                "map",
                "name",
                "sctp_whitelist",
                "pinned",
                str(sctp_whitelist),
                "map",
                "name",
                "sctp_conntrack",
                "pinned",
                str(sctp_conntrack),
            ]
        )

    try:
        _run_bpftool(load_cmd, f"Failed to load {obj_path}")
        _run_bpftool(
            [
                "bpftool",
                "map",
                "update",
                "pinned",
                str(proto_handlers),
                "key",
                str(proto),
                "0",
                "0",
                "0",
                "value",
                "pinned",
                str(pin_path),
            ],
            f"Failed to register handler for proto {proto}",
        )
    except RuntimeError as exc:
        if pin_path.exists():
            pin_path.unlink()
        print(str(exc), file=sys.stderr)
        return 1

    print(f"Loaded handler for proto {proto} from {obj_path}")
    _ensure_config_exists(path)
    slot_args = argparse.Namespace(config=str(path), name=builtin_name) if builtin_name else None
    if builtin_name:
        _cmd_slot_enable_builtin(slot_args)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m auto_xdp.admin_cli")
    parser.add_argument("--config", required=True)
    parser.add_argument("--bpf-pin-dir", default="/sys/fs/bpf/xdp_fw")
    parser.add_argument("--install-dir", default="/usr/local/lib/auto_xdp")
    parser.add_argument("--handlers-dir")
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

    permanent = subparsers.add_parser("permanent")
    perm_sub = permanent.add_subparsers(dest="subcommand", required=True)
    perm_list = perm_sub.add_parser("list")
    perm_list.set_defaults(func=_cmd_permanent_list)
    perm_add = perm_sub.add_parser("add")
    perm_add.add_argument("proto", choices=["tcp", "udp", "sctp"])
    perm_add.add_argument("port", type=int)
    perm_add.add_argument("label", nargs="?")
    perm_add.set_defaults(func=_cmd_permanent_add)
    perm_del = perm_sub.add_parser("del")
    perm_del.add_argument("proto", choices=["tcp", "udp", "sctp"])
    perm_del.add_argument("port", type=int)
    perm_del.set_defaults(func=_cmd_permanent_del)

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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
