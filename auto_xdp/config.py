from __future__ import annotations

import copy
import ipaddress
import logging
import os
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


log = logging.getLogger(__name__)

TOML_CONFIG_PATH = "/etc/auto_xdp/config.toml"
RINGBUF_SOCKET_PATH = "/var/run/auto_xdp/pkt_events.sock"

BACKEND_AUTO = "auto"
BACKEND_XDP = "xdp"
BACKEND_NFTABLES = "nftables"

# Compiled-in defaults — single source of truth for TOML fallbacks
_BPF_PIN_DIR = "/sys/fs/bpf/xdp_fw"
_NFT_FAMILY = "inet"
_NFT_TABLE = "auto_xdp"

XDP_OBJ_PATH = os.environ.get("XDP_OBJ_PATH", "")

_SYN_RATE_BY_PROC: dict[str, int] = {}
_SYN_RATE_BY_SERVICE: dict[str, int] = {}
_SYN_AGG_RATE_BY_PROC: dict[str, int] = {}
_SYN_AGG_RATE_BY_SERVICE: dict[str, int] = {}
_UDP_RATE_BY_PROC: dict[str, int] = {}
_UDP_RATE_BY_SERVICE: dict[str, int] = {}
_UDP_AGG_BYTES_BY_PROC: dict[str, int] = {}
_UDP_AGG_BYTES_BY_SERVICE: dict[str, int] = {}

# ARRAY_OF_MAPS requires every LRU inner to match the compiled template.
_RATE_MAP_TEMPLATE_ENTRIES_V4 = 16384
_RATE_MAP_TEMPLATE_ENTRIES_V6 = 4096
RATE_MAP_ENTRIES_V4 = _RATE_MAP_TEMPLATE_ENTRIES_V4
RATE_MAP_ENTRIES_V6 = _RATE_MAP_TEMPLATE_ENTRIES_V6
_RATE_MAP_ENTRIES_BY_PROC: dict[str, int] = {}
_RATE_MAP_ENTRIES_BY_SERVICE: dict[str, int] = {}

# Default-on TCP protection knobs — applied when no explicit per-proc/service
# entry exists. See docs/superpowers/specs/2026-05-06-tcp-default-on-protection-design.md.
XDP_SENSITIVE_PORT_THRESHOLD = 5
XDP_DEFAULT_TCP_SYN_RATE_STRICT = 5
XDP_DEFAULT_TCP_SYN_RATE = 100
XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT = 50
XDP_DEFAULT_TCP_SYN_AGG_RATE = 1000
RATE_LIMIT_SOURCE_PREFIX_V4 = 32
RATE_LIMIT_SOURCE_PREFIX_V6 = 128

BOGON_FILTER_ENABLED = True
ISATTACK_MODE = False
DROP_EVENTS_ENABLED = True
LOG_LEVEL: str = "warning"
DEBOUNCE_SECONDS = 0.4
POLICY_MODE = "audit"
ZONES: dict[str, dict[str, list[str]]] = {}
SUBJECTS: dict[str, dict] = {}
UNKNOWN_SUBJECTS: dict[str, str] = {"public": "deny"}
DISCOVERY_EXCLUDE_LOOPBACK = True
DISCOVERY_EXCLUDE_BIND_CIDRS: list[str] = []
DISCOVERY_EXCLUDE_PORTS: set[int] = set()
PREFERRED_BACKEND = BACKEND_AUTO
XDP_ICMP_BURST_PACKETS = 100
XDP_ICMP_RATE_PPS = 100.0
XDP_UDP_GLOBAL_WINDOW_SECONDS = 1.0
XDP_RATE_WINDOW_SECONDS = 1.0
XDP_UDP_GLOBAL_BYTE_RATE = 0

NFT_FAMILY = _NFT_FAMILY
NFT_TABLE = _NFT_TABLE
NFT_TCP_SET = "tcp_ports"
NFT_UDP_SET = "udp_ports"
NFT_SCTP_SET = "sctp_ports"
NFT_TRUSTED_SET4 = "trusted_v4"
NFT_TRUSTED_SET6 = "trusted_v6"

TRUSTED_SRC_IPS: dict[str, str] = {}
ACL_RULES: list[dict] = []
SIT4_ENDPOINTS: list[str] = []

ABUSEIPDB_ENABLED = False
ABUSEIPDB_BASE_URL = "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main"
ABUSEIPDB_SOURCES: list[str] = ["s1003d"]
ABUSEIPDB_REFRESH_SECONDS = 3600.0
ABUSEIPDB_RISK_MAP_PATH4 = ""

SLOT_DEFAULT_ACTION = "drop"

ACL_MAX_PORTS = 64
ACL_VAL_SIZE = 4 + ACL_MAX_PORTS * 2

_PACKAGE_DIR = Path(__file__).resolve().parent
_DEFAULT_XDP_REQUIRED_MAP_NAMES = (
    "prog",
    "tcp_whitelist",
    "udp_whitelist",
    "tcp_zone_whitelist",
    "udp_zone_whitelist",
    "sctp_whitelist",
    "trusted_ipv4",
    "trusted_ipv6",
    "tcp_port_policies",
    "udp_port_policies",
    "udp_global_rl",
    "xdp_runtime_cfg",
    "udp_percpu_acc",
    "proto_handlers",
    "tcp_profile_handlers",
    "tcp_port_handlers",
    "udp_port_handlers",
    "hblk4",
    "hblk6",
    "udp_hv4",
    "udp_hv6",
    "slot_ctx_map",
    "profile_ctx_map",
    "sit4_endpoints",
    "abuseipdb_v4",
    "syn4",
    "syn6",
    "udprt4",
    "udprt6",
)


def load_required_xdp_map_names() -> tuple[str, ...]:
    candidates = []

    override = os.environ.get("XDP_REQUIRED_MAPS_FILE")
    if override:
        candidates.append(Path(override))

    candidates.append(_PACKAGE_DIR / "xdp_required_maps.txt")

    install_dir = os.environ.get("INSTALL_DIR")
    if install_dir:
        candidates.append(Path(install_dir) / "xdp_required_maps.txt")

    for path in candidates:
        try:
            with path.open("r", encoding="utf-8") as fh:
                names = []
                for raw_line in fh:
                    line = raw_line.split("#", 1)[0].strip()
                    if line:
                        names.append(line)
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.warning("Failed to load %s: %s", path, exc)
            continue
        if names:
            return tuple(names)

    return _DEFAULT_XDP_REQUIRED_MAP_NAMES


REQUIRED_XDP_MAP_NAMES = load_required_xdp_map_names()

# Map paths derived from BPF_PIN_DIR. Declared here so they are visible at
# module scope; the real values are filled in by _set_bpf_pin_dir() below.
BPF_PIN_DIR = ""
TCP_MAP_PATH = ""
UDP_MAP_PATH = ""
TCP_ZONE_MAP_PATH = ""
UDP_ZONE_MAP_PATH = ""
SCTP_MAP_PATH = ""
TRUSTED_IPS_MAP_PATH4 = ""
TRUSTED_IPS_MAP_PATH6 = ""
TCP_PORT_POLICY_MAP_PATH = ""
UDP_PORT_POLICY_MAP_PATH = ""
TCP_PROFILE_HANDLER_MAP_PATH = ""
UDP_GLOBAL_RL_MAP_PATH = ""
XDP_RUNTIME_CFG_MAP_PATH = ""
TCP_ACL_MAP_PATH4 = ""
TCP_ACL_MAP_PATH6 = ""
UDP_ACL_MAP_PATH4 = ""
UDP_ACL_MAP_PATH6 = ""
SIT4_ENDPOINTS_MAP_PATH = ""
SYN4_MAP_PATH = ""
SYN6_MAP_PATH = ""
UDPRT4_MAP_PATH = ""
UDPRT6_MAP_PATH = ""
REQUIRED_XDP_MAP_PATHS: tuple[str, ...] = ()


def _set_bpf_pin_dir(pin_dir: str) -> None:
    """Update BPF_PIN_DIR and every derived map-path global in one place."""
    global BPF_PIN_DIR
    global TCP_MAP_PATH, UDP_MAP_PATH, TCP_ZONE_MAP_PATH, UDP_ZONE_MAP_PATH, SCTP_MAP_PATH
    global TRUSTED_IPS_MAP_PATH4, TRUSTED_IPS_MAP_PATH6
    global TCP_PORT_POLICY_MAP_PATH, UDP_PORT_POLICY_MAP_PATH, TCP_PROFILE_HANDLER_MAP_PATH
    global UDP_GLOBAL_RL_MAP_PATH, XDP_RUNTIME_CFG_MAP_PATH
    global TCP_ACL_MAP_PATH4, TCP_ACL_MAP_PATH6
    global UDP_ACL_MAP_PATH4, UDP_ACL_MAP_PATH6
    global SIT4_ENDPOINTS_MAP_PATH
    global SYN4_MAP_PATH, SYN6_MAP_PATH, UDPRT4_MAP_PATH, UDPRT6_MAP_PATH
    global REQUIRED_XDP_MAP_PATHS
    global ABUSEIPDB_RISK_MAP_PATH4
    BPF_PIN_DIR = pin_dir
    TCP_MAP_PATH = f"{pin_dir}/tcp_whitelist"
    UDP_MAP_PATH = f"{pin_dir}/udp_whitelist"
    TCP_ZONE_MAP_PATH = f"{pin_dir}/tcp_zone_whitelist"
    UDP_ZONE_MAP_PATH = f"{pin_dir}/udp_zone_whitelist"
    SCTP_MAP_PATH = f"{pin_dir}/sctp_whitelist"
    TRUSTED_IPS_MAP_PATH4 = f"{pin_dir}/trusted_ipv4"
    TRUSTED_IPS_MAP_PATH6 = f"{pin_dir}/trusted_ipv6"
    TCP_PORT_POLICY_MAP_PATH = f"{pin_dir}/tcp_port_policies"
    UDP_PORT_POLICY_MAP_PATH = f"{pin_dir}/udp_port_policies"
    TCP_PROFILE_HANDLER_MAP_PATH = f"{pin_dir}/tcp_profile_handlers"
    UDP_GLOBAL_RL_MAP_PATH = f"{pin_dir}/udp_global_rl"
    XDP_RUNTIME_CFG_MAP_PATH = f"{pin_dir}/xdp_runtime_cfg"
    TCP_ACL_MAP_PATH4 = f"{pin_dir}/tcp_acl_v4"
    TCP_ACL_MAP_PATH6 = f"{pin_dir}/tcp_acl_v6"
    UDP_ACL_MAP_PATH4 = f"{pin_dir}/udp_acl_v4"
    UDP_ACL_MAP_PATH6 = f"{pin_dir}/udp_acl_v6"
    SIT4_ENDPOINTS_MAP_PATH = f"{pin_dir}/sit4_endpoints"
    SYN4_MAP_PATH = f"{pin_dir}/syn4"
    SYN6_MAP_PATH = f"{pin_dir}/syn6"
    UDPRT4_MAP_PATH = f"{pin_dir}/udprt4"
    UDPRT6_MAP_PATH = f"{pin_dir}/udprt6"
    ABUSEIPDB_RISK_MAP_PATH4 = f"{pin_dir}/abuseipdb_v4"
    REQUIRED_XDP_MAP_PATHS = tuple(f"{pin_dir}/{n}" for n in REQUIRED_XDP_MAP_NAMES)


_set_bpf_pin_dir(_BPF_PIN_DIR)


def normalize_cidr(cidr_str: str) -> str:
    net: ipaddress.IPv4Network | ipaddress.IPv6Network
    if ":" in cidr_str:
        net = ipaddress.IPv6Network(cidr_str, strict=False)
    else:
        net = ipaddress.IPv4Network(cidr_str, strict=False)
    return f"{net.network_address}/{net.prefixlen}"


def load_toml_config(path: str = TOML_CONFIG_PATH, *, strict: bool = False) -> dict:
    if tomllib is None:
        log.debug("tomllib not available; skipping TOML config load.")
        if strict:
            raise RuntimeError("TOML support is unavailable")
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        if strict:
            raise
        return {}
    except OSError as exc:
        log.warning("Failed to load %s: %s", path, exc)
        if strict:
            raise
        return {}
    except ValueError as exc:
        log.warning("Invalid TOML in %s: %s", path, exc)
        raise




def _coerce_log_level(value: object, default: str = "warning") -> str:
    level = str(value).lower()
    if level not in {"debug", "info", "warning", "error"}:
        log.warning("Invalid daemon.log_level %r; using %s", value, default)
        return default
    return level


def _coerce_backend(value: object, default: str = BACKEND_AUTO) -> str:
    backend = str(value).lower()
    if backend not in {BACKEND_AUTO, BACKEND_XDP, BACKEND_NFTABLES}:
        log.warning("Invalid daemon.preferred_backend %r; using %s", value, default)
        return default
    return backend


def _coerce_positive_float(value: object, path: str, default: float) -> float:
    try:
        parsed = float(value)  # type: ignore[arg-type]  # runtime-coerce arbitrary TOML value
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed <= 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_positive_int(value: object, path: str, default: int) -> int:
    try:
        parsed = int(value)  # type: ignore[call-overload]  # runtime-coerce arbitrary TOML value
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed <= 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_nonnegative_float(value: object, path: str, default: float) -> float:
    try:
        parsed = float(value)  # type: ignore[arg-type]  # runtime-coerce arbitrary TOML value
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed < 0:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _coerce_prefix_len(value: object, path: str, default: int, maximum: int) -> int:
    if isinstance(value, str):
        value = value.removeprefix("/")
    try:
        parsed = int(value)  # type: ignore[call-overload]  # runtime-coerce arbitrary TOML value
    except (TypeError, ValueError):
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    if parsed < 0 or parsed > maximum:
        log.warning("Invalid %s %r; using %s", path, value, default)
        return default
    return parsed


def _apply_toml_config_in_place(cfg: dict) -> None:
    global BOGON_FILTER_ENABLED, ISATTACK_MODE, DROP_EVENTS_ENABLED
    global LOG_LEVEL, DEBOUNCE_SECONDS
    global DISCOVERY_EXCLUDE_LOOPBACK
    global PREFERRED_BACKEND
    global RATE_LIMIT_SOURCE_PREFIX_V4, RATE_LIMIT_SOURCE_PREFIX_V6
    global RATE_MAP_ENTRIES_V4, RATE_MAP_ENTRIES_V6
    global XDP_ICMP_BURST_PACKETS, XDP_ICMP_RATE_PPS
    global XDP_UDP_GLOBAL_WINDOW_SECONDS, XDP_RATE_WINDOW_SECONDS
    global XDP_UDP_GLOBAL_BYTE_RATE
    global NFT_FAMILY, NFT_TABLE
    global POLICY_MODE, ZONES, SUBJECTS, UNKNOWN_SUBJECTS
    global XDP_SENSITIVE_PORT_THRESHOLD
    global XDP_DEFAULT_TCP_SYN_RATE_STRICT, XDP_DEFAULT_TCP_SYN_RATE
    global XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT, XDP_DEFAULT_TCP_SYN_AGG_RATE

    TRUSTED_SRC_IPS.clear()
    ACL_RULES.clear()
    SIT4_ENDPOINTS.clear()

    _SYN_RATE_BY_PROC.clear()
    _SYN_RATE_BY_SERVICE.clear()
    _SYN_AGG_RATE_BY_PROC.clear()
    _SYN_AGG_RATE_BY_SERVICE.clear()
    _UDP_RATE_BY_PROC.clear()
    _UDP_RATE_BY_SERVICE.clear()
    _UDP_AGG_BYTES_BY_PROC.clear()
    _UDP_AGG_BYTES_BY_SERVICE.clear()
    _RATE_MAP_ENTRIES_BY_PROC.clear()
    _RATE_MAP_ENTRIES_BY_SERVICE.clear()
    DISCOVERY_EXCLUDE_BIND_CIDRS.clear()
    DISCOVERY_EXCLUDE_PORTS.clear()
    ZONES = {}
    SUBJECTS = {}
    UNKNOWN_SUBJECTS = {"public": "deny"}
    POLICY_MODE = "audit"
    RATE_LIMIT_SOURCE_PREFIX_V4 = 32
    RATE_LIMIT_SOURCE_PREFIX_V6 = 128
    RATE_MAP_ENTRIES_V4 = _RATE_MAP_TEMPLATE_ENTRIES_V4
    RATE_MAP_ENTRIES_V6 = _RATE_MAP_TEMPLATE_ENTRIES_V6

    if "permanent_ports" in cfg:
        raise ValueError("unsupported exposure configuration; use subjects.*.exposure grants")

    for cidr, label in cfg.get("trusted_ips", {}).items():
        TRUSTED_SRC_IPS[normalize_cidr(cidr)] = str(label)

    for ep in cfg.get("tunnel", {}).get("sit4_endpoints", []):
        try:
            ip = ipaddress.IPv4Address(str(ep))
            SIT4_ENDPOINTS.append(str(ip))
        except ValueError:
            log.warning("Invalid tunnel.sit4_endpoints entry %r; skipping.", ep)

    for rule in cfg.get("acl", []):
        ACL_RULES.append({
            "proto": rule["proto"],
            "cidr": normalize_cidr(rule["cidr"]),
            "ports": [int(p) for p in rule.get("ports", [])],
        })

    rl = cfg.get("rate_limits", {})
    RATE_LIMIT_SOURCE_PREFIX_V4 = _coerce_prefix_len(
        rl.get("source_cidr_v4", rl.get("source_prefix_v4", 32)),
        "rate_limits.source_cidr_v4",
        32,
        32,
    )
    RATE_LIMIT_SOURCE_PREFIX_V6 = _coerce_prefix_len(
        rl.get("source_cidr_v6", rl.get("source_prefix_v6", 128)),
        "rate_limits.source_cidr_v6",
        128,
        128,
    )
    _SYN_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("syn_by_proc", {}).items()})
    _SYN_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("syn_by_service", {}).items()})
    _SYN_AGG_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("syn_agg_by_proc", {}).items()})
    _SYN_AGG_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("syn_agg_by_service", {}).items()})
    _UDP_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("udp_by_proc", {}).items()})
    _UDP_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("udp_by_service", {}).items()})
    _UDP_AGG_BYTES_BY_PROC.update({k: int(v) for k, v in rl.get("udp_agg_bytes_by_proc", {}).items()})
    _UDP_AGG_BYTES_BY_SERVICE.update({k: int(v) for k, v in rl.get("udp_agg_bytes_by_service", {}).items()})
    RATE_MAP_ENTRIES_V4 = int(rl.get("map_entries_v4", _RATE_MAP_TEMPLATE_ENTRIES_V4))
    RATE_MAP_ENTRIES_V6 = int(rl.get("map_entries_v6", _RATE_MAP_TEMPLATE_ENTRIES_V6))
    if (
        RATE_MAP_ENTRIES_V4 != _RATE_MAP_TEMPLATE_ENTRIES_V4
        or RATE_MAP_ENTRIES_V6 != _RATE_MAP_TEMPLATE_ENTRIES_V6
        or rl.get("map_entries_by_proc")
        or rl.get("map_entries_by_service")
    ):
        raise ValueError(
            "rate-limit inner map capacities are fixed by the compiled XDP map ABI"
        )

    BOGON_FILTER_ENABLED = bool(cfg.get("firewall", {}).get("bogon_filter", True))
    ISATTACK = cfg.get("under_attack", {})
    ISATTACK_MODE = bool(ISATTACK.get("enabled", False))
    DROP_EVENTS_ENABLED = not ISATTACK_MODE
    daemon = cfg.get("daemon", {})
    LOG_LEVEL = _coerce_log_level(daemon.get("log_level", "warning"))
    DEBOUNCE_SECONDS = _coerce_positive_float(
        daemon.get("debounce_seconds", 0.4),
        "daemon.debounce_seconds",
        0.4,
    )
    PREFERRED_BACKEND = _coerce_backend(daemon.get("preferred_backend", BACKEND_AUTO))

    discovery = cfg.get("discovery", {})
    DISCOVERY_EXCLUDE_LOOPBACK = bool(discovery.get("exclude_loopback", True))
    DISCOVERY_EXCLUDE_BIND_CIDRS.extend(
        normalize_cidr(cidr) for cidr in discovery.get("exclude_bind_cidrs", [])
    )
    DISCOVERY_EXCLUDE_PORTS.update(
        int(p) for p in discovery.get("exclude_ports", [])
    )

    policy_cfg = cfg.get("policy", {})
    if not isinstance(policy_cfg, dict):
        raise ValueError("policy must be a table")
    POLICY_MODE = str(policy_cfg.get("mode", "audit")).lower()
    if POLICY_MODE not in {"observe", "audit", "enforce"}:
        raise ValueError("policy.mode must be one of observe, audit, enforce")

    raw_zones = cfg.get("zones", {})
    if not isinstance(raw_zones, dict):
        raise ValueError("zones must be a table")
    interface_zones: dict[str, str] = {}
    for zone_name, zone in raw_zones.items():
        if not isinstance(zone, dict):
            raise ValueError(f"zones.{zone_name} must be a table")
        interfaces = zone.get("interfaces", [])
        if not isinstance(interfaces, list) or not all(isinstance(item, str) for item in interfaces):
            raise ValueError(f"zones.{zone_name}.interfaces must be a list of strings")
        cidrs = zone.get("cidrs", [])
        if not isinstance(cidrs, list) or not all(isinstance(item, str) for item in cidrs):
            raise ValueError(f"zones.{zone_name}.cidrs must be a list of strings")
        for interface in interfaces:
            if interface == "*":
                continue
            previous = interface_zones.setdefault(interface, str(zone_name))
            if previous != str(zone_name):
                raise ValueError(
                    f"interface {interface!r} belongs to both zones {previous!r} and {zone_name!r}"
                )
        ZONES[str(zone_name)] = {"interfaces": list(interfaces), "cidrs": list(cidrs)}
    ZONES.setdefault("public", {"interfaces": [], "cidrs": []})

    raw_subjects = cfg.get("subjects", {})
    if not isinstance(raw_subjects, dict):
        raise ValueError("subjects must be a table")
    for subject_name, subject in raw_subjects.items():
        if not isinstance(subject, dict):
            raise ValueError(f"subjects.{subject_name} must be a table")
        resolve = subject.get("resolve", {})
        if not isinstance(resolve, dict):
            raise ValueError(f"subjects.{subject_name}.resolve must be a table")
        resolve_keys = {
            "systemd_unit", "process_name", "container_runtime", "container_id",
            "container_name", "container_label",
        }
        unknown_resolve = set(resolve) - resolve_keys
        if unknown_resolve:
            raise ValueError(
                f"subjects.{subject_name}.resolve has unsupported keys: "
                f"{', '.join(sorted(str(key) for key in unknown_resolve))}"
            )
        container_runtime = resolve.get("container_runtime")
        if container_runtime is not None and str(container_runtime).lower() not in {"docker", "podman"}:
            raise ValueError(f"subjects.{subject_name}.resolve.container_runtime must be docker or podman")
        container_label = resolve.get("container_label")
        if container_label is not None and not isinstance(container_label, (str, dict)):
            raise ValueError(f"subjects.{subject_name}.resolve.container_label must be a string or table")
        container_identity = any(
            bool(resolve.get(key))
            for key in ("container_id", "container_name", "container_label")
        )
        if container_runtime and not container_identity:
            raise ValueError(
                f"subjects.{subject_name}.resolve.container_runtime requires container identity"
            )
        exposure = subject.get("exposure", {})
        if not isinstance(exposure, dict):
            raise ValueError(f"subjects.{subject_name}.exposure must be a table")
        for zone_name, zone_policy in exposure.items():
            if str(zone_name) not in ZONES:
                raise ValueError(f"subjects.{subject_name} references unknown zone {zone_name}")
            if not isinstance(zone_policy, dict):
                raise ValueError(f"subjects.{subject_name}.exposure.{zone_name} must be a table")
            for protocol in ("tcp", "udp", "sctp"):
                protocol_policy = zone_policy.get(protocol)
                if protocol_policy is None:
                    continue
                if not isinstance(protocol_policy, dict):
                    raise ValueError(f"subjects.{subject_name}.exposure.{zone_name}.{protocol} must be a table")
                ports = protocol_policy.get("ports", [])
                if not isinstance(ports, list):
                    raise ValueError(f"subjects.{subject_name}.exposure.{zone_name}.{protocol}.ports must be a list")
                try:
                    if any(isinstance(port, bool) or not 1 <= int(port) <= 65535 for port in ports):
                        raise ValueError
                except (TypeError, ValueError):
                    raise ValueError(
                        f"subjects.{subject_name}.exposure.{zone_name}.{protocol}.ports must contain 1..65535"
                    ) from None
        SUBJECTS[str(subject_name)] = copy.deepcopy(subject)

    raw_unknown = cfg.get("unknown_subjects", policy_cfg.get("unknown_subjects", {"public": "deny"}))
    if not isinstance(raw_unknown, dict):
        raise ValueError("unknown_subjects must be a table")
    for zone_name, action in raw_unknown.items():
        if str(action).lower() != "deny":
            raise ValueError("unknown_subjects may only use deny")
        UNKNOWN_SUBJECTS[str(zone_name)] = "deny"

    xdp = cfg.get("xdp", {})
    _set_bpf_pin_dir(str(xdp.get("bpf_pin_dir", _BPF_PIN_DIR)).rstrip("/"))

    nftables = cfg.get("nftables", {})
    NFT_FAMILY = str(nftables.get("family", _NFT_FAMILY))
    NFT_TABLE = str(nftables.get("table", _NFT_TABLE))

    xdp_runtime = xdp.get("runtime", {})
    XDP_ICMP_BURST_PACKETS = _coerce_positive_int(
        xdp_runtime.get("icmp_burst_packets", 100),
        "xdp.runtime.icmp_burst_packets",
        100,
    )
    XDP_ICMP_RATE_PPS = _coerce_nonnegative_float(
        xdp_runtime.get("icmp_rate_pps", 100.0),
        "xdp.runtime.icmp_rate_pps",
        100.0,
    )
    XDP_UDP_GLOBAL_WINDOW_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("udp_global_window_seconds", 1.0),
        "xdp.runtime.udp_global_window_seconds",
        1.0,
    )
    XDP_RATE_WINDOW_SECONDS = _coerce_nonnegative_float(
        xdp_runtime.get("rate_window_seconds", 1.0),
        "xdp.runtime.rate_window_seconds",
        1.0,
    )
    XDP_SENSITIVE_PORT_THRESHOLD = _coerce_positive_int(
        xdp_runtime.get("sensitive_port_threshold", 5),
        "xdp.runtime.sensitive_port_threshold", 5,
    )
    XDP_DEFAULT_TCP_SYN_RATE_STRICT = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_rate_strict", 5),
        "xdp.runtime.default_tcp_syn_rate_strict", 5,
    )
    XDP_DEFAULT_TCP_SYN_RATE = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_rate", 100),
        "xdp.runtime.default_tcp_syn_rate", 100,
    )
    XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_agg_rate_strict", 50),
        "xdp.runtime.default_tcp_syn_agg_rate_strict", 50,
    )
    XDP_DEFAULT_TCP_SYN_AGG_RATE = _coerce_positive_int(
        xdp_runtime.get("default_tcp_syn_agg_rate", 1000),
        "xdp.runtime.default_tcp_syn_agg_rate", 1000,
    )
    _udp_global_byte_rate_mbps = _coerce_nonnegative_float(
        xdp_runtime.get("udp_global_byte_rate_mbps", 0.0),
        "xdp.runtime.udp_global_byte_rate_mbps",
        0.0,
    )
    XDP_UDP_GLOBAL_BYTE_RATE = int(_udp_global_byte_rate_mbps * 1_000_000 / 8)

    global SLOT_DEFAULT_ACTION
    _slots = cfg.get("slots", {})
    _slot_default = str(_slots.get("default_action", "drop")).lower()
    SLOT_DEFAULT_ACTION = "drop" if _slot_default == "drop" else "pass"

    global ABUSEIPDB_ENABLED, ABUSEIPDB_BASE_URL, ABUSEIPDB_SOURCES, ABUSEIPDB_REFRESH_SECONDS
    _ab = cfg.get("abuseipdb", {})
    ABUSEIPDB_ENABLED = bool(_ab.get("enabled", False))
    ABUSEIPDB_BASE_URL = str(_ab.get(
        "base_url",
        "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/refs/heads/main",
    ))
    _raw_sources = _ab.get("sources", ["s1003d"])
    ABUSEIPDB_SOURCES = [str(s) for s in _raw_sources] if isinstance(_raw_sources, list) else ["s1003d"]
    ABUSEIPDB_REFRESH_SECONDS = _coerce_positive_float(
        _ab.get("refresh_seconds", 3600.0),
        "abuseipdb.refresh_seconds",
        3600.0,
    )


def apply_toml_config(cfg: dict) -> None:
    """Apply a configuration atomically from the daemon's perspective.

    The parser below updates module-level policy tables used by the daemon. If
    any field fails validation, restore every config global so a failed SIGHUP
    cannot leave a partially applied policy.
    """
    snapshot = {
        name: (value, copy.deepcopy(value))
        for name, value in globals().items()
        if name.isupper()
    }
    try:
        _apply_toml_config_in_place(cfg)
    except Exception:
        for name, (original, saved) in snapshot.items():
            if isinstance(original, dict):
                original.clear()
                original.update(saved)
            elif isinstance(original, list):
                original[:] = saved
            elif isinstance(original, set):
                original.clear()
                original.update(saved)
            globals()[name] = original
        raise
