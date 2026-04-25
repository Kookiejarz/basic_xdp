from __future__ import annotations

import ipaddress
import logging

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]


log = logging.getLogger(__name__)

TOML_CONFIG_PATH = "/etc/auto_xdp/config.toml"

TCP_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_whitelist"
UDP_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_whitelist"
SCTP_MAP_PATH = "/sys/fs/bpf/xdp_fw/sctp_whitelist"
TCP_CONNTRACK_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_conntrack"
TRUSTED_IPS_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/trusted_ipv4"
TRUSTED_IPS_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/trusted_ipv6"
SYN_RATE_MAP_PATH = "/sys/fs/bpf/xdp_fw/syn_rate_ports"
UDP_RATE_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_rate_ports"
SYN_AGG_RATE_MAP_PATH = "/sys/fs/bpf/xdp_fw/syn_agg_rate_ports"
TCP_CONN_LIMIT_MAP_PATH = "/sys/fs/bpf/xdp_fw/tcp_conn_limit_ports"
UDP_AGG_RATE_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_agg_rate_ports"
UDP_GLOBAL_RL_MAP_PATH = "/sys/fs/bpf/xdp_fw/udp_global_rl"
BOGON_CFG_MAP_PATH = "/sys/fs/bpf/xdp_fw/bogon_cfg"
TCP_ACL_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/tcp_acl_v4"
TCP_ACL_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/tcp_acl_v6"
UDP_ACL_MAP_PATH4 = "/sys/fs/bpf/xdp_fw/udp_acl_v4"
UDP_ACL_MAP_PATH6 = "/sys/fs/bpf/xdp_fw/udp_acl_v6"
REQUIRED_XDP_MAP_PATHS = (
    TCP_MAP_PATH,
    UDP_MAP_PATH,
    TCP_CONNTRACK_MAP_PATH,
    TRUSTED_IPS_MAP_PATH4,
    TRUSTED_IPS_MAP_PATH6,
)

_SYN_RATE_BY_PROC: dict[str, int] = {}
_SYN_RATE_BY_SERVICE: dict[str, int] = {}
_SYN_AGG_RATE_BY_PROC: dict[str, int] = {}
_SYN_AGG_RATE_BY_SERVICE: dict[str, int] = {}
_TCP_CONN_BY_PROC: dict[str, int] = {}
_TCP_CONN_BY_SERVICE: dict[str, int] = {}
_UDP_RATE_BY_PROC: dict[str, int] = {}
_UDP_RATE_BY_SERVICE: dict[str, int] = {}
_UDP_AGG_BYTES_BY_PROC: dict[str, int] = {}
_UDP_AGG_BYTES_BY_SERVICE: dict[str, int] = {}

BOGON_FILTER_ENABLED = True
LOG_LEVEL: str = "warning"
DISCOVERY_EXCLUDE_LOOPBACK = True
DISCOVERY_EXCLUDE_BIND_CIDRS: list[str] = []

NFT_FAMILY = "inet"
NFT_TABLE = "auto_xdp"
NFT_TCP_SET = "tcp_ports"
NFT_UDP_SET = "udp_ports"
NFT_SCTP_SET = "sctp_ports"
NFT_TRUSTED_SET4 = "trusted_v4"
NFT_TRUSTED_SET6 = "trusted_v6"

BACKEND_AUTO = "auto"
BACKEND_XDP = "xdp"
BACKEND_NFTABLES = "nftables"

TCP_PERMANENT: dict[int, str] = {}
UDP_PERMANENT: dict[int, str] = {}
SCTP_PERMANENT: dict[int, str] = {}
TRUSTED_SRC_IPS: dict[str, str] = {}
ACL_RULES: list[dict] = []

ACL_MAX_PORTS = 64
ACL_VAL_SIZE = 4 + ACL_MAX_PORTS * 2


def normalize_cidr(cidr_str: str) -> str:
    if ":" in cidr_str:
        net = ipaddress.IPv6Network(cidr_str, strict=False)
    else:
        net = ipaddress.IPv4Network(cidr_str, strict=False)
    return f"{net.network_address}/{net.prefixlen}"


def load_toml_config(path: str = TOML_CONFIG_PATH) -> dict:
    if tomllib is None:
        log.debug("tomllib not available; skipping TOML config load.")
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        log.warning("Failed to load %s: %s", path, exc)
        return {}


def apply_toml_config(cfg: dict) -> None:
    global BOGON_FILTER_ENABLED, LOG_LEVEL
    global DISCOVERY_EXCLUDE_LOOPBACK, DISCOVERY_EXCLUDE_BIND_CIDRS

    TCP_PERMANENT.clear()
    UDP_PERMANENT.clear()
    SCTP_PERMANENT.clear()
    TRUSTED_SRC_IPS.clear()
    ACL_RULES.clear()

    _SYN_RATE_BY_PROC.clear()
    _SYN_RATE_BY_SERVICE.clear()
    _SYN_AGG_RATE_BY_PROC.clear()
    _SYN_AGG_RATE_BY_SERVICE.clear()
    _TCP_CONN_BY_PROC.clear()
    _TCP_CONN_BY_SERVICE.clear()
    _UDP_RATE_BY_PROC.clear()
    _UDP_RATE_BY_SERVICE.clear()
    _UDP_AGG_BYTES_BY_PROC.clear()
    _UDP_AGG_BYTES_BY_SERVICE.clear()
    DISCOVERY_EXCLUDE_BIND_CIDRS.clear()

    perm = cfg.get("permanent_ports", {})
    for p in perm.get("tcp", []):
        TCP_PERMANENT[int(p)] = "config"
    for p in perm.get("udp", []):
        UDP_PERMANENT[int(p)] = "config"
    for p in perm.get("sctp", []):
        SCTP_PERMANENT[int(p)] = "config"

    for cidr, label in cfg.get("trusted_ips", {}).items():
        TRUSTED_SRC_IPS[normalize_cidr(cidr)] = str(label)

    for rule in cfg.get("acl", []):
        ACL_RULES.append({
            "proto": rule["proto"],
            "cidr": normalize_cidr(rule["cidr"]),
            "ports": [int(p) for p in rule.get("ports", [])],
        })

    rl = cfg.get("rate_limits", {})
    _SYN_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("syn_by_proc", {}).items()})
    _SYN_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("syn_by_service", {}).items()})
    _SYN_AGG_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("syn_agg_by_proc", {}).items()})
    _SYN_AGG_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("syn_agg_by_service", {}).items()})
    _TCP_CONN_BY_PROC.update({k: int(v) for k, v in rl.get("tcp_conn_by_proc", {}).items()})
    _TCP_CONN_BY_SERVICE.update({k: int(v) for k, v in rl.get("tcp_conn_by_service", {}).items()})
    _UDP_RATE_BY_PROC.update({k: int(v) for k, v in rl.get("udp_by_proc", {}).items()})
    _UDP_RATE_BY_SERVICE.update({k: int(v) for k, v in rl.get("udp_by_service", {}).items()})
    _UDP_AGG_BYTES_BY_PROC.update({k: int(v) for k, v in rl.get("udp_agg_bytes_by_proc", {}).items()})
    _UDP_AGG_BYTES_BY_SERVICE.update({k: int(v) for k, v in rl.get("udp_agg_bytes_by_service", {}).items()})

    BOGON_FILTER_ENABLED = bool(cfg.get("firewall", {}).get("bogon_filter", True))
    LOG_LEVEL = cfg.get("daemon", {}).get("log_level", "warning").lower()

    discovery = cfg.get("discovery", {})
    DISCOVERY_EXCLUDE_LOOPBACK = bool(discovery.get("exclude_loopback", True))
    DISCOVERY_EXCLUDE_BIND_CIDRS.extend(
        normalize_cidr(cidr) for cidr in discovery.get("exclude_bind_cidrs", [])
    )
