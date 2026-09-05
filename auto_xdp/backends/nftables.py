"""nftables fallback backend.

The fallback shares Auto XDP's desired policy model, but applies it as one
versioned nftables transaction.  A complete replacement avoids transient
half-applied policy when ports, ACLs, and rate limits change together.
"""
from __future__ import annotations

import ipaddress
import logging
import math
import re
import shutil
import subprocess
from typing import cast

from auto_xdp import config as cfg
from auto_xdp.backends.base import BackendStatus, PortBackend
from auto_xdp.bpf.maps import run_nft as _run_nft
from auto_xdp.state import AppliedState, DesiredState, ObservedState, ReconcilePlan

log = logging.getLogger(__name__)

_NFT_SCHEMA_MARKER = "policy_schema_v2"
_BOGON_V4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
_BOGON_V6 = (
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)


def _set_block(name: str, value_type: str, elements: list[str], *, interval: bool = False) -> str:
    lines = [f"    set {name} {{", f"        type {value_type}"]
    if interval:
        lines.append("        flags interval")
    if elements:
        lines.append(f"        elements = {{ {', '.join(elements)} }}")
    lines.append("    }")
    return "\n".join(lines)


def _rate(value: int | float) -> int:
    return max(1, int(math.ceil(value)))


def _prefix_mask(family: int, prefix: int) -> str:
    bits = 32 if family == 4 else 128
    prefix = max(0, min(bits, prefix))
    network = ipaddress.ip_network(f"0.0.0.0/{prefix}" if family == 4 else f"::/{prefix}")
    return str(network.netmask)


def _collapse_cidrs(cidrs: list[str]) -> list[str]:
    networks = [ipaddress.ip_network(cidr) for cidr in cidrs]
    v4 = [network for network in networks if isinstance(network, ipaddress.IPv4Network)]
    v6 = [network for network in networks if isinstance(network, ipaddress.IPv6Network)]
    collapsed = list(ipaddress.collapse_addresses(v4))
    # Typeshed exposes only the IPv4 overload here; both families are valid at
    # runtime, and the v4/v6 split above keeps them from being mixed.
    collapsed.extend(
        ipaddress.collapse_addresses(cast(list[ipaddress.IPv4Network], v6))
    )
    return [str(network) for network in collapsed]


def _policy_signature(desired: DesiredState) -> tuple[object, ...]:
    return (
        frozenset(desired.tcp_ports),
        frozenset(desired.udp_ports),
        frozenset(desired.sctp_ports),
        frozenset(desired.trusted_cidrs),
        tuple(sorted((zone, tuple(sorted(ports))) for zone, ports in desired.zone_tcp_ports.items())),
        tuple(sorted((zone, tuple(sorted(ports))) for zone, ports in desired.zone_udp_ports.items())),
        tuple(sorted(desired.tcp_syn_rate_limits.items())),
        tuple(sorted(desired.tcp_syn_agg_rate_limits.items())),
        tuple(sorted(desired.udp_rate_limits.items())),
        tuple(sorted(desired.udp_agg_rate_limits.items())),
        tuple(sorted((proto, cidr, tuple(sorted(ports))) for (proto, cidr), ports in desired.acl_rules.items())),
        desired.bogon_filter_enabled,
        desired.drop_events_enabled,
        desired.rate_limit_source_prefix_v4,
        desired.rate_limit_source_prefix_v6,
        desired.udp_global_byte_rate,
        tuple(cfg.SIT4_ENDPOINTS),
        cfg.SLOT_DEFAULT_ACTION,
        cfg.NFT_FAMILY,
        cfg.NFT_TABLE,
    )


class NftablesBackend(PortBackend):
    name = cfg.BACKEND_NFTABLES

    @classmethod
    def probe(cls) -> BackendStatus:
        nft_path = shutil.which("nft")
        checks = {"nft": nft_path is not None}
        if nft_path is None:
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="nft command not found",
                details={"nft": "not found"},
                checks=checks,
            )
        return BackendStatus(name=cls.name, available=True, checks=checks)

    def __init__(self) -> None:
        if shutil.which("nft") is None:
            raise RuntimeError("nft command not found")
        self._tcp_cache: set[int] = set()
        self._udp_cache: set[int] = set()
        self._sctp_cache: set[int] = set()
        self._zone_tcp_cache: dict[str, set[int]] = {}
        self._zone_udp_cache: dict[str, set[int]] = {}
        self._trusted_cache: set[str] = set()
        self._reset_policy_cache()
        self._ensure_ruleset()
        self._refresh_caches()

    def _reset_policy_cache(self) -> None:
        self._tcp_syn_rate_cache: dict[int, int] = {}
        self._tcp_syn_agg_rate_cache: dict[int, int] = {}
        self._udp_rate_cache: dict[int, int] = {}
        self._udp_agg_rate_cache: dict[int, int] = {}
        self._acl_cache: dict[tuple[str, str], frozenset[int]] = {}
        self._bogon_cache: bool | None = None
        self._drop_events_cache: bool | None = None
        self._udp_global_byte_rate_cache: int | None = None
        self._policy_signature: tuple[object, ...] | None = None

    def _parse_set_elements(self, body: str) -> list[str]:
        match = re.search(r"elements\s*=\s*\{(.*?)\}", body, re.DOTALL)
        if not match:
            return []
        raw = match.group(1).replace("\n", " ").strip()
        if not raw:
            return []
        return [item.strip() for item in raw.split(",") if item.strip()]

    def _parse_named_set_elements(self, table_body: str, set_name: str) -> list[str]:
        match = re.search(
            rf"\bset\s+{re.escape(set_name)}\s*\{{(.*?)(?=\n\s*\}})",
            table_body,
            re.DOTALL,
        )
        return self._parse_set_elements(match.group(1)) if match else []

    def _list_set_elements(self, set_name: str) -> list[str]:
        result = _run_nft(
            ["list", "set", cfg.NFT_FAMILY, cfg.NFT_TABLE, set_name],
            check=False,
        )
        if result.returncode != 0:
            return []
        return self._parse_set_elements(result.stdout)

    def _refresh_caches(self) -> None:
        self._tcp_cache = {int(item) for item in self._list_set_elements(cfg.NFT_TCP_SET)}
        self._udp_cache = {int(item) for item in self._list_set_elements(cfg.NFT_UDP_SET)}
        self._sctp_cache = {int(item) for item in self._list_set_elements(cfg.NFT_SCTP_SET)}
        self._trusted_cache = set(self._list_set_elements(cfg.NFT_TRUSTED_SET4))
        self._trusted_cache.update(self._list_set_elements(cfg.NFT_TRUSTED_SET6))

    def get_applied_state(self) -> AppliedState:
        return AppliedState(
            tcp_ports=set(self._tcp_cache),
            udp_ports=set(self._udp_cache),
            sctp_ports=set(self._sctp_cache),
            zone_tcp_ports={zone: set(ports) for zone, ports in self._zone_tcp_cache.items()},
            zone_udp_ports={zone: set(ports) for zone, ports in self._zone_udp_cache.items()},
            trusted_cidrs=set(self._trusted_cache),
            tcp_syn_rate_limits=dict(self._tcp_syn_rate_cache),
            tcp_syn_agg_rate_limits=dict(self._tcp_syn_agg_rate_cache),
            udp_rate_limits=dict(self._udp_rate_cache),
            udp_agg_rate_limits=dict(self._udp_agg_rate_cache),
            acl_rules=dict(self._acl_cache),
            bogon_filter_enabled=self._bogon_cache,
            drop_events_enabled=self._drop_events_cache,
            udp_global_byte_rate=self._udp_global_byte_rate_cache,
        )

    def _family_flags(self) -> tuple[bool, bool]:
        return cfg.NFT_FAMILY in {"inet", "ip"}, cfg.NFT_FAMILY in {"inet", "ip6"}

    @staticmethod
    def _zone_ports(desired: DesiredState, proto: str) -> set[int]:
        by_zone = desired.zone_tcp_ports if proto == "tcp" else desired.zone_udp_ports
        return set().union(*(ports for ports in by_zone.values())) if by_zone else set()

    def _zone_rules(self, desired: DesiredState, proto: str) -> list[str]:
        by_zone = desired.zone_tcp_ports if proto == "tcp" else desired.zone_udp_ports
        rules: list[str] = []
        for zone, ports in sorted(by_zone.items()):
            interfaces = [name for name in cfg.ZONES.get(zone, {}).get("interfaces", []) if name != "*"]
            if not interfaces or not ports:
                continue
            names = ", ".join(f'"{name}"' for name in sorted(set(interfaces)))
            rendered_ports = ", ".join(str(port) for port in sorted(ports))
            match = f'iifname {{ {names} }} {proto} dport {{ {rendered_ports} }}'
            if proto == "tcp":
                match += " tcp flags & (syn | ack) == syn"
            rules.append(f"        {match} counter accept")
        return rules

    def _acl_rules(self, desired: DesiredState, proto: str, family: int) -> list[str]:
        result: list[str] = []
        addr_expr = "ip saddr" if family == 4 else "ip6 saddr"
        port_set = cfg.NFT_TCP_SET if proto == "tcp" else cfg.NFT_UDP_SET
        for (rule_proto, cidr), ports in sorted(desired.acl_rules.items()):
            if rule_proto != proto or (":" in cidr) != (family == 6) or not ports:
                continue
            rendered_ports = ", ".join(str(port) for port in sorted(ports))
            if proto == "tcp":
                result.append(
                    f"        {addr_expr} {cidr} tcp flags & (syn | ack) == syn "
                    f"tcp dport @{port_set} tcp dport {{ {rendered_ports} }} counter accept"
                )
            else:
                result.append(
                    f"        {addr_expr} {cidr} udp dport @{port_set} "
                    f"udp dport {{ {rendered_ports} }} counter accept"
                )
        return result

    def _tcp_policy_rules(self, desired: DesiredState, family: int) -> list[str]:
        addr_expr = "ip saddr" if family == 4 else "ip6 saddr"
        prefix = (
            desired.rate_limit_source_prefix_v4
            if family == 4
            else desired.rate_limit_source_prefix_v6
        )
        mask = _prefix_mask(family, prefix)
        rules: list[str] = []
        for port in sorted(set(desired.tcp_ports) | self._zone_ports(desired, "tcp")):
            per_src = desired.tcp_syn_rate_limits.get(port, 0)
            if per_src > 0:
                rate = _rate(per_src)
                rules.append(
                    f"        tcp dport {port} tcp flags & (syn | ack) == syn "
                    f"meter ts{family}_{port} {{ {addr_expr} limit rate over {rate}/second "
                    f"burst {rate} packets }} counter drop"
                )
            per_prefix = desired.tcp_syn_agg_rate_limits.get(port, 0)
            if per_prefix > 0:
                rate = _rate(per_prefix)
                rules.append(
                    f"        tcp dport {port} tcp flags & (syn | ack) == syn "
                    f"meter tp{family}_{port} {{ {addr_expr} & {mask} limit rate over {rate}/second "
                    f"burst {rate} packets }} counter drop"
                )
        return rules

    def _udp_policy_rules(self, desired: DesiredState, family: int) -> list[str]:
        addr_expr = "ip saddr" if family == 4 else "ip6 saddr"
        prefix = (
            desired.rate_limit_source_prefix_v4
            if family == 4
            else desired.rate_limit_source_prefix_v6
        )
        mask = _prefix_mask(family, prefix)
        rules: list[str] = []
        for port in sorted(set(desired.udp_ports) | self._zone_ports(desired, "udp")):
            per_src = desired.udp_rate_limits.get(port, 0)
            if per_src > 0:
                rate = _rate(per_src)
                rules.append(
                    f"        udp dport {port} meter us{family}_{port} "
                    f"{{ {addr_expr} limit rate over {rate}/second burst {rate} packets }} counter drop"
                )
            per_prefix = desired.udp_agg_rate_limits.get(port, 0)
            if per_prefix > 0:
                rate = _rate(per_prefix)
                rules.append(
                    f"        udp dport {port} meter up{family}_{port} "
                    f"{{ {addr_expr} & {mask} limit rate over {rate} bytes/second "
                    f"burst {rate} bytes }} counter drop"
                )
        return rules

    def _render_ruleset(self, desired: DesiredState, *, replace: bool) -> str:
        has_v4, has_v6 = self._family_flags()
        trusted_v4 = _collapse_cidrs(sorted(cidr for cidr in desired.trusted_cidrs if ":" not in cidr))
        trusted_v6 = _collapse_cidrs(sorted(cidr for cidr in desired.trusted_cidrs if ":" in cidr))
        blocks = [
            _set_block(_NFT_SCHEMA_MARKER, "mark", []),
            _set_block(cfg.NFT_TCP_SET, "inet_service", [str(port) for port in sorted(desired.tcp_ports)]),
            _set_block(cfg.NFT_UDP_SET, "inet_service", [str(port) for port in sorted(desired.udp_ports)]),
            _set_block(cfg.NFT_SCTP_SET, "inet_service", [str(port) for port in sorted(desired.sctp_ports)]),
            _set_block(cfg.NFT_TRUSTED_SET4, "ipv4_addr", trusted_v4, interval=True),
            _set_block(cfg.NFT_TRUSTED_SET6, "ipv6_addr", trusted_v6, interval=True),
        ]
        if has_v4 and desired.bogon_filter_enabled:
            blocks.append(_set_block("bogon_v4", "ipv4_addr", list(_BOGON_V4), interval=True))
        if has_v6 and desired.bogon_filter_enabled:
            blocks.append(_set_block("bogon_v6", "ipv6_addr", list(_BOGON_V6), interval=True))
        rules = [
            "        iifname \"lo\" counter accept",
        ]
        if has_v4:
            rules.append("        ip frag-off & 0x3fff != 0 counter drop")
        if has_v6:
            rules.append("        exthdr frag exists counter drop")
        if has_v4 and desired.bogon_filter_enabled:
            rules.append("        ip saddr @bogon_v4 counter drop")
        if has_v6 and desired.bogon_filter_enabled:
            rules.append("        ip6 saddr @bogon_v6 counter drop")

        rules.extend(
            [
                "        tcp sport 0 counter drop",
                "        tcp dport 0 counter drop",
                "        tcp flags == 0 counter drop",
                "        tcp flags & (syn | fin) == (syn | fin) counter drop",
                "        tcp flags & (syn | rst) == (syn | rst) counter drop",
                "        tcp flags & (rst | fin) == (rst | fin) counter drop",
                "        tcp flags & (fin | psh | urg) == (fin | psh | urg) counter drop",
                "        udp sport 0 counter drop",
                "        udp dport 0 counter drop",
                "        udp length < 8 counter drop",
                "        ct state invalid counter drop",
                "        ct state established,related counter accept",
            ]
        )

        if has_v4:
            rules.append(
                f"        ip saddr @{cfg.NFT_TRUSTED_SET4} tcp dport @{cfg.NFT_TCP_SET} "
                "tcp flags & (syn | ack) == syn counter accept"
            )
            rules.extend(self._acl_rules(desired, "tcp", 4))
        if has_v6:
            rules.append(
                f"        ip6 saddr @{cfg.NFT_TRUSTED_SET6} tcp dport @{cfg.NFT_TCP_SET} "
                "tcp flags & (syn | ack) == syn counter accept"
            )
            rules.extend(self._acl_rules(desired, "tcp", 6))
        if has_v4:
            rules.extend(self._tcp_policy_rules(desired, 4))
        if has_v6:
            rules.extend(self._tcp_policy_rules(desired, 6))
        rules.extend(self._zone_rules(desired, "tcp"))
        rules.extend(
            [
                f"        tcp flags & (syn | ack) == syn tcp dport @{cfg.NFT_TCP_SET} counter accept",
                "        meta l4proto tcp counter drop",
            ]
        )

        if has_v4:
            rules.append(f"        ip saddr @{cfg.NFT_TRUSTED_SET4} udp dport @{cfg.NFT_UDP_SET} counter accept")
            rules.extend(self._acl_rules(desired, "udp", 4))
        if has_v6:
            rules.append(f"        ip6 saddr @{cfg.NFT_TRUSTED_SET6} udp dport @{cfg.NFT_UDP_SET} counter accept")
            rules.extend(self._acl_rules(desired, "udp", 6))
        if desired.udp_global_byte_rate > 0:
            rate = _rate(desired.udp_global_byte_rate)
            rules.append(
                f"        udp dport @{cfg.NFT_UDP_SET} limit rate over {rate} bytes/second "
                f"burst {rate} bytes counter drop"
            )
        if has_v4:
            rules.extend(self._udp_policy_rules(desired, 4))
        if has_v6:
            rules.extend(self._udp_policy_rules(desired, 6))
        rules.extend(self._zone_rules(desired, "udp"))
        rules.extend(
            [
                f"        udp dport @{cfg.NFT_UDP_SET} counter accept",
                "        meta l4proto udp counter drop",
                f"        sctp dport @{cfg.NFT_SCTP_SET} counter accept",
                "        meta l4proto sctp counter drop",
            ]
        )

        icmp_rate = _rate(cfg.XDP_ICMP_RATE_PPS) if cfg.XDP_ICMP_RATE_PPS > 0 else 0
        icmp_burst = max(1, cfg.XDP_ICMP_BURST_PACKETS)
        if has_v4:
            rules.append(
                "        ip protocol icmp icmp type { destination-unreachable, "
                "time-exceeded, parameter-problem } counter accept"
            )
            rules.append(f"        ip saddr @{cfg.NFT_TRUSTED_SET4} ip protocol icmp counter accept")
            if icmp_rate:
                rules.append(
                    f"        ip protocol icmp icmp type echo-request limit rate over {icmp_rate}/second "
                    f"burst {icmp_burst} packets counter drop"
                )
            rules.append("        ip protocol icmp counter accept")
        if has_v6:
            rules.append(f"        ip6 saddr @{cfg.NFT_TRUSTED_SET6} meta l4proto ipv6-icmp counter accept")
            if icmp_rate:
                rules.append(
                    f"        meta l4proto ipv6-icmp icmpv6 type echo-request limit rate over {icmp_rate}/second "
                    f"burst {icmp_burst} packets counter drop"
                )
            rules.append("        meta l4proto ipv6-icmp counter accept")

        if has_v4 and cfg.SIT4_ENDPOINTS:
            endpoints = ", ".join(sorted(cfg.SIT4_ENDPOINTS))
            rules.append(f"        ip protocol ipv6 ip saddr {{ {endpoints} }} counter accept")
            rules.append("        ip protocol ipv6 counter drop")

        if cfg.SLOT_DEFAULT_ACTION == "drop":
            rules.append("        counter drop")
        else:
            rules.append("        counter accept")

        prefix = f"delete table {cfg.NFT_FAMILY} {cfg.NFT_TABLE}\n" if replace else ""
        body = "\n\n".join(blocks)
        chain = "\n".join(rules)
        return (
            f"{prefix}table {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {{\n"
            f"{body}\n\n"
            "    chain input {\n"
            "        type filter hook input priority filter; policy accept;\n"
            f"{chain}\n"
            "    }\n"
            "}\n"
        )

    def _install_ruleset(self, desired: DesiredState, *, replace: bool, dry_run: bool = False) -> None:
        script = self._render_ruleset(desired, replace=replace)
        if dry_run:
            for line in script.splitlines():
                log.info("[DRY] nft %s", line)
            return
        try:
            _run_nft(["-f", "-"], input_text=script, check=True)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else str(exc)
            raise RuntimeError(f"nftables policy transaction failed: {stderr}") from exc

    def _ensure_ruleset(self) -> None:
        result = _run_nft(["list", "table", cfg.NFT_FAMILY, cfg.NFT_TABLE], check=False)
        exists = result.returncode == 0
        if exists and all(
            marker in result.stdout
            for marker in (
                f"set {_NFT_SCHEMA_MARKER}",
                f"set {cfg.NFT_TCP_SET}",
                f"set {cfg.NFT_UDP_SET}",
                f"set {cfg.NFT_SCTP_SET}",
                f"set {cfg.NFT_TRUSTED_SET4}",
                "chain input",
            )
        ):
            return
        bootstrap = DesiredState(bogon_filter_enabled=cfg.BOGON_FILTER_ENABLED)
        if exists:
            # Preserve the old admission sets during the v1 -> v2 migration.
            # The next normal reconcile fills in rate limits and ACL policy,
            # but active listener/trust state never passes through an empty
            # generation.
            bootstrap.tcp_ports = {
                int(item)
                for item in self._parse_named_set_elements(result.stdout, cfg.NFT_TCP_SET)
            }
            bootstrap.udp_ports = {
                int(item)
                for item in self._parse_named_set_elements(result.stdout, cfg.NFT_UDP_SET)
            }
            bootstrap.sctp_ports = {
                int(item)
                for item in self._parse_named_set_elements(result.stdout, cfg.NFT_SCTP_SET)
            }
            bootstrap.trusted_cidrs = set(
                self._parse_named_set_elements(result.stdout, cfg.NFT_TRUSTED_SET4)
            )
            bootstrap.trusted_cidrs.update(
                self._parse_named_set_elements(result.stdout, cfg.NFT_TRUSTED_SET6)
            )
        self._install_ruleset(bootstrap, replace=exists)

    def _remember_desired(self, desired: DesiredState) -> None:
        self._tcp_cache = set(desired.tcp_ports)
        self._udp_cache = set(desired.udp_ports)
        self._sctp_cache = set(desired.sctp_ports)
        self._zone_tcp_cache = {zone: set(ports) for zone, ports in desired.zone_tcp_ports.items()}
        self._zone_udp_cache = {zone: set(ports) for zone, ports in desired.zone_udp_ports.items()}
        self._trusted_cache = set(desired.trusted_cidrs)
        self._tcp_syn_rate_cache = dict(desired.tcp_syn_rate_limits)
        self._tcp_syn_agg_rate_cache = dict(desired.tcp_syn_agg_rate_limits)
        self._udp_rate_cache = dict(desired.udp_rate_limits)
        self._udp_agg_rate_cache = dict(desired.udp_agg_rate_limits)
        self._acl_cache = dict(desired.acl_rules)
        self._bogon_cache = desired.bogon_filter_enabled
        self._drop_events_cache = desired.drop_events_enabled
        self._udp_global_byte_rate_cache = desired.udp_global_byte_rate
        self._policy_signature = _policy_signature(desired)

    def apply_reconcile_plan(
        self,
        plan: ReconcilePlan,
        dry_run: bool,
        desired_state: DesiredState,
        observed_state: ObservedState | None = None,
    ) -> None:
        _ = plan, observed_state  # native conntrack owns established-flow state
        signature = _policy_signature(desired_state)
        if signature == self._policy_signature:
            log.debug("nftables policy up-to-date.")
            return

        # A single nft batch validates the complete candidate and commits it
        # atomically.  If parsing or kernel validation fails, the old table is
        # retained by the nftables transaction engine.
        self._install_ruleset(desired_state, replace=True, dry_run=dry_run)
        if not dry_run:
            self._remember_desired(desired_state)
            log.info("Applied complete nftables fallback policy transaction.")
