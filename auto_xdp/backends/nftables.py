"""nftables fallback backend."""
from __future__ import annotations

import logging
import shutil
import subprocess

from auto_xdp import config as cfg
from auto_xdp.backends.base import PortBackend
from auto_xdp.bpf.maps import (
    render_nft_addrs as _render_nft_addrs,
    render_nft_ports as _render_nft_ports,
    run_nft as _run_nft,
)

log = logging.getLogger(__name__)


class NftablesBackend(PortBackend):
    name = cfg.BACKEND_NFTABLES

    def __init__(self) -> None:
        if shutil.which("nft") is None:
            raise RuntimeError("nft command not found")
        self._tcp_cache: set[int] = set()
        self._udp_cache: set[int] = set()
        self._sctp_cache: set[int] = set()
        self._trusted_cache: set[str] = set()
        self._ensure_ruleset()

    def _ensure_ruleset(self) -> None:
        result = _run_nft(["list", "table", cfg.NFT_FAMILY, cfg.NFT_TABLE], check=False)
        if result.returncode == 0:
            body = result.stdout
            if all(marker in body for marker in (
                f"set {cfg.NFT_TCP_SET}", f"set {cfg.NFT_UDP_SET}", f"set {cfg.NFT_SCTP_SET}",
                f"set {cfg.NFT_TRUSTED_SET4}", "chain input",
            )):
                return
            _run_nft(["delete", "table", cfg.NFT_FAMILY, cfg.NFT_TABLE], check=True)

        script = f"""table {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {{
    set {cfg.NFT_TCP_SET} {{
        type inet_service
    }}

    set {cfg.NFT_UDP_SET} {{
        type inet_service
    }}

    set {cfg.NFT_SCTP_SET} {{
        type inet_service
    }}

    set {cfg.NFT_TRUSTED_SET4} {{
        type ipv4_addr
        flags interval
    }}

    set {cfg.NFT_TRUSTED_SET6} {{
        type ipv6_addr
        flags interval
    }}

    chain input {{
        type filter hook input priority filter; policy accept;
        iifname "lo" accept
        ct state established,related accept
        ip saddr @{cfg.NFT_TRUSTED_SET4} accept
        ip6 saddr @{cfg.NFT_TRUSTED_SET6} accept
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept
        tcp flags & (ack | rst | fin) != 0 accept
        tcp flags & (syn | ack) == syn tcp dport @{cfg.NFT_TCP_SET} accept
        udp sport {{ 53, 67, 123, 443, 547 }} accept
        udp dport @{cfg.NFT_UDP_SET} accept
        sctp dport @{cfg.NFT_SCTP_SET} accept
        counter drop
    }}
}}
"""
        _run_nft(["-f", "-"], input_text=script, check=True)

    def _apply_targets(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        sctp_target: set[int],
        dry_run: bool,
    ) -> None:
        lines = [
            f"flush set {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TCP_SET}",
            f"flush set {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_UDP_SET}",
            f"flush set {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_SCTP_SET}",
        ]
        if tcp_target:
            lines.append(
                f"add element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TCP_SET} {_render_nft_ports(tcp_target)}"
            )
        if udp_target:
            lines.append(
                f"add element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_UDP_SET} {_render_nft_ports(udp_target)}"
            )
        if sctp_target:
            lines.append(
                f"add element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_SCTP_SET} {_render_nft_ports(sctp_target)}"
            )
        script = "\n".join(lines) + "\n"

        if dry_run:
            for line in lines:
                log.info("[DRY] nft %s", line)
            return

        try:
            _run_nft(["-f", "-"], input_text=script, check=True)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else str(exc)
            raise RuntimeError(f"nftables update failed: {stderr}") from exc

    def _apply_trusted(self, trusted_target: set[str], dry_run: bool) -> None:
        v4 = {a for a in trusted_target if ":" not in a}
        v6 = {a for a in trusted_target if ":" in a}
        lines = [
            f"flush set {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TRUSTED_SET4}",
            f"flush set {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TRUSTED_SET6}",
        ]
        if v4:
            lines.append(
                f"add element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TRUSTED_SET4} {_render_nft_addrs(v4)}"
            )
        if v6:
            lines.append(
                f"add element {cfg.NFT_FAMILY} {cfg.NFT_TABLE} {cfg.NFT_TRUSTED_SET6} {_render_nft_addrs(v6)}"
            )
        script = "\n".join(lines) + "\n"
        if dry_run:
            for line in lines:
                log.info("[DRY] nft %s", line)
            return
        try:
            _run_nft(["-f", "-"], input_text=script, check=True)
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else str(exc)
            raise RuntimeError(f"nftables trusted-ip update failed: {stderr}") from exc

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        sctp_target: set[int],
        trusted_target: set[str],
        conntrack_target: set[bytes],
        dry_run: bool,
        cached_conns=None,
    ) -> None:
        changed = False
        _ = conntrack_target  # kernel conntrack handles established flows natively

        for ip_str in sorted(trusted_target - self._trusted_cache):
            tag = f" [{cfg.TRUSTED_SRC_IPS[ip_str]}]" if ip_str in cfg.TRUSTED_SRC_IPS else ""
            log.info("TRUST +%s%s", ip_str, tag)
            changed = True
        for ip_str in sorted(self._trusted_cache - trusted_target):
            log.info("TRUST -%s  (removed)", ip_str)
            changed = True

        for port in sorted(tcp_target - self._tcp_cache):
            tag = f" [{cfg.TCP_PERMANENT[port]}]" if port in cfg.TCP_PERMANENT else ""
            log.info("TCP +%d%s", port, tag)
            changed = True
        for port in sorted(self._tcp_cache - tcp_target - set(cfg.TCP_PERMANENT)):
            log.info("TCP -%d  (stopped)", port)
            changed = True

        for port in sorted(udp_target - self._udp_cache):
            tag = f" [{cfg.UDP_PERMANENT[port]}]" if port in cfg.UDP_PERMANENT else ""
            log.info("UDP +%d%s", port, tag)
            changed = True
        for port in sorted(self._udp_cache - udp_target - set(cfg.UDP_PERMANENT)):
            log.info("UDP -%d  (stopped)", port)
            changed = True

        for port in sorted(sctp_target - self._sctp_cache):
            tag = f" [{cfg.SCTP_PERMANENT[port]}]" if port in cfg.SCTP_PERMANENT else ""
            log.info("SCTP +%d%s", port, tag)
            changed = True
        for port in sorted(self._sctp_cache - sctp_target - set(cfg.SCTP_PERMANENT)):
            log.info("SCTP -%d  (stopped)", port)
            changed = True

        self._apply_targets(tcp_target, udp_target, sctp_target, dry_run)
        self._apply_trusted(trusted_target, dry_run)
        self._tcp_cache = set(tcp_target)
        self._udp_cache = set(udp_target)
        self._sctp_cache = set(sctp_target)
        self._trusted_cache = set(trusted_target)

        if not changed:
            log.debug("Whitelist up-to-date.")
