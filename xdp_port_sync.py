#!/usr/bin/env python3
"""Port whitelist auto-sync daemon.

Port discovery  : psutil  (reads /proc directly, no subprocesses)
XDP backend     : bpf(2) syscall via ctypes  (no bpftool)
Fallback        : nftables dynamic sets
Event trigger   : Linux Netlink Process Connector (EXEC/EXIT)
Fallback poll   : periodic scan every --interval seconds (default 30)
"""
from __future__ import annotations

import argparse
import logging
import os
import select
import signal
import time

from auto_xdp import config as cfg
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.discovery import (
    PortState,
    get_listening_ports,
    _net_connections,
)
from auto_xdp.proc_events import open_proc_connector, drain_proc_events
from auto_xdp.backends import NftablesBackend, PortBackend, XdpBackend
from auto_xdp.bpf.maps import render_nft_ports as _render_nft_ports
from auto_xdp.policy import (
    _port_rate_limit,
    _syn_aggregate_rate_limit,
    _tcp_conn_limit,
    _udp_port_rate_limit,
    _udp_aggregate_byte_limit,
)

TOML_CONFIG_PATH = cfg.TOML_CONFIG_PATH
REQUIRED_XDP_MAP_PATHS = cfg.REQUIRED_XDP_MAP_PATHS
BACKEND_AUTO = cfg.BACKEND_AUTO
BACKEND_XDP = cfg.BACKEND_XDP
BACKEND_NFTABLES = cfg.BACKEND_NFTABLES
TCP_PERMANENT = cfg.TCP_PERMANENT
UDP_PERMANENT = cfg.UDP_PERMANENT
SCTP_PERMANENT = cfg.SCTP_PERMANENT
TRUSTED_SRC_IPS = cfg.TRUSTED_SRC_IPS
NFT_FAMILY = cfg.NFT_FAMILY
NFT_TABLE = cfg.NFT_TABLE
NFT_TCP_SET = cfg.NFT_TCP_SET
NFT_UDP_SET = cfg.NFT_UDP_SET
NFT_SCTP_SET = cfg.NFT_SCTP_SET
NFT_TRUSTED_SET4 = cfg.NFT_TRUSTED_SET4
NFT_TRUSTED_SET6 = cfg.NFT_TRUSTED_SET6


# Wait this long after an EXEC/EXIT event before scanning,
# giving the new process time to call bind().
DEBOUNCE_S = 0.4

DEFAULT_LOG_LEVEL = os.environ.get("BASIC_XDP_LOG_LEVEL", "WARNING").upper()

logging.basicConfig(
    level=getattr(logging, DEFAULT_LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def sync_once(backend: PortBackend, dry_run: bool) -> None:
    try:
        all_conns = _net_connections(kind="inet") if (_net_connections is not None) else []
    except Exception:
        all_conns = []
    current = get_listening_ports(cached_conns=all_conns)
    tcp_target = current.tcp | set(TCP_PERMANENT)
    udp_target = current.udp | set(UDP_PERMANENT)
    sctp_target = current.sctp | set(SCTP_PERMANENT)
    trusted_target = set(TRUSTED_SRC_IPS)
    conntrack_target: set[bytes] = set()
    backend.sync_ports(tcp_target, udp_target, sctp_target, trusted_target, conntrack_target, dry_run, cached_conns=all_conns)


def open_backend(name: str) -> PortBackend:
    missing_xdp_maps = [path for path in REQUIRED_XDP_MAP_PATHS if not os.path.exists(path)]

    if name == BACKEND_XDP:
        if missing_xdp_maps:
            raise RuntimeError(f"required XDP maps missing: {', '.join(missing_xdp_maps)}")
        return XdpBackend()
    if name == BACKEND_NFTABLES:
        return NftablesBackend()
    if name != BACKEND_AUTO:
        raise RuntimeError(f"Unsupported backend: {name}")

    if not missing_xdp_maps:
        try:
            backend = XdpBackend()
            log.info("Backend selected: xdp")
            return backend
        except OSError as exc:
            log.warning("XDP backend unavailable (%s); trying nftables.", exc)
    elif missing_xdp_maps:
        log.warning("XDP maps incomplete (%s); trying nftables.", ", ".join(missing_xdp_maps))

    backend = NftablesBackend()
    log.info("Backend selected: nftables")
    return backend


def watch(interval: int, dry_run: bool, backend_name: str, config_path: str = TOML_CONFIG_PATH, cli_trusted_ips: dict[str, str] | None = None, cli_log_level: str | None = None) -> None:
    backend = None
    nl = None

    last_sync_t = 0.0
    last_event_t = 0.0
    reload_requested = False

    def _on_sighup(signum: int, frame: object) -> None:
        nonlocal reload_requested
        reload_requested = True

    signal.signal(signal.SIGHUP, _on_sighup)

    try:
        while True:
            # Re-initialize backend if needed
            if backend is None:
                try:
                    backend = open_backend(backend_name)
                    log.info("Backend initialized.")
                    # Force a sync after (re)initialization
                    sync_once(backend, dry_run)
                    last_sync_t = time.monotonic()
                    last_event_t = 0.0
                except Exception as exc:
                    log.error("Failed to open backend: %s. Retrying in 5s...", exc)
                    time.sleep(5)
                    continue

            # Re-subscribe to netlink if needed
            if nl is None:
                nl = open_proc_connector()

            now = time.monotonic()
            poll_due = last_sync_t + interval
            deb_due = (last_event_t + DEBOUNCE_S) if last_event_t else float("inf")
            sleep_for = max(0.05, min(poll_due, deb_due) - now)

            try:
                if nl and not last_event_t:
                    rdy, _, _ = select.select([nl], [], [], sleep_for)
                    if rdy and drain_proc_events(nl):
                        log.debug("Proc event -> debounce armed.")
                        last_event_t = time.monotonic()
                else:
                    time.sleep(sleep_for)
            except OSError as exc:
                log.warning("Netlink error (%s); switching to poll-only mode.", exc)
                if nl:
                    nl.close()
                nl = None
                continue

            if reload_requested:
                reload_requested = False
                log.warning("SIGHUP received — reloading config from %s", config_path)
                apply_toml_config(load_toml_config(config_path))
                if cli_trusted_ips:
                    TRUSTED_SRC_IPS.update(cli_trusted_ips)
                if cli_log_level is None:
                    _lvl = getattr(logging, cfg.LOG_LEVEL.upper(), logging.WARNING)
                    logging.getLogger().setLevel(_lvl)
                    log.setLevel(_lvl)
                last_sync_t = 0.0  # force sync on next iteration

            now = time.monotonic()
            debounce_fired = bool(last_event_t) and (now - last_event_t >= DEBOUNCE_S)
            fallback_fired = now - last_sync_t >= interval

            if debounce_fired or fallback_fired:
                if nl:
                    drain_proc_events(nl)
                log.debug("Sync triggered by %s.", "event" if debounce_fired else "poll")
                try:
                    sync_once(backend, dry_run)
                except Exception as exc:
                    log.error("Sync error: %s", exc)
                    # If it's a BPF/backend error, reset it for re-init
                    if isinstance(exc, (OSError, RuntimeError)):
                        log.warning("Backend may be broken; will attempt to re-initialize.")
                        backend.close()
                        backend = None

                last_sync_t = time.monotonic()
                last_event_t = 0.0

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        if backend:
            backend.close()


def main() -> None:
    def _parse_trusted_ip(ip_str: str) -> str:
        try:
            return cfg.normalize_cidr(ip_str)
        except ValueError:
            raise argparse.ArgumentTypeError(
                f"invalid IPv4/IPv6 address or CIDR: {ip_str}"
            ) from None

    p = argparse.ArgumentParser(description="Auto XDP port-whitelist sync daemon")
    p.add_argument(
        "--backend",
        choices=[BACKEND_AUTO, BACKEND_XDP, BACKEND_NFTABLES],
        default=BACKEND_AUTO,
        help="Sync backend to use (default: auto)",
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="Run as a daemon (event-driven + fallback poll)",
    )
    p.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Fallback poll interval in seconds (default: 30)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print operations without executing them",
    )
    p.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error"],
        default=None,
        help="Set daemon log level (default: read from config.toml [daemon] log_level)",
    )
    p.add_argument(
        "--trusted-ip",
        action="append",
        nargs=2,
        metavar=("IP", "LABEL"),
        default=[],
        help="Add a trusted IPv4/IPv6 source IP or CIDR and label (repeatable)",
    )
    p.add_argument(
        "--config",
        default=TOML_CONFIG_PATH,
        metavar="PATH",
        help=f"TOML config file path (default: {TOML_CONFIG_PATH})",
    )
    args = p.parse_args()

    apply_toml_config(load_toml_config(args.config))

    # CLI --log-level wins; fall back to TOML [daemon] log_level.
    effective_level = (args.log_level or cfg.LOG_LEVEL).upper()
    logging.getLogger().setLevel(getattr(logging, effective_level, logging.WARNING))
    log.setLevel(getattr(logging, effective_level, logging.WARNING))

    cli_trusted_ips: dict[str, str] = {}
    try:
        for ip_str, label in args.trusted_ip:
            cidr = _parse_trusted_ip(ip_str)
            TRUSTED_SRC_IPS[cidr] = label
            cli_trusted_ips[cidr] = label
    except argparse.ArgumentTypeError as exc:
        p.error(str(exc))

    backend = None
    try:
        if args.watch:
            watch(args.interval, args.dry_run, args.backend, args.config, cli_trusted_ips, cli_log_level=args.log_level)
        else:
            backend = open_backend(args.backend)
            sync_once(backend, args.dry_run)
            log.info("Sync completed.")
    finally:
        if backend is not None:
            backend.close()


if __name__ == "__main__":
    main()
