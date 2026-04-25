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

from auto_xdp import config as cfg
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.syncer import open_backend, sync_once, watch

TOML_CONFIG_PATH = cfg.TOML_CONFIG_PATH
BACKEND_AUTO = cfg.BACKEND_AUTO
BACKEND_XDP = cfg.BACKEND_XDP
BACKEND_NFTABLES = cfg.BACKEND_NFTABLES
TRUSTED_SRC_IPS = cfg.TRUSTED_SRC_IPS


DEFAULT_LOG_LEVEL = os.environ.get("BASIC_XDP_LOG_LEVEL", "WARNING").upper()

logging.basicConfig(
    level=getattr(logging, DEFAULT_LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


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
