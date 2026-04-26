"""CLI entry point for the port-whitelist sync daemon."""
from __future__ import annotations

import argparse
import logging
import os
import sys

from auto_xdp import config as cfg
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.syncer import open_backend, sync_once, watch

log = logging.getLogger(__name__)


def main() -> None:
    DEFAULT_LOG_LEVEL = os.environ.get("BASIC_XDP_LOG_LEVEL", "WARNING").upper()
    logging.basicConfig(
        level=getattr(logging, DEFAULT_LOG_LEVEL, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    bootstrap = argparse.ArgumentParser(add_help=False)
    bootstrap.add_argument(
        "--config",
        default=cfg.TOML_CONFIG_PATH,
        metavar="PATH",
    )
    bootstrap_args, _ = bootstrap.parse_known_args(sys.argv[1:])
    apply_toml_config(load_toml_config(bootstrap_args.config))

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
        choices=[cfg.BACKEND_AUTO, cfg.BACKEND_XDP, cfg.BACKEND_NFTABLES],
        default=cfg.PREFERRED_BACKEND,
        help=f"Sync backend to use (default: {cfg.PREFERRED_BACKEND})",
    )
    p.add_argument(
        "--watch",
        action="store_true",
        help="Run as a daemon (event-driven reconciliation)",
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
        default=cfg.TOML_CONFIG_PATH,
        metavar="PATH",
        help=f"TOML config file path (default: {cfg.TOML_CONFIG_PATH})",
    )
    args = p.parse_args()

    # CLI --log-level wins; fall back to TOML [daemon] log_level.
    effective_level = (args.log_level or cfg.LOG_LEVEL).upper()
    logging.getLogger().setLevel(getattr(logging, effective_level, logging.WARNING))
    log.setLevel(getattr(logging, effective_level, logging.WARNING))

    cli_trusted_ips: dict[str, str] = {}
    try:
        for ip_str, label in args.trusted_ip:
            cidr = _parse_trusted_ip(ip_str)
            cfg.TRUSTED_SRC_IPS[cidr] = label
            cli_trusted_ips[cidr] = label
    except argparse.ArgumentTypeError as exc:
        p.error(str(exc))

    backend = None
    try:
        if args.watch:
            watch(
                args.dry_run, args.backend, args.config,
                cli_trusted_ips, cli_log_level=args.log_level,
            )
        else:
            backend = open_backend(args.backend)
            sync_once(backend, args.dry_run)
            log.info("Sync completed.")
    finally:
        if backend is not None:
            backend.close()
