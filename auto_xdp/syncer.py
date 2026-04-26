"""Sync orchestration: one-shot sync and event-driven daemon loop."""
from __future__ import annotations

import logging
import select
import signal
import time

from auto_xdp import config as cfg
from auto_xdp.backends import NftablesBackend, PortBackend, XdpBackend
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.discovery import _net_connections, get_listening_ports
from auto_xdp.policy import resolve_desired_state
from auto_xdp.proc_events import drain_proc_events, open_proc_connector

log = logging.getLogger(__name__)

TOML_CONFIG_PATH = cfg.TOML_CONFIG_PATH
BACKEND_AUTO = cfg.BACKEND_AUTO
BACKEND_XDP = cfg.BACKEND_XDP
BACKEND_NFTABLES = cfg.BACKEND_NFTABLES
TRUSTED_SRC_IPS = cfg.TRUSTED_SRC_IPS


def observe_system_state():
    try:
        all_conns = _net_connections(kind="inet") if (_net_connections is not None) else []
    except Exception:
        all_conns = []
    return get_listening_ports(cached_conns=all_conns)


def sync_once(backend: PortBackend, dry_run: bool) -> None:
    observed = observe_system_state()
    desired = resolve_desired_state(observed)
    backend.reconcile(desired, dry_run, observed)


def _format_backend_status(status) -> str:
    return status.format_message()


def _probe_backend(backend_cls: type[PortBackend]):
    status = backend_cls.probe()
    if status.available:
        return status
    log.warning("%s backend unavailable (%s).", status.name, _format_backend_status(status))
    return status


def open_backend(name: str) -> PortBackend:
    if name == BACKEND_XDP:
        status = XdpBackend.probe()
        if not status.available:
            raise RuntimeError(_format_backend_status(status))
        return XdpBackend()
    if name == BACKEND_NFTABLES:
        status = NftablesBackend.probe()
        if not status.available:
            raise RuntimeError(_format_backend_status(status))
        return NftablesBackend()
    if name != BACKEND_AUTO:
        raise RuntimeError(f"Unsupported backend: {name}")

    xdp_status = _probe_backend(XdpBackend)
    if xdp_status.available:
        backend = XdpBackend()
        log.info("Backend selected: xdp")
        return backend

    nft_status = _probe_backend(NftablesBackend)
    if not nft_status.available:
        raise RuntimeError(_format_backend_status(nft_status))
    backend = NftablesBackend()
    log.info("Backend selected: nftables")
    return backend


def watch(
    dry_run: bool,
    backend_name: str,
    config_path: str = TOML_CONFIG_PATH,
    cli_trusted_ips: dict[str, str] | None = None,
    cli_log_level: str | None = None,
) -> None:
    backend = None
    nl = None

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
                    sync_once(backend, dry_run)
                    last_event_t = 0.0
                except Exception as exc:
                    log.error("Failed to open backend: %s. Retrying in 5s...", exc)
                    time.sleep(5)
                    continue

            # Re-subscribe to netlink if needed
            if nl is None:
                nl = open_proc_connector()
                if nl is None:
                    time.sleep(5)
                    continue

            debounce_s = cfg.DEBOUNCE_SECONDS
            timeout = max(0.05, debounce_s - (time.monotonic() - last_event_t)) if last_event_t else 1.0

            try:
                rdy, _, _ = select.select([nl], [], [], timeout)
                if rdy and drain_proc_events(nl):
                    log.debug("Proc event -> debounce armed.")
                    last_event_t = time.monotonic()
            except OSError as exc:
                log.warning("Netlink error (%s); reconnecting proc connector.", exc)
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
                last_event_t = time.monotonic() - cfg.DEBOUNCE_SECONDS

            if last_event_t and (time.monotonic() - last_event_t >= cfg.DEBOUNCE_SECONDS):
                if nl:
                    drain_proc_events(nl)
                log.debug("Sync triggered by event.")
                try:
                    sync_once(backend, dry_run)
                except Exception as exc:
                    log.error("Sync error: %s", exc)
                    if isinstance(exc, (OSError, RuntimeError)):
                        log.warning("Backend may be broken; will attempt to re-initialize.")
                        backend.close()
                        backend = None

                last_event_t = 0.0

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        if backend:
            backend.close()
