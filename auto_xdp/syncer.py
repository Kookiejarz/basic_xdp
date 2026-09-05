"""Sync orchestration: one-shot, event-driven, and periodic reconciliation."""
from __future__ import annotations

import json as _json
import logging
import select
import signal
import socket as _socket
import time
from collections.abc import Callable

from auto_xdp import config as cfg
from auto_xdp.backends import NftablesBackend, PortBackend, XdpBackend
from auto_xdp.config import apply_toml_config, load_toml_config
from auto_xdp.discovery import DiscoveryError, get_listening_ports
from auto_xdp.policy import resolve_desired_state
from auto_xdp.proc_events import drain_proc_events, open_proc_connector

log = logging.getLogger(__name__)

TOML_CONFIG_PATH = cfg.TOML_CONFIG_PATH
BACKEND_AUTO = cfg.BACKEND_AUTO
BACKEND_XDP = cfg.BACKEND_XDP
BACKEND_NFTABLES = cfg.BACKEND_NFTABLES
TRUSTED_SRC_IPS = cfg.TRUSTED_SRC_IPS

# Cap debounce so a continuous burst of proc events can't keep deferring sync.
# Without this, busy systems (containers, cron storms) never see a quiet window
# longer than DEBOUNCE_SECONDS and sync stalls for tens of seconds.
DEBOUNCE_MAX_WAIT_SECONDS = 1.0
# A full discovery/reconcile is the safety net for missed proc/socket events.
# Event-triggered reconciles also perform a full discovery, so this interval is
# the maximum time the daemon may go without re-reading the system state.
FULL_RECONCILE_INTERVAL_SECONDS = 30.0
EVENT_SOURCE_RETRY_INTERVAL_SECONDS = 5.0


def observe_system_state():
    return get_listening_ports()


def _reload_config(config_path: str) -> bool:
    """Reload config without disturbing the last known-good configuration."""
    try:
        apply_toml_config(load_toml_config(config_path, strict=True))
    except Exception as exc:
        log.error("Configuration reload failed; retaining previous configuration: %s", exc)
        return False
    return True


def sync_once(
    backend: PortBackend | None,
    dry_run: bool,
    mode: str | None = None,
    explain: bool = False,
) -> dict[str, object]:
    started = time.monotonic()
    observed = observe_system_state()
    desired = resolve_desired_state(observed)
    effective_mode = mode or cfg.POLICY_MODE
    if effective_mode not in {"observe", "audit", "enforce"}:
        raise ValueError(f"Unsupported policy mode: {effective_mode}")
    if explain or desired.exposure_decisions:
        for decision in desired.exposure_decisions:
            endpoint = decision.endpoint
            message = (
                "exposure %s %s/%s %s:%d subject=%s attribution=%s zone=%s reason=%s%s"
                % (
                decision.action.upper(), endpoint.protocol, endpoint.bind_scope,
                endpoint.host_address, endpoint.host_port,
                decision.subject or endpoint.subject or "unknown",
                endpoint.attribution_state, endpoint.ingress_zone, decision.reason,
                f" profile={decision.protection_profile}" if decision.protection_profile else "",
                )
            )
            if explain:
                print(message)
            else:
                log.info(message)
    if effective_mode in {"observe", "audit"}:
        if effective_mode == "audit":
            log.info(
                "exposure audit: %d endpoint(s), %d authorized",
                len(desired.exposure_decisions),
                sum(item.action == "allow" for item in desired.exposure_decisions),
            )
    else:
        if backend is None:
            raise RuntimeError("an enforcement backend is required in enforce mode")
        backend.reconcile(desired, dry_run, observed)
    elapsed = time.monotonic() - started
    log.info(
        "reconciliation mode=%s elapsed_ms=%.3f endpoints=%d effective_ports=%d",
        effective_mode, elapsed * 1000, len(desired.exposure_decisions),
        len(desired.tcp_ports) + len(desired.udp_ports) + len(desired.sctp_ports),
    )
    return {
        "mode": effective_mode,
        "elapsed_seconds": elapsed,
        "observed": observed,
        "desired": desired,
    }


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
        backend: PortBackend = XdpBackend()
        log.info("Backend selected: xdp")
        return backend

    nft_status = _probe_backend(NftablesBackend)
    if not nft_status.available:
        raise RuntimeError(_format_backend_status(nft_status))
    backend = NftablesBackend()
    log.info("Backend selected: nftables")
    return backend


def _open_relay_client(sock_path: str) -> "_socket.socket | None":
    """Connect to pkt_relay Unix socket as a non-blocking subscriber."""
    try:
        s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        s.connect(sock_path)
        s.setblocking(False)
        return s
    except OSError:
        return None


def _drain_relay_lines(
    relay_sock: "_socket.socket",
    pending: bytearray | None = None,
) -> bool:
    """Read available lines from the relay socket.

    Returns True if any port_change event was found.
    Raises ConnectionResetError if the relay closed the connection.
    """
    if pending is None:
        pending = bytearray()
    try:
        while True:
            chunk = relay_sock.recv(4096)
            if not chunk:
                raise ConnectionResetError("relay disconnected")
            pending.extend(chunk)
    except BlockingIOError:
        pass

    found = False
    while (line_end := pending.find(b"\n")) >= 0:
        raw_line = bytes(pending[:line_end])
        del pending[: line_end + 1]
        if not raw_line:
            continue
        try:
            msg = _json.loads(raw_line)
        except _json.JSONDecodeError:
            continue
        if msg.get("type") == "port_change":
            found = True
    return found


def watch(
    dry_run: bool,
    backend_name: str,
    config_path: str = TOML_CONFIG_PATH,
    cli_trusted_ips: dict[str, str] | None = None,
    cli_log_level: str | None = None,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    mode: str | None = None,
    explain: bool = False,
) -> None:
    backend = None
    nl = None

    last_event_t = 0.0
    first_event_t = 0.0
    last_reconcile_t = 0.0
    last_stale_check_t = 0.0
    last_netlink_connect_t = -EVENT_SOURCE_RETRY_INTERVAL_SECONDS
    reload_requested = False
    mode_only_synced = False

    def _on_sighup(signum: int, frame: object) -> None:
        nonlocal reload_requested
        reload_requested = True

    signal.signal(signal.SIGHUP, _on_sighup)

    relay_sock: "_socket.socket | None" = None
    relay_pending = bytearray()
    last_relay_connect_t = -EVENT_SOURCE_RETRY_INTERVAL_SECONDS

    def _sync() -> dict[str, object]:
        if mode is None and not explain:
            return sync_once(backend, dry_run)
        return sync_once(backend, dry_run, mode=mode, explain=explain)

    try:
        while True:
            # Observe/audit are useful without root or an installed backend.
            needs_backend = (mode or cfg.POLICY_MODE) not in {"observe", "audit"}
            if not needs_backend:
                if backend is not None:
                    backend.close()
                    backend = None
                if not mode_only_synced:
                    try:
                        _sync()
                        last_reconcile_t = monotonic()
                        mode_only_synced = True
                    except DiscoveryError as exc:
                        log.error("Initial discovery failed; retrying: %s", exc)
                        last_reconcile_t = monotonic()
                        continue
            # Re-initialize backend if needed
            elif backend is None:
                mode_only_synced = False
                try:
                    backend = open_backend(backend_name)
                    log.info("Backend initialized.")
                    _sync()
                    last_reconcile_t = monotonic()
                    last_event_t = 0.0
                    first_event_t = 0.0
                except DiscoveryError as exc:
                    log.error("Initial discovery failed; keeping existing policy: %s", exc)
                    last_reconcile_t = monotonic()
                    continue
                except (OSError, RuntimeError) as exc:
                    log.error("Failed to open backend: %s. Retrying in 5s...", exc)
                    time.sleep(5)
                    continue

            # Netlink is an optional acceleration path. Failure must not stop
            # relay events, the periodic safety reconcile, GC, or drift checks.
            now_mono = monotonic()
            if (
                nl is None
                and now_mono - last_netlink_connect_t
                >= EVENT_SOURCE_RETRY_INTERVAL_SECONDS
            ):
                nl = open_proc_connector()
                last_netlink_connect_t = now_mono

            # Optionally subscribe to pkt_relay for instant port_change triggers.
            if (
                relay_sock is None
                and now_mono - last_relay_connect_t
                >= EVENT_SOURCE_RETRY_INTERVAL_SECONDS
            ):
                relay_sock = _open_relay_client(cfg.RINGBUF_SOCKET_PATH)
                last_relay_connect_t = now_mono
                if relay_sock:
                    relay_pending.clear()
                    log.info("Connected to pkt_relay for port_change events.")

            debounce_s = cfg.DEBOUNCE_SECONDS
            timeout = max(0.05, debounce_s - (monotonic() - last_event_t)) if last_event_t else 1.0
            if last_reconcile_t:
                until_reconcile = max(
                    0.05,
                    FULL_RECONCILE_INTERVAL_SECONDS
                    - (monotonic() - last_reconcile_t),
                )
                timeout = min(timeout, until_reconcile)

            select_fds = []
            if nl is not None:
                select_fds.append(nl)
            if relay_sock is not None:
                select_fds.append(relay_sock)

            try:
                if select_fds:
                    rdy, _, _ = select.select(select_fds, [], [], timeout)
                else:
                    time.sleep(timeout)
                    rdy = []
                if nl is not None and nl in rdy and drain_proc_events(nl):
                    log.debug("Proc event -> debounce armed.")
                    _now = monotonic()
                    if not first_event_t:
                        first_event_t = _now
                    last_event_t = _now
                if relay_sock is not None and relay_sock in rdy:
                    try:
                        if _drain_relay_lines(relay_sock, relay_pending):
                            log.debug("port_change from relay → immediate sync.")
                            try:
                                _sync()
                                last_reconcile_t = monotonic()
                                last_event_t = 0.0
                                first_event_t = 0.0
                            except DiscoveryError as exc:
                                log.error("Discovery failed; keeping existing policy: %s", exc)
                                last_event_t = monotonic()
                                first_event_t = last_event_t
                                continue
                            except (OSError, RuntimeError) as exc:
                                log.error("Sync error (port_change): %s", exc)
                                if backend is not None:
                                    backend.close()
                                backend = None
                    except (ConnectionResetError, OSError):
                        log.info("pkt_relay disconnected; reverting to proc_connector only.")
                        relay_sock.close()
                        relay_sock = None
                        relay_pending.clear()
                        last_relay_connect_t = monotonic()
            except OSError as exc:
                log.warning("Netlink event error (%s); reconnecting proc connector.", exc)
                if nl:
                    nl.close()
                nl = None
                last_netlink_connect_t = monotonic()

            if reload_requested:
                reload_requested = False
                log.warning("SIGHUP received — reloading config from %s", config_path)
                _old_pin_dir = cfg.BPF_PIN_DIR
                _old_nft_family = cfg.NFT_FAMILY
                _old_nft_table = cfg.NFT_TABLE
                _old_preferred = cfg.PREFERRED_BACKEND
                if not _reload_config(config_path):
                    continue
                if cli_trusted_ips:
                    TRUSTED_SRC_IPS.update(cli_trusted_ips)
                if cli_log_level is None:
                    _lvl = getattr(logging, cfg.LOG_LEVEL.upper(), logging.WARNING)
                    logging.getLogger().setLevel(_lvl)
                    log.setLevel(_lvl)
                _backend_stale = (
                    cfg.BPF_PIN_DIR != _old_pin_dir
                    or cfg.NFT_FAMILY != _old_nft_family
                    or cfg.NFT_TABLE != _old_nft_table
                )
                if cfg.PREFERRED_BACKEND != _old_preferred and backend_name == _old_preferred:
                    backend_name = cfg.PREFERRED_BACKEND
                    _backend_stale = True
                if _backend_stale and backend is not None:
                    log.warning(
                        "Backend-critical config changed; closing backend for rebuild."
                    )
                    backend.close()
                    backend = None
                last_event_t = monotonic() - cfg.DEBOUNCE_SECONDS
                first_event_t = last_event_t

            if backend is None and needs_backend:
                continue

            now = monotonic()
            if last_event_t and (
                now - last_event_t >= cfg.DEBOUNCE_SECONDS
                or now - first_event_t >= DEBOUNCE_MAX_WAIT_SECONDS
            ):
                if nl:
                    drain_proc_events(nl)
                log.debug("Sync triggered by event.")
                try:
                    _sync()
                    last_reconcile_t = monotonic()
                except DiscoveryError as exc:
                    log.error("Discovery failed; keeping existing policy: %s", exc)
                    last_event_t = monotonic()
                    first_event_t = last_event_t
                    continue
                except (OSError, RuntimeError) as exc:
                    log.error("Sync error: %s", exc)
                    log.warning("Backend may be broken; will attempt to re-initialize.")
                    if backend is not None:
                        backend.close()
                    backend = None
                    continue

                last_event_t = 0.0
                first_event_t = 0.0

                apply_failures = getattr(backend, "last_apply_failures", 0)
                if backend is not None and apply_failures and hasattr(backend, "verify_kernel_state"):
                    log.warning(
                        "Reconcile had %d failed map update(s); verifying kernel state.",
                        apply_failures,
                    )
                    backend.verify_kernel_state()
                    # Arm debounce so a corrective sync runs shortly.
                    last_event_t = monotonic()
                    first_event_t = last_event_t

            if (
                monotonic() - last_reconcile_t
                >= FULL_RECONCILE_INTERVAL_SECONDS
            ):
                log.debug("Periodic safety reconcile.")
                try:
                    _sync()
                    last_reconcile_t = monotonic()
                    # This was a full discovery, so it also satisfies any
                    # pending event-triggered reconcile.
                    last_event_t = 0.0
                    first_event_t = 0.0
                except DiscoveryError as exc:
                    log.error("Periodic discovery failed; keeping existing policy: %s", exc)
                    last_reconcile_t = monotonic()
                except (OSError, RuntimeError) as exc:
                    log.error("Periodic sync error: %s", exc)
                    log.warning("Backend may be broken; will attempt to re-initialize.")
                    if backend is not None:
                        backend.close()
                    backend = None
                    continue

            if monotonic() - last_stale_check_t >= 30.0:
                last_stale_check_t = monotonic()
                if backend is not None and hasattr(backend, "is_stale") and backend.is_stale():
                    log.warning(
                        "XDP map FDs are stale (BPF program was reloaded); "
                        "reinitializing backend."
                    )
                    backend.close()
                    backend = None
                elif backend is not None and hasattr(backend, "verify_kernel_state"):
                    if backend.verify_kernel_state():
                        # Drift found: arm debounce to schedule a corrective sync.
                        _now = monotonic()
                        if not first_event_t:
                            first_event_t = _now
                        last_event_t = _now

    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        if nl:
            nl.close()
        if relay_sock:
            relay_sock.close()
        if backend:
            backend.close()
