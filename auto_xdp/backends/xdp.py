"""XDP/BPF backend — syncs port whitelist and rate-limit maps directly."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import logging
import os
from pathlib import Path
import socket
import secrets
import shutil
import subprocess
import sys
from typing import Mapping

from auto_xdp import config as cfg
from auto_xdp.install_state import atomic_write_json
from auto_xdp.backends.base import BackendStatus, PortBackend
from auto_xdp.abuseipdb import AbuseIPDBSyncer, BpfRiskMaps
from auto_xdp.bpf.syscall import map_id, obj_get, probe_inner_map_support
from auto_xdp.bpf.maps import (
    BpfAclMaps,
    BpfArrayMap,
    BpfGlobalRlMap,
    BpfPortPolicyMap,
    BpfPortPolicyViewMap,
    BpfRateOuterMap,
    BpfRuntimeConfigMap,
    BpfSit4EndpointsMap,
    BpfSynRatePortsMap,
    BpfTrustedMaps,
    BpfZonePortMap,
    XDP_CFG_FLAG_ABUSEIPDB_ENABLED,
    XDP_CFG_FLAG_BOGON_DISABLED,
    XDP_CFG_FLAG_DROP_EVENTS_DISABLED,
    XDP_CFG_FLAG_SLOT_DROP,
)
from auto_xdp.policy import rate_map_entries_v6
from auto_xdp.services import service_name
from auto_xdp.state import AppliedState, DesiredState, ObservedState, ReconcilePlan

log = logging.getLogger(__name__)

# A rate-limit map slot holds either the standalone SYN-rate map or a per-field
# view over the shared port-policy map; both expose active()/set()/delete().
RateLimitMap = BpfSynRatePortsMap | BpfPortPolicyViewMap

_MINECRAFT_PROFILE = "minecraft"
_PROFILE_IDS = {_MINECRAFT_PROFILE: 1}
_PROFILE_STATE_DIR = "profile-handlers"
_POLICY_GENERATION_STATE = "policy-generations.json"
_TCP_ENDPOINT_VALUE_FORMAT = "=IIQQ"
_TCP_ALLOW = 1


def _compute_cfg_flags(desired: DesiredState) -> int:
    flags = 0
    if not desired.bogon_filter_enabled:
        flags |= XDP_CFG_FLAG_BOGON_DISABLED
    if not desired.drop_events_enabled:
        flags |= XDP_CFG_FLAG_DROP_EVENTS_DISABLED
    if cfg.ABUSEIPDB_ENABLED:
        flags |= XDP_CFG_FLAG_ABUSEIPDB_ENABLED
    if cfg.SLOT_DEFAULT_ACTION == "drop":
        flags |= XDP_CFG_FLAG_SLOT_DROP
    return flags


def _cfg_flag_bogon(m: BpfRuntimeConfigMap | None) -> bool | None:
    if m is None:
        return None
    flags = m.get_cfg_flags()
    return None if flags is None else not bool(flags & XDP_CFG_FLAG_BOGON_DISABLED)


def _cfg_flag_drop_events(m: BpfRuntimeConfigMap | None) -> bool | None:
    if m is None:
        return None
    flags = m.get_cfg_flags()
    return None if flags is None else not bool(flags & XDP_CFG_FLAG_DROP_EVENTS_DISABLED)


class XdpBackend(PortBackend):
    name = cfg.BACKEND_XDP

    @classmethod
    def probe(cls) -> BackendStatus:
        checks: dict[str, bool] = {}
        details: dict[str, str] = {}

        bpftool_path = shutil.which("bpftool")
        checks["bpftool"] = bpftool_path is not None
        if bpftool_path is None:
            details["bpftool"] = "not found"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="bpftool not found",
                details=details,
                checks=checks,
            )

        missing_maps = [path for path in cfg.REQUIRED_XDP_MAP_PATHS if not os.path.exists(path)]
        checks["required_maps"] = not missing_maps
        if missing_maps:
            details["missing_maps"] = ", ".join(missing_maps)
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="required XDP maps missing",
                details=details,
                checks=checks,
            )

        if cfg.XDP_OBJ_PATH:
            checks["xdp_obj"] = os.path.exists(cfg.XDP_OBJ_PATH)
            if not checks["xdp_obj"]:
                details["xdp_obj_path"] = cfg.XDP_OBJ_PATH
                return BackendStatus(
                    name=cls.name,
                    available=False,
                    reason="configured XDP object file missing",
                    details=details,
                    checks=checks,
                )

        try:
            checks["inner_map_support"] = probe_inner_map_support()
        except PermissionError:
            checks["inner_map_support"] = False
            details["inner_map_support"] = "BPF map creation denied (EPERM)"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="insufficient privileges to create BPF maps (run as root)",
                details=details,
                checks=checks,
            )
        if not checks["inner_map_support"]:
            details["inner_map_support"] = "map-in-map probe failed"
            return BackendStatus(
                name=cls.name,
                available=False,
                reason="kernel lacks ARRAY_OF_MAPS map-in-map support (need 5.10+)",
                details=details,
                checks=checks,
            )

        return BackendStatus(name=cls.name, available=True, checks=checks)

    def __init__(self) -> None:
        self.last_apply_failures: int = 0
        self.tcp_map = BpfArrayMap(cfg.TCP_MAP_PATH, _TCP_ENDPOINT_VALUE_FORMAT)
        self.udp_map = BpfArrayMap(cfg.UDP_MAP_PATH)
        self.tcp_zone_map = BpfZonePortMap(cfg.TCP_ZONE_MAP_PATH, _TCP_ENDPOINT_VALUE_FORMAT)
        self.udp_zone_map = BpfZonePortMap(cfg.UDP_ZONE_MAP_PATH)
        self.tcp_profile_map = BpfArrayMap(cfg.TCP_PROFILE_HANDLER_MAP_PATH)
        self._policy_generations = self._load_policy_generations()
        self._persisted_policy_generations = dict(self._policy_generations)
        self.trusted_map = BpfTrustedMaps(cfg.TRUSTED_IPS_MAP_PATH4, cfg.TRUSTED_IPS_MAP_PATH6)
        self._tcp_policy_map: BpfPortPolicyMap | None = None
        self._udp_policy_map: BpfPortPolicyMap | None = None
        self.syn_rate_map: RateLimitMap | None = None
        self.syn_agg_rate_map: RateLimitMap | None = None
        self.udp_rate_map: RateLimitMap | None = None
        self.udp_agg_rate_map: RateLimitMap | None = None
        self.acl_maps: BpfAclMaps | None = None
        self.runtime_config_map: BpfRuntimeConfigMap | None = None
        self.global_rl_map: BpfGlobalRlMap | None = None
        self.sctp_map: BpfArrayMap | None = None
        try:
            self._tcp_policy_map = BpfPortPolicyMap(cfg.TCP_PORT_POLICY_MAP_PATH)
            self.syn_rate_map = BpfPortPolicyViewMap(self._tcp_policy_map, 0, cfg.TCP_PORT_POLICY_MAP_PATH)
            self.syn_agg_rate_map = BpfPortPolicyViewMap(self._tcp_policy_map, 1, cfg.TCP_PORT_POLICY_MAP_PATH)
            log.debug("tcp_port_policies map opened; TCP per-port policy active.")
        except OSError as exc:
            log.debug("tcp_port_policies map unavailable (%s); TCP per-port policy inactive.", exc)
        try:
            self._udp_policy_map = BpfPortPolicyMap(cfg.UDP_PORT_POLICY_MAP_PATH)
            self.udp_rate_map = BpfPortPolicyViewMap(self._udp_policy_map, 0, cfg.UDP_PORT_POLICY_MAP_PATH)
            self.udp_agg_rate_map = BpfPortPolicyViewMap(self._udp_policy_map, 1, cfg.UDP_PORT_POLICY_MAP_PATH)
            log.debug("udp_port_policies map opened; UDP per-port policy active.")
        except OSError as exc:
            log.debug("udp_port_policies map unavailable (%s); UDP per-port policy inactive.", exc)
        try:
            self.acl_maps = BpfAclMaps(
                cfg.TCP_ACL_MAP_PATH4, cfg.TCP_ACL_MAP_PATH6,
                cfg.UDP_ACL_MAP_PATH4, cfg.UDP_ACL_MAP_PATH6,
            )
            log.debug("ACL maps opened; per-CIDR port ACL active.")
        except OSError as exc:
            log.debug("ACL maps unavailable (%s); per-CIDR ACL inactive.", exc)
        try:
            self.runtime_config_map = BpfRuntimeConfigMap(cfg.XDP_RUNTIME_CFG_MAP_PATH)
            log.debug("xdp_runtime_cfg map opened; runtime tuning active.")
        except OSError as exc:
            log.debug("xdp_runtime_cfg map unavailable (%s); runtime tuning inactive.", exc)
        try:
            self.global_rl_map = BpfGlobalRlMap(cfg.UDP_GLOBAL_RL_MAP_PATH)
            log.debug("udp_global_rl map opened; global UDP rate limit control active.")
        except OSError as exc:
            log.debug("udp_global_rl map unavailable (%s); global UDP rate limit inactive.", exc)
        try:
            self.sctp_map = BpfArrayMap(cfg.SCTP_MAP_PATH)
            log.debug("sctp_whitelist map opened; SCTP whitelist sync active.")
        except OSError as exc:
            log.debug("sctp_whitelist map unavailable (%s); SCTP whitelist sync inactive.", exc)
        self.sit4_map: BpfSit4EndpointsMap | None = None
        try:
            self.sit4_map = BpfSit4EndpointsMap(cfg.SIT4_ENDPOINTS_MAP_PATH)
            log.debug("sit4_endpoints map opened; 6in4 tunnel endpoint control active.")
        except OSError as exc:
            log.debug("sit4_endpoints map unavailable (%s); 6in4 tunnel endpoint sync inactive.", exc)
        self.syn4_outer: BpfRateOuterMap | None = None
        self.syn6_outer: BpfRateOuterMap | None = None
        self.udprt4_outer: BpfRateOuterMap | None = None
        self.udprt6_outer: BpfRateOuterMap | None = None
        try:
            self.syn4_outer = BpfRateOuterMap(
                cfg.SYN4_MAP_PATH, 4, 8, cfg.RATE_MAP_ENTRIES_V4, "s4_"
            )
            self.syn6_outer = BpfRateOuterMap(
                cfg.SYN6_MAP_PATH, 16, 8, cfg.RATE_MAP_ENTRIES_V6, "s6_"
            )
            self.udprt4_outer = BpfRateOuterMap(
                cfg.UDPRT4_MAP_PATH, 4, 8, cfg.RATE_MAP_ENTRIES_V4, "u4_"
            )
            self.udprt6_outer = BpfRateOuterMap(
                cfg.UDPRT6_MAP_PATH, 16, 8, cfg.RATE_MAP_ENTRIES_V6, "u6_"
            )
            log.debug("rate outer maps opened; per-port rate-limit isolation active.")
        except OSError as exc:
            log.debug("rate outer maps unavailable (%s); per-port rate-limit isolation inactive.", exc)
        self._risk_maps: BpfRiskMaps | None = None
        self._abuseipdb_syncer: AbuseIPDBSyncer | None = None
        try:
            if self.runtime_config_map is not None:
                self._risk_maps = BpfRiskMaps(
                    cfg.ABUSEIPDB_RISK_MAP_PATH4,
                    self.runtime_config_map,
                )
            if cfg.ABUSEIPDB_ENABLED and self._risk_maps is not None:
                self._abuseipdb_syncer = AbuseIPDBSyncer(
                    self._risk_maps,
                    base_url=cfg.ABUSEIPDB_BASE_URL,
                    sources=cfg.ABUSEIPDB_SOURCES,
                    refresh_seconds=cfg.ABUSEIPDB_REFRESH_SECONDS,
                )
                self._abuseipdb_syncer.start()
            log.debug("AbuseIPDB risk maps opened.")
        except OSError as exc:
            log.debug("AbuseIPDB maps unavailable (%s); AbuseIPDB blocking inactive.", exc)

    def _desired_udp_zone_values(self, desired: DesiredState) -> dict[tuple[int, int], int]:
        values: dict[tuple[int, int], int] = {}
        for zone, ports in desired.zone_udp_ports.items():
            for interface in cfg.ZONES.get(zone, {}).get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    log.warning("Configured zone interface does not exist: %s", interface)
                    continue
                values.update(((ifindex, port), 1) for port in ports)
        for zone, spec in cfg.ZONES.items():
            for interface in spec.get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    continue
                for port in desired.udp_ports:
                    values.setdefault((ifindex, port), 0)
        return values

    def _policy_fingerprint(
        self, desired: DesiredState, endpoint: tuple[str, int], profile: str
    ) -> str:
        zone, port = endpoint
        material = [
            (
                item.endpoint.host_address,
                item.endpoint.bind_scope,
                item.endpoint.attribution_state,
                item.endpoint.attribution_source,
                item.endpoint.container_runtime,
                item.endpoint.container_id,
                item.endpoint.instance_id,
                item.subject,
                item.protection_profile,
            )
            for item in desired.exposure_decisions
            if item.action == "allow"
            and item.endpoint.protocol == "tcp"
            and item.endpoint.ingress_zone == zone
            and item.endpoint.host_port == port
        ]
        endpoint_acl = sorted(
            (protocol, cidr, tuple(sorted(ports)))
            for (protocol, cidr), ports in desired.acl_rules.items()
            if protocol == "tcp" and port in ports
        )
        payload = (
            zone,
            port,
            profile,
            tuple(cfg.ZONES.get(zone, {}).get("interfaces", [])),
            desired.tcp_syn_rate_limits.get(port),
            desired.tcp_syn_agg_rate_limits.get(port),
            endpoint_acl,
            desired.bogon_filter_enabled,
            sorted(material),
        )
        return hashlib.sha256(repr(payload).encode()).hexdigest()

    def _endpoint_generation(
        self, desired: DesiredState, endpoint: tuple[str, int], profile: str
    ) -> int:
        fingerprint = self._policy_fingerprint(desired, endpoint, profile)
        current = self._policy_generations.get(endpoint)
        if current is not None and current[0] == fingerprint:
            return current[1]
        generation = secrets.randbits(64) or 1
        self._policy_generations[endpoint] = (fingerprint, generation)
        return generation

    @staticmethod
    def _profile_generation(object_path: Path) -> int:
        digest = hashlib.sha256(object_path.read_bytes()).digest()
        return int.from_bytes(digest[:8], "little") or 1

    def _tcp_endpoint_value(
        self,
        desired: DesiredState,
        endpoint: tuple[str, int],
        profile_generation: int,
    ) -> tuple[int, int, int, int]:
        profile = desired.tcp_protection_profiles.get(endpoint, "")
        if not profile:
            return (_TCP_ALLOW, 0, 0, 0)
        return (
            _TCP_ALLOW,
            _PROFILE_IDS[profile],
            self._endpoint_generation(desired, endpoint, profile),
            profile_generation,
        )

    def _desired_tcp_values(
        self, desired: DesiredState, profile_generation: int
    ) -> tuple[dict[int, tuple[int, int, int, int]], dict[tuple[int, int], tuple[int, int, int, int]]]:
        active_endpoints = set(desired.tcp_protection_profiles)
        for endpoint in set(self._policy_generations) - active_endpoints:
            self._policy_generations.pop(endpoint, None)

        global_values = {
            port: self._tcp_endpoint_value(
                desired, ("public", port), profile_generation
            )
            for port in desired.tcp_ports
        }
        zone_values: dict[tuple[int, int], tuple[int, int, int, int]] = {}
        for zone, ports in desired.zone_tcp_ports.items():
            for interface in cfg.ZONES.get(zone, {}).get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    log.warning("Configured zone interface does not exist: %s", interface)
                    continue
                for port in ports:
                    zone_values[(ifindex, port)] = self._tcp_endpoint_value(
                        desired, (zone, port), profile_generation
                    )
        for zone, spec in cfg.ZONES.items():
            for interface in spec.get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    ifindex = socket.if_nametoindex(interface)
                except OSError:
                    continue
                for port in desired.tcp_ports:
                    zone_values.setdefault((ifindex, port), (0, 0, 0, 0))
        return global_values, zone_values

    def _zone_state(self, zone_map: BpfZonePortMap) -> dict[str, set[int]]:
        active = zone_map.active_entries()
        result: dict[str, set[int]] = {}
        for zone, spec in cfg.ZONES.items():
            indices = set()
            for interface in spec.get("interfaces", []):
                if interface == "*":
                    continue
                try:
                    indices.add(socket.if_nametoindex(interface))
                except OSError:
                    continue
            ports = {port for ifindex, port in active if ifindex in indices}
            if ports:
                result[zone] = ports
        return result

    def _apply_zone_delta(
        self,
        zone_map: BpfZonePortMap,
        desired_values: Mapping[tuple[int, int], int | tuple[int, ...]],
        dry_run: bool,
        additions: bool,
    ) -> int:
        failures = 0
        current = zone_map.entries()
        desired_entries = set(desired_values)
        changed = {
            key for key in current & desired_entries
            if hasattr(zone_map, "value")
            and zone_map.value(*key)
            != (
                (desired_values[key],)
                if isinstance(desired_values[key], int)
                else desired_values[key]
            )
        }
        entries = ((desired_entries - current) | changed) if additions else (current - desired_entries)
        for ifindex, port in sorted(entries):
            ok = (
                zone_map.set(ifindex, port, desired_values[(ifindex, port)], dry_run)
                if additions
                else zone_map.delete(ifindex, port, dry_run)
            )
            if not ok:
                failures += 1
            elif not dry_run:
                log.debug("%s zone port %s %d", "+" if additions else "-", ifindex, port)
        return failures

    @staticmethod
    def _profile_install_dir() -> Path:
        python_root = os.environ.get("PYTHON_LIB_DIR")
        if python_root:
            return Path(python_root).resolve().parent
        return Path(__file__).resolve().parents[2]

    @staticmethod
    def _profile_marker() -> Path:
        run_dir = Path(os.environ.get("RUN_STATE_DIR", "/run/auto_xdp"))
        return run_dir / _PROFILE_STATE_DIR / "tcp" / _MINECRAFT_PROFILE

    @staticmethod
    def _policy_generation_state_path() -> Path:
        return Path(os.environ.get("RUN_STATE_DIR", "/run/auto_xdp")) / _POLICY_GENERATION_STATE

    def _load_policy_generations(self) -> dict[tuple[str, int], tuple[str, int]]:
        try:
            data = json.loads(self._policy_generation_state_path().read_text(encoding="utf-8"))
            if data.get("schema") != 1 or not isinstance(data.get("entries"), list):
                return {}
            result: dict[tuple[str, int], tuple[str, int]] = {}
            for item in data["entries"]:
                zone = str(item["zone"])
                port = int(item["port"])
                fingerprint = str(item["fingerprint"])
                generation = int(item["generation"])
                if zone and 1 <= port <= 65535 and fingerprint and generation > 0:
                    result[(zone, port)] = (fingerprint, generation)
            return result
        except (AttributeError, KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return {}

    def _save_policy_generations(self) -> None:
        if self._policy_generations == getattr(
            self, "_persisted_policy_generations", self._policy_generations
        ):
            return
        try:
            atomic_write_json(
                self._policy_generation_state_path(),
                {
                    "schema": 1,
                    "entries": [
                        {
                            "zone": zone,
                            "port": port,
                            "fingerprint": fingerprint,
                            "generation": generation,
                        }
                        for (zone, port), (fingerprint, generation)
                        in sorted(self._policy_generations.items())
                    ],
                },
                mode=0o600,
            )
            self._persisted_policy_generations = dict(self._policy_generations)
        except OSError as exc:
            log.warning("Cannot persist policy generations: %s", exc)

    @staticmethod
    def _pinned_program_id(pin: Path) -> int | None:
        if not pin.exists():
            return None
        try:
            result = subprocess.run(
                ["bpftool", "-j", "prog", "show", "pinned", str(pin)],
                capture_output=True,
                text=True,
            )
        except OSError:
            return None
        if result.returncode != 0:
            return None
        try:
            value = json.loads(result.stdout)
            if isinstance(value, list):
                value = value[0]
            return int(value["id"])
        except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _profile_command(self, action: str, profile_id: int, object_path: Path | None = None) -> bool:
        install_dir = self._profile_install_dir()
        command = [
            sys.executable,
            "-m",
            "auto_xdp.admin_cli",
            "--config",
            cfg.TOML_CONFIG_PATH,
            "--bpf-pin-dir",
            cfg.BPF_PIN_DIR,
            "--install-dir",
            str(install_dir),
            "profile-handler",
            action,
            str(profile_id),
        ]
        if object_path is not None:
            command.append(str(object_path))
        try:
            result = subprocess.run(command, capture_output=True, text=True)
        except OSError as exc:
            log.error("Cannot run Minecraft profile handler command: %s", exc)
            return False
        if result.returncode == 0:
            return True
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        log.error("Minecraft profile handler %s failed for profile %d: %s", action, profile_id, detail)
        return False

    def _managed_profile_handler(self) -> tuple[int, int] | None:
        try:
            value = json.loads(self._profile_marker().read_text(encoding="utf-8"))
            if (
                value["profile"] != _MINECRAFT_PROFILE
                or int(value["profile_id"]) != _PROFILE_IDS[_MINECRAFT_PROFILE]
            ):
                return None
            program_id = int(value["program_id"])
            profile_generation = int(value["profile_generation"])
            if program_id <= 0 or profile_generation <= 0:
                return None
            return program_id, profile_generation
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _ensure_profile_handlers(
        self,
        desired: dict[tuple[str, int], str],
        profile_generation: int,
        dry_run: bool,
    ) -> tuple[set[tuple[str, int]], int]:
        failures: set[tuple[str, int]] = set()
        install_dir = self._profile_install_dir()
        object_path = install_dir / "handlers" / f"{_MINECRAFT_PROFILE}_handler.o"
        for endpoint, profile in desired.items():
            if profile != _MINECRAFT_PROFILE:
                log.error("Unsupported TCP protection profile %r on %s/%d", profile, *endpoint)
                failures.add(endpoint)
        if failures:
            return set(desired), 0
        if not desired:
            return set(), 0
        if not object_path.is_file():
            log.error("Minecraft profile object is missing: %s", object_path)
            return set(desired), 0

        profile_id = _PROFILE_IDS[_MINECRAFT_PROFILE]
        live_pin = Path(cfg.BPF_PIN_DIR) / "profile_handlers" / "tcp" / str(profile_id) / "prog"
        live_id = self._pinned_program_id(live_pin)
        managed = self._managed_profile_handler()
        self.tcp_profile_map.verify()
        array_value = self.tcp_profile_map.value(profile_id)
        array_id = array_value[0] if array_value else None
        if managed == (live_id, profile_generation) and array_id == live_id:
            return failures, profile_generation
        if dry_run:
            log.info("Would load Minecraft profile handler ID %d", profile_id)
            return failures, profile_generation
        if not self._profile_command("load", profile_id, object_path):
            return set(desired), 0
        live_id = self._pinned_program_id(live_pin)
        self.tcp_profile_map.refresh()
        array_value = self.tcp_profile_map.value(profile_id)
        if live_id is None or array_value is None or array_value[0] != live_id:
            self._profile_command("unload", profile_id)
            return set(desired), 0
        marker = self._profile_marker()
        try:
            atomic_write_json(
                marker,
                {
                    "profile": _MINECRAFT_PROFILE,
                    "profile_id": profile_id,
                    "program_id": live_id,
                    "profile_generation": profile_generation,
                },
                mode=0o600,
            )
        except OSError as exc:
            log.error("Cannot record Minecraft profile ownership: %s", exc)
            self._profile_command("unload", profile_id)
            return set(desired), 0
        log.info("Minecraft protection profile %d enabled", profile_id)
        return failures, profile_generation

    def _remove_stale_profile_handlers(
        self, desired: dict[tuple[str, int], str], dry_run: bool
    ) -> int:
        if desired:
            return 0
        profile_map = getattr(self, "tcp_profile_map", None)
        if profile_map is None:
            return 0
        profile_id = _PROFILE_IDS[_MINECRAFT_PROFILE]
        live_pin = Path(cfg.BPF_PIN_DIR) / "profile_handlers" / "tcp" / str(profile_id) / "prog"
        live_id = self._pinned_program_id(live_pin)
        profile_map.verify()
        array_value = profile_map.value(profile_id)
        array_id = array_value[0] if array_value else None
        if live_id is None and array_id is None:
            try:
                self._profile_marker().unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                log.warning("Cannot remove stale profile marker: %s", exc)
                return 1
            return 0
        if live_id is None or array_id != live_id:
            log.error("Cannot safely remove inconsistent Minecraft profile handler state")
            return 1
        if dry_run:
            log.info("Would unload stale Minecraft profile handler ID %d", profile_id)
            return 0
        if not self._profile_command("unload", profile_id):
            return 1
        profile_map.refresh()
        try:
            self._profile_marker().unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            log.warning("Cannot remove stale profile marker: %s", exc)
            return 1
        log.info("Minecraft protection profile %d disabled", profile_id)
        return 0

    def is_stale(self) -> bool:
        """Return True if the pinned tcp_whitelist map has been replaced since init."""
        try:
            fd = obj_get(cfg.TCP_MAP_PATH)
            try:
                pinned_id = map_id(fd)
            finally:
                os.close(fd)
            return pinned_id != self.tcp_map.map_id()
        except OSError:
            return False

    def close(self) -> None:
        self.tcp_map.close()
        self.udp_map.close()
        if hasattr(self, "tcp_profile_map"):
            self.tcp_profile_map.close()
        for zone_map in (getattr(self, "tcp_zone_map", None), getattr(self, "udp_zone_map", None)):
            if zone_map is not None:
                zone_map.close()
        self.trusted_map.close()
        if self._tcp_policy_map is not None:
            self._tcp_policy_map.close()
        if self._udp_policy_map is not None:
            self._udp_policy_map.close()
        if self.acl_maps is not None:
            self.acl_maps.close()
        if self.runtime_config_map is not None:
            self.runtime_config_map.close()
        if self.global_rl_map is not None:
            self.global_rl_map.close()
        if self.sctp_map is not None:
            self.sctp_map.close()
        if self.sit4_map is not None:
            self.sit4_map.close()
        for outer in (self.syn4_outer, self.syn6_outer, self.udprt4_outer, self.udprt6_outer):
            if outer is not None:
                outer.close()
        if self._abuseipdb_syncer is not None:
            self._abuseipdb_syncer.stop()
        if self._risk_maps is not None:
            self._risk_maps.close()

    def get_applied_state(self) -> AppliedState:
        return AppliedState(
            tcp_ports=self.tcp_map.active_ports(),
            udp_ports=self.udp_map.active_ports(),
            zone_tcp_ports=self._zone_state(self.tcp_zone_map) if hasattr(self, "tcp_zone_map") else {},
            zone_udp_ports=self._zone_state(self.udp_zone_map) if hasattr(self, "udp_zone_map") else {},
            sctp_ports=self.sctp_map.active_ports() if self.sctp_map is not None else set(),
            trusted_cidrs=self.trusted_map.active_keys(),
            tcp_syn_rate_limits=self.syn_rate_map.active() if self.syn_rate_map is not None else {},
            tcp_syn_agg_rate_limits=self.syn_agg_rate_map.active() if self.syn_agg_rate_map is not None else {},
            udp_rate_limits=self.udp_rate_map.active() if self.udp_rate_map is not None else {},
            udp_agg_rate_limits=self.udp_agg_rate_map.active() if self.udp_agg_rate_map is not None else {},
            acl_rules=self.acl_maps.active_entries() if self.acl_maps is not None else {},
            bogon_filter_enabled=_cfg_flag_bogon(self.runtime_config_map),
            drop_events_enabled=_cfg_flag_drop_events(self.runtime_config_map),
            udp_global_byte_rate=self.global_rl_map.get() if self.global_rl_map is not None else None,
            xdp_runtime_config=self.runtime_config_map.get() if self.runtime_config_map is not None else None,
        )

    def build_reconcile_plan(
        self,
        desired_state: DesiredState,
        applied_state: AppliedState,
    ) -> ReconcilePlan:
        plan = super().build_reconcile_plan(desired_state, applied_state)
        return plan

    def _ok(self, result: bool) -> bool:
        if not result:
            self.last_apply_failures += 1
        return result

    def verify_kernel_state(self) -> int:
        """Re-read userspace-owned config maps from the kernel and repair caches.

        Returns the total number of discrepancies found (0 = kernel matches cache).
        """
        total = 0
        total += self.tcp_map.verify()
        total += self.udp_map.verify()
        if hasattr(self, "tcp_profile_map"):
            total += self.tcp_profile_map.verify()
        for zone_map in (getattr(self, "tcp_zone_map", None), getattr(self, "udp_zone_map", None)):
            if zone_map is not None:
                total += zone_map.verify()
        if self.sctp_map is not None:
            total += self.sctp_map.verify()
        total += self.trusted_map.verify()
        if self._tcp_policy_map is not None:
            total += self._tcp_policy_map.verify()
        if self._udp_policy_map is not None:
            total += self._udp_policy_map.verify()
        if self.acl_maps is not None:
            total += self.acl_maps.verify()
        if self.sit4_map is not None:
            total += self.sit4_map.verify()
        for outer in (self.syn4_outer, self.syn6_outer, self.udprt4_outer, self.udprt6_outer):
            if outer is not None:
                total += outer.verify()
        if total:
            log.warning(
                "Kernel state verification found %d drifted map entr%s; caches repaired, corrective sync recommended.",
                total, "y" if total == 1 else "ies",
            )
        return total

    def apply_reconcile_plan(
        self,
        plan: ReconcilePlan,
        dry_run: bool,
        desired_state: DesiredState,
        observed_state: ObservedState | None = None,
    ) -> None:
        self.last_apply_failures = getattr(self, "_precondition_failures", 0)
        self._precondition_failures = 0
        changed = False
        for port in sorted(plan.tcp_ports_to_remove):
            if self._ok(self.tcp_map.set(port, 0, dry_run)):
                log.debug("TCP -%d  (stopped)", port)
                changed = True

        for port in sorted(plan.udp_ports_to_remove):
            if self._ok(self.udp_map.set(port, 0, dry_run)):
                log.debug("UDP -%d  (stopped)", port)
                changed = True

        if self.sctp_map is not None:
            for port in sorted(plan.sctp_ports_to_add):
                if self._ok(self.sctp_map.set(port, 1, dry_run)):
                    log.info("SCTP +%d", port)
                    changed = True

            for port in sorted(plan.sctp_ports_to_remove):
                if self._ok(self.sctp_map.set(port, 0, dry_run)):
                    log.info("SCTP -%d  (stopped)", port)
                    changed = True

        # HASH maps need delete, not write-zero, when trust entries disappear.
        for ip_str in sorted(plan.trusted_cidrs_to_add):
            tag = f" [{cfg.TRUSTED_SRC_IPS[ip_str]}]" if ip_str in cfg.TRUSTED_SRC_IPS else ""
            if self._ok(self.trusted_map.set(ip_str, 1, dry_run)):
                log.info("TRUST +%s%s", ip_str, tag)
                changed = True

        for ip_str in sorted(plan.trusted_cidrs_to_remove):
            if self._ok(self.trusted_map.delete(ip_str, dry_run)):
                log.info("TRUST -%s  (removed)", ip_str)
                changed = True

        if not changed:
            log.debug("Whitelist up-to-date.")

        if self.syn_rate_map is not None:
            self._apply_rate_map_delta(
                self.syn_rate_map,
                plan.tcp_syn_rate_limits_to_upsert,
                plan.tcp_syn_rate_limits_to_remove,
                dry_run,
                "tcp",
                {} if observed_state is None else observed_state.tcp_processes,
            )

        if self.syn_agg_rate_map is not None:
            self._apply_rate_map_delta(
                self.syn_agg_rate_map,
                plan.tcp_syn_agg_rate_limits_to_upsert,
                plan.tcp_syn_agg_rate_limits_to_remove,
                dry_run,
                "tcp_syn_agg",
            )

        if self.udp_rate_map is not None:
            self._apply_rate_map_delta(
                self.udp_rate_map,
                plan.udp_rate_limits_to_upsert,
                plan.udp_rate_limits_to_remove,
                dry_run,
                "udp",
                {} if observed_state is None else observed_state.udp_processes,
            )

        if self.udp_agg_rate_map is not None:
            self._apply_rate_map_delta(
                self.udp_agg_rate_map,
                plan.udp_agg_rate_limits_to_upsert,
                plan.udp_agg_rate_limits_to_remove,
                dry_run,
                "udp_agg",
            )

        tcp_entries = desired_state.tcp_rate_map_entries
        udp_entries = desired_state.udp_rate_map_entries
        if self.syn4_outer is not None:
            self._apply_rate_outer_delta(self.syn4_outer, tcp_entries, dry_run)
        if self.syn6_outer is not None:
            self._apply_rate_outer_delta(
                self.syn6_outer,
                {p: rate_map_entries_v6(c) for p, c in tcp_entries.items()},
                dry_run,
            )
        if self.udprt4_outer is not None:
            self._apply_rate_outer_delta(self.udprt4_outer, udp_entries, dry_run)
        if self.udprt6_outer is not None:
            self._apply_rate_outer_delta(
                self.udprt6_outer,
                {p: rate_map_entries_v6(c) for p, c in udp_entries.items()},
                dry_run,
            )

        if self._tcp_policy_map is not None:
            tcp_policy_ports = (
                set(desired_state.tcp_syn_rate_limits)
                | set(desired_state.tcp_syn_agg_rate_limits)
            )
            self._tcp_policy_map.ensure_prefixes(
                tcp_policy_ports,
                desired_state.rate_limit_source_prefix_v4,
                desired_state.rate_limit_source_prefix_v6,
                dry_run,
            )

        if self._udp_policy_map is not None:
            udp_policy_ports = set(desired_state.udp_rate_limits) | set(desired_state.udp_agg_rate_limits)
            self._udp_policy_map.ensure_prefixes(
                udp_policy_ports,
                desired_state.rate_limit_source_prefix_v4,
                desired_state.rate_limit_source_prefix_v6,
                dry_run,
            )

        if self.acl_maps is not None:
            self._apply_acl_delta(plan, dry_run)

        if self.runtime_config_map is not None:
            cfg_flags = _compute_cfg_flags(desired_state)
            current = self.runtime_config_map.get()
            current_flags = self.runtime_config_map.get_cfg_flags() or 0
            if desired_state.xdp_runtime_config != current or cfg_flags != current_flags:
                self._ok(self.runtime_config_map.set(desired_state.xdp_runtime_config, cfg_flags, dry_run))

        if self.global_rl_map is not None and plan.udp_global_byte_rate_update is not None:
            rate = plan.udp_global_byte_rate_update
            if self._ok(self.global_rl_map.set(rate, dry_run)):
                if rate:
                    log.info("UDP global rate limit set to %d bytes/s", rate)
                else:
                    log.info("UDP global rate limit disabled")

        if self.sit4_map is not None:
            desired_sit4 = set(cfg.SIT4_ENDPOINTS)
            current_sit4 = self.sit4_map.active_keys()
            for ip_str in sorted(desired_sit4 - current_sit4):
                if self._ok(self.sit4_map.set(ip_str, dry_run)):
                    log.info("SIT4 +%s (6in4 tunnel endpoint added)", ip_str)
            for ip_str in sorted(current_sit4 - desired_sit4):
                if self._ok(self.sit4_map.delete(ip_str, dry_run)):
                    log.info("SIT4 -%s (6in4 tunnel endpoint removed)", ip_str)

        # BPF maps do not provide a transaction.  Prepare all protection state
        # first, then expose new TCP/UDP ports only if that preparation passed.
        # A failed map update leaves the port closed and is retried next round.
        if self.last_apply_failures:
            if plan.tcp_ports_to_add or plan.udp_ports_to_add:
                log.warning(
                    "Keeping new TCP/UDP ports closed because protection setup "
                    "failed (%d map update failure(s)).",
                    self.last_apply_failures,
                )
        elif not getattr(self, "_defer_global_admission", False):
            self._apply_global_admission(plan, dry_run)

        if self.last_apply_failures and not dry_run:
            log.warning(
                "%d BPF map update%s failed this reconcile; kernel state may lag desired state.",
                self.last_apply_failures,
                "" if self.last_apply_failures == 1 else "s",
            )

    def _apply_global_admission(self, plan: ReconcilePlan, dry_run: bool) -> None:
        tcp_values = getattr(self, "_desired_tcp_global_values", {})
        for port in sorted(plan.tcp_ports_to_add):
            value = tcp_values.get(port, (_TCP_ALLOW, 0, 0, 0))
            if self._ok(self.tcp_map.set(port, value, dry_run)):
                log.debug("TCP +%d", port)
        for port in sorted(plan.udp_ports_to_add):
            if self._ok(self.udp_map.set(port, 1, dry_run)):
                log.debug("UDP +%d", port)

    def reconcile(
        self,
        desired_state: DesiredState,
        dry_run: bool,
        observed_state: ObservedState | None = None,
    ) -> None:
        if not hasattr(self, "_policy_generations"):
            self._policy_generations = {}
        if not hasattr(self, "_persisted_policy_generations"):
            self._persisted_policy_generations = dict(self._policy_generations)
        self.last_apply_failures = 0

        install_dir = self._profile_install_dir()
        profile_object = install_dir / "handlers" / f"{_MINECRAFT_PROFILE}_handler.o"
        tentative_profile_generation = (
            self._profile_generation(profile_object) if profile_object.is_file() else 0
        )
        desired_global, desired_zone = self._desired_tcp_values(
            desired_state, tentative_profile_generation
        )
        desired_udp_zone = self._desired_udp_zone_values(desired_state)

        # Policy/profile replacement is close-before-open.  Removing the old
        # admission also guarantees the base reconcile sees the endpoint as an
        # addition and writes the complete new generation atomically.
        for port in self.tcp_map.active_ports() & set(desired_global):
            current = self.tcp_map.value(port) if hasattr(self.tcp_map, "value") else None
            if current is not None and current != desired_global[port]:
                self._ok(self.tcp_map.set(port, (0, 0, 0, 0), dry_run))
        tcp_zone_map = getattr(self, "tcp_zone_map", None)
        if tcp_zone_map is not None:
            for key in tcp_zone_map.entries() & set(desired_zone):
                current = tcp_zone_map.value(*key) if hasattr(tcp_zone_map, "value") else None
                if current is not None and current != desired_zone[key]:
                    self._ok(tcp_zone_map.set(*key, (0, 0, 0, 0), dry_run=dry_run))
            for key, tcp_value in desired_zone.items():
                if tcp_zone_map.value(*key) != tcp_value and key[1] in desired_global:
                    self._ok(self.tcp_map.set(key[1], (0, 0, 0, 0), dry_run))
        udp_zone_map = getattr(self, "udp_zone_map", None)
        if udp_zone_map is not None:
            for key in udp_zone_map.entries() & set(desired_udp_zone):
                current = udp_zone_map.value(*key) if hasattr(udp_zone_map, "value") else None
                if current is not None and current != (desired_udp_zone[key],):
                    self._ok(udp_zone_map.set(*key, 0, dry_run=dry_run))
            for key, udp_value in desired_udp_zone.items():
                if udp_zone_map.value(*key) != (udp_value,) and key[1] in desired_state.udp_ports:
                    self._ok(self.udp_map.set(key[1], 0, dry_run))

        failed_profile_endpoints, profile_generation = self._ensure_profile_handlers(
            desired_state.tcp_protection_profiles,
            tentative_profile_generation,
            dry_run,
        )
        effective_desired = desired_state
        if failed_profile_endpoints:
            effective_desired = replace(
                desired_state,
                tcp_ports={
                    port for port in desired_state.tcp_ports
                    if ("public", port) not in failed_profile_endpoints
                },
                zone_tcp_ports={
                    zone: {
                        port for port in ports
                        if (zone, port) not in failed_profile_endpoints
                    }
                    for zone, ports in desired_state.zone_tcp_ports.items()
                    if any((zone, port) not in failed_profile_endpoints for port in ports)
                },
                tcp_protection_profiles={
                    endpoint: profile
                    for endpoint, profile in desired_state.tcp_protection_profiles.items()
                    if endpoint not in failed_profile_endpoints
                },
            )

        self._desired_tcp_global_values, tcp_zone_values = self._desired_tcp_values(
            effective_desired, profile_generation
        )
        udp_zone_values = self._desired_udp_zone_values(effective_desired)

        tcp_zone_map = getattr(self, "tcp_zone_map", None)
        udp_zone_map = getattr(self, "udp_zone_map", None)
        zone_failures = 0
        if tcp_zone_map is not None:
            zone_failures += self._apply_zone_delta(
                tcp_zone_map, tcp_zone_values, dry_run, additions=False
            )
        if udp_zone_map is not None:
            zone_failures += self._apply_zone_delta(
                udp_zone_map, udp_zone_values, dry_run, additions=False
            )
        self._precondition_failures = self.last_apply_failures + zone_failures
        self._defer_global_admission = True
        try:
            super().reconcile(effective_desired, dry_run, observed_state)
        finally:
            self._defer_global_admission = False
        self.last_apply_failures += len(failed_profile_endpoints)
        if not self.last_apply_failures:
            if tcp_zone_map is not None:
                self.last_apply_failures += self._apply_zone_delta(
                    tcp_zone_map, tcp_zone_values, dry_run, additions=True
                )
            if udp_zone_map is not None:
                self.last_apply_failures += self._apply_zone_delta(
                    udp_zone_map, udp_zone_values, dry_run, additions=True
                )
        if not self.last_apply_failures:
            admission_plan = ReconcilePlan(
                tcp_ports_to_add=effective_desired.tcp_ports - self.tcp_map.active_ports(),
                udp_ports_to_add=effective_desired.udp_ports - self.udp_map.active_ports(),
            )
            self._apply_global_admission(admission_plan, dry_run)
        self.last_apply_failures += self._remove_stale_profile_handlers(
            desired_state.tcp_protection_profiles,
            dry_run,
        )
        if not dry_run:
            self._save_policy_generations()

    def _apply_acl_delta(self, plan: ReconcilePlan, dry_run: bool) -> None:
        if self.acl_maps is None:
            return
        for (proto, cidr), ports in plan.acl_rules_to_upsert.items():
            if self._ok(self.acl_maps.set(proto, cidr, sorted(ports), dry_run)):
                log.info("ACL %s %s ports %s", proto.upper(), cidr, sorted(ports))

        for (proto, cidr) in plan.acl_rules_to_remove:
            if self._ok(self.acl_maps.delete(proto, cidr, dry_run)):
                log.info("ACL %s %s removed", proto.upper(), cidr)

    def _apply_rate_outer_delta(
        self,
        outer: BpfRateOuterMap,
        desired: dict[int, int],
        dry_run: bool,
    ) -> None:
        current = outer.active()
        for port, capacity in desired.items():
            if current.get(port) != capacity:
                self._ok(outer.set(port, capacity, dry_run))
        for port in set(current) - set(desired):
            self._ok(outer.delete(port, dry_run))

    def _apply_rate_map_delta(
        self,
        rate_map: RateLimitMap,
        upserts: dict[int, int],
        removals: set[int],
        dry_run: bool,
        kind: str,
        port_procs: dict[int, str] | None = None,
    ) -> None:
        port_procs = {} if port_procs is None else port_procs
        for port, rate_max in upserts.items():
            if self._ok(rate_map.set(port, rate_max, dry_run)):
                if kind == "tcp":
                    svc = port_procs.get(port) or service_name(port, "tcp") or "unknown"
                    log.info("SYN rate port %d (%s) rate_max=%d/s", port, svc, rate_max)
                elif kind == "tcp_syn_agg":
                    log.info("SYN aggregate port %d rate_max=%d/s", port, rate_max)
                elif kind == "udp":
                    svc = port_procs.get(port) or service_name(port, "udp") or "unknown"
                    log.info("UDP rate port %d (%s) rate_max=%d/s", port, svc, rate_max)
                elif kind == "udp_agg":
                    log.info("UDP aggregate port %d byte_rate_max=%d/s", port, rate_max)

        for port in removals:
            if self._ok(rate_map.delete(port, dry_run)):
                if kind == "tcp":
                    log.info("SYN rate port %d removed (port no longer whitelisted)", port)
                elif kind == "tcp_syn_agg":
                    log.info("SYN aggregate port %d removed", port)
                elif kind == "udp":
                    log.info("UDP rate port %d removed (port no longer whitelisted)", port)
                elif kind == "udp_agg":
                    log.info("UDP aggregate port %d removed", port)
