import socket
import struct
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest import mock

from auto_xdp.discovery import _discovery_exclude_networks, _bind_ip_is_exposed
from auto_xdp.bpf.maps import render_nft_ports as _render_nft_ports
from auto_xdp import config as cfg
import auto_xdp.backends as backends_mod
import auto_xdp.backends.xdp as xdp_backend_mod
import auto_xdp.backends.nftables as nftables_mod
import auto_xdp.bpf.maps as bpf_maps_mod
import auto_xdp.proc_events as proc_events_mod
import auto_xdp.syncer as syncer_mod
import auto_xdp.discovery as discovery_mod
import auto_xdp.cli as cli_mod
import auto_xdp.policy as policy_mod
import auto_xdp.services as services_mod
import auto_xdp.state as state_mod


def make_addr(ip: str, port: int):
    return types.SimpleNamespace(ip=ip, port=port)


def make_conn(
    *,
    family,
    conn_type,
    status,
    laddr,
    raddr=None,
    pid=None,
):
    return types.SimpleNamespace(
        family=family,
        type=conn_type,
        status=status,
        laddr=laddr,
        raddr=raddr,
        pid=pid,
    )


class FakePortMap:
    def __init__(self, active=None):
        self._active = set(active or [])
        self.ops = []
        self.closed = False

    def active_ports(self):
        return set(self._active)

    def set(self, port, val, dry_run=False):
        self.ops.append((port, val, dry_run))
        if val:
            self._active.add(port)
        else:
            self._active.discard(port)
        return True

    def close(self):
        self.closed = True


class FakeTrustedMap:
    def __init__(self, active=None):
        self._active = set(active or [])
        self.set_ops = []
        self.delete_ops = []
        self.closed = False

    def active_keys(self):
        return set(self._active)

    def set(self, key, val, dry_run=False):
        self.set_ops.append((key, val, dry_run))
        if val:
            self._active.add(key)
        return True

    def delete(self, key, dry_run=False):
        self.delete_ops.append((key, dry_run))
        self._active.discard(key)
        return True

    def close(self):
        self.closed = True


class FakeConntrackMap:
    def __init__(self, active=None):
        self._active = set(active or [])
        self.ops = []
        self.delete_ops = []
        self.delete_port_ops = []
        self.lookup_ops = []
        self.closed = False

    def active_keys(self):
        return set(self._active)

    def existing_keys(self, keys):
        wanted = set(keys)
        self.lookup_ops.append(wanted)
        return self._active & wanted

    def set(self, key, dry_run=False):
        self.ops.append((key, dry_run))
        self._active.add(key)
        return True

    def delete(self, key, dry_run=False):
        self.delete_ops.append((key, dry_run))
        self._active.discard(key)
        return True

    def delete_dest_ports(self, ports, dry_run=False):
        self.delete_port_ops.append((set(ports), dry_run))
        return len(self._active)

    def close(self):
        self.closed = True


class FakeSynRateMap:
    def __init__(self, active=None):
        self._active = dict(active or {})
        self.set_ops = []
        self.delete_ops = []
        self.closed = False

    def active(self):
        return dict(self._active)

    def set(self, port, rate_max, dry_run=False):
        self.set_ops.append((port, rate_max, dry_run))
        self._active[port] = rate_max
        return True

    def delete(self, port, dry_run=False):
        self.delete_ops.append((port, dry_run))
        self._active.pop(port, None)
        return True

    def close(self):
        self.closed = True


class FakeUdpPortMap(FakeSynRateMap):
    pass


class FakeArrayCfgMap:
    def __init__(self, active=None):
        self._active = set(active or [])
        self.ops = []
        self.closed = False

    def get(self, key):
        return 1 if key in self._active else 0

    def set(self, key, val, dry_run=False):
        self.ops.append((key, val, dry_run))
        if val:
            self._active.add(key)
        else:
            self._active.discard(key)
        return True

    def close(self):
        self.closed = True


class FakeRuntimeConfigMap:
    def __init__(self, active=None):
        self._active = active
        self.ops = []
        self.closed = False

    def get(self):
        return self._active

    def set(self, fields, dry_run=False):
        self.ops.append((fields, dry_run))
        self._active = fields
        return True

    def close(self):
        self.closed = True


def make_proc_event_message(what: int) -> bytes:
    payload = struct.pack("I", what)
    cn = struct.pack("IIIIHH", proc_events_mod._CN_IDX_PROC, 1, 0, 0, len(payload), 0) + payload
    msg_len = proc_events_mod._NLMSG_HDRLEN + len(cn)
    hdr = struct.pack("IHHII", msg_len, proc_events_mod._NLMSG_MIN_TYPE, 0, 0, 0)
    padded_len = (msg_len + 3) & ~3
    return hdr + cn + (b"\x00" * (padded_len - msg_len))


class XdpPortSyncTests(unittest.TestCase):
    def test_apply_toml_config_supports_extended_runtime_options(self):
        old_values = {
            "log_level": cfg.LOG_LEVEL,
            "debounce_seconds": cfg.DEBOUNCE_SECONDS,
            "preferred_backend": cfg.PREFERRED_BACKEND,
            "exclude_loopback": cfg.DISCOVERY_EXCLUDE_LOOPBACK,
            "exclude_bind_cidrs": list(cfg.DISCOVERY_EXCLUDE_BIND_CIDRS),
            "xdp_conntrack_stale_reconciles": cfg.XDP_CONNTRACK_STALE_RECONCILES,
            "drop_events_enabled": cfg.DROP_EVENTS_ENABLED,
            "syn_agg_by_proc": dict(cfg._SYN_AGG_RATE_BY_PROC),
            "syn_agg_by_service": dict(cfg._SYN_AGG_RATE_BY_SERVICE),
            "tcp_conn_by_proc": dict(cfg._TCP_CONN_BY_PROC),
            "tcp_conn_by_service": dict(cfg._TCP_CONN_BY_SERVICE),
            "udp_agg_bytes_by_proc": dict(cfg._UDP_AGG_BYTES_BY_PROC),
            "udp_agg_bytes_by_service": dict(cfg._UDP_AGG_BYTES_BY_SERVICE),
            "rate_limit_source_prefix_v4": cfg.RATE_LIMIT_SOURCE_PREFIX_V4,
            "rate_limit_source_prefix_v6": cfg.RATE_LIMIT_SOURCE_PREFIX_V6,
            "xdp_tcp_timeout_seconds": cfg.XDP_TCP_TIMEOUT_SECONDS,
            "xdp_udp_timeout_seconds": cfg.XDP_UDP_TIMEOUT_SECONDS,
            "xdp_conntrack_refresh_seconds": cfg.XDP_CONNTRACK_REFRESH_SECONDS,
            "xdp_icmp_burst_packets": cfg.XDP_ICMP_BURST_PACKETS,
            "xdp_icmp_rate_pps": cfg.XDP_ICMP_RATE_PPS,
            "xdp_udp_global_window_seconds": cfg.XDP_UDP_GLOBAL_WINDOW_SECONDS,
            "xdp_rate_window_seconds": cfg.XDP_RATE_WINDOW_SECONDS,
        }
        try:
            cfg.apply_toml_config({
                "daemon": {
                    "log_level": "debug",
                    "debounce_seconds": 1.25,
                    "preferred_backend": "nftables",
                },
                "discovery": {
                    "exclude_loopback": False,
                    "exclude_bind_cidrs": ["10.0.0.0/8", "fd00::/8"],
                },
                "rate_limits": {
                    "source_cidr_v4": 24,
                    "source_cidr_v6": "/64",
                    "syn_agg_by_proc": {"sshd": 16},
                    "syn_agg_by_service": {"ssh": 12},
                    "tcp_conn_by_proc": {"sshd": 64},
                    "tcp_conn_by_service": {"ssh": 48},
                    "udp_agg_bytes_by_proc": {"dnsmasq": 6000000},
                    "udp_agg_bytes_by_service": {"domain": 7000000},
                },
                "under_attack": {
                    "enabled": True,
                },
                "xdp": {
                    "conntrack_stale_reconciles": 4,
                    "runtime": {
                        "tcp_timeout_seconds": 600,
                        "udp_timeout_seconds": 120,
                        "conntrack_refresh_seconds": 45,
                        "icmp_burst_packets": 200,
                        "icmp_rate_pps": 50,
                        "udp_global_window_seconds": 2,
                        "rate_window_seconds": 0.5,
                    },
                },
            })

            self.assertEqual(cfg.LOG_LEVEL, "debug")
            self.assertEqual(cfg.DEBOUNCE_SECONDS, 1.25)
            self.assertEqual(cfg.PREFERRED_BACKEND, cfg.BACKEND_NFTABLES)
            self.assertFalse(cfg.DISCOVERY_EXCLUDE_LOOPBACK)
            self.assertEqual(
                cfg.DISCOVERY_EXCLUDE_BIND_CIDRS,
                ["10.0.0.0/8", "fd00::/8"],
            )
            self.assertEqual(cfg._SYN_AGG_RATE_BY_PROC, {"sshd": 16})
            self.assertEqual(cfg._SYN_AGG_RATE_BY_SERVICE, {"ssh": 12})
            self.assertEqual(cfg._TCP_CONN_BY_PROC, {"sshd": 64})
            self.assertEqual(cfg._TCP_CONN_BY_SERVICE, {"ssh": 48})
            self.assertEqual(cfg._UDP_AGG_BYTES_BY_PROC, {"dnsmasq": 6000000})
            self.assertEqual(cfg._UDP_AGG_BYTES_BY_SERVICE, {"domain": 7000000})
            self.assertEqual(cfg.RATE_LIMIT_SOURCE_PREFIX_V4, 24)
            self.assertEqual(cfg.RATE_LIMIT_SOURCE_PREFIX_V6, 64)
            self.assertEqual(cfg.XDP_CONNTRACK_STALE_RECONCILES, 4)
            self.assertEqual(cfg.XDP_TCP_TIMEOUT_SECONDS, 600)
            self.assertEqual(cfg.XDP_UDP_TIMEOUT_SECONDS, 120)
            self.assertEqual(cfg.XDP_CONNTRACK_REFRESH_SECONDS, 45)
            self.assertEqual(cfg.XDP_ICMP_BURST_PACKETS, 200)
            self.assertEqual(cfg.XDP_ICMP_RATE_PPS, 50)
            self.assertEqual(cfg.XDP_UDP_GLOBAL_WINDOW_SECONDS, 2)
            self.assertEqual(cfg.XDP_RATE_WINDOW_SECONDS, 0.5)
            self.assertFalse(cfg.DROP_EVENTS_ENABLED)
        finally:
            cfg.LOG_LEVEL = old_values["log_level"]
            cfg.DEBOUNCE_SECONDS = old_values["debounce_seconds"]
            cfg.PREFERRED_BACKEND = old_values["preferred_backend"]
            cfg.DISCOVERY_EXCLUDE_LOOPBACK = old_values["exclude_loopback"]
            cfg.DISCOVERY_EXCLUDE_BIND_CIDRS[:] = old_values["exclude_bind_cidrs"]
            cfg.XDP_CONNTRACK_STALE_RECONCILES = old_values["xdp_conntrack_stale_reconciles"]
            cfg.DROP_EVENTS_ENABLED = old_values["drop_events_enabled"]
            cfg._SYN_AGG_RATE_BY_PROC.clear()
            cfg._SYN_AGG_RATE_BY_PROC.update(old_values["syn_agg_by_proc"])
            cfg._SYN_AGG_RATE_BY_SERVICE.clear()
            cfg._SYN_AGG_RATE_BY_SERVICE.update(old_values["syn_agg_by_service"])
            cfg._TCP_CONN_BY_PROC.clear()
            cfg._TCP_CONN_BY_PROC.update(old_values["tcp_conn_by_proc"])
            cfg._TCP_CONN_BY_SERVICE.clear()
            cfg._TCP_CONN_BY_SERVICE.update(old_values["tcp_conn_by_service"])
            cfg._UDP_AGG_BYTES_BY_PROC.clear()
            cfg._UDP_AGG_BYTES_BY_PROC.update(old_values["udp_agg_bytes_by_proc"])
            cfg._UDP_AGG_BYTES_BY_SERVICE.clear()
            cfg._UDP_AGG_BYTES_BY_SERVICE.update(old_values["udp_agg_bytes_by_service"])
            cfg.RATE_LIMIT_SOURCE_PREFIX_V4 = old_values["rate_limit_source_prefix_v4"]
            cfg.RATE_LIMIT_SOURCE_PREFIX_V6 = old_values["rate_limit_source_prefix_v6"]
            cfg.XDP_TCP_TIMEOUT_SECONDS = old_values["xdp_tcp_timeout_seconds"]
            cfg.XDP_UDP_TIMEOUT_SECONDS = old_values["xdp_udp_timeout_seconds"]
            cfg.XDP_CONNTRACK_REFRESH_SECONDS = old_values["xdp_conntrack_refresh_seconds"]
            cfg.XDP_ICMP_BURST_PACKETS = old_values["xdp_icmp_burst_packets"]
            cfg.XDP_ICMP_RATE_PPS = old_values["xdp_icmp_rate_pps"]
            cfg.XDP_UDP_GLOBAL_WINDOW_SECONDS = old_values["xdp_udp_global_window_seconds"]
            cfg.XDP_RATE_WINDOW_SECONDS = old_values["xdp_rate_window_seconds"]

    def test_udp_malformed_drop_only_rejects_port_zero(self):
        source = (Path(__file__).resolve().parents[2] / "bpf" / "include" / "parse.h").read_text()
        self.assertRegex(
            source,
            r"if\s*\(\s*udp->source\s*==\s*0\s*\|\|\s*udp->dest\s*==\s*0\s*\)",
        )
        self.assertNotIn("udp->source == udp->dest", source)

    def test_render_nft_ports_sorts_ports(self):
        self.assertEqual(_render_nft_ports({443, 22, 80}), "{ 22, 80, 443 }")

    def test_port_rate_limit_prefers_process_name_then_service_name(self):
        import auto_xdp.policy as policy
        with mock.patch.object(policy, "service_name", side_effect=lambda port, proto: "ssh" if port == 22 else "http"), \
             mock.patch.object(policy.cfg, "_SYN_RATE_BY_PROC", {"sshd": 2}), \
             mock.patch.object(policy.cfg, "_SYN_RATE_BY_SERVICE", {"ssh": 2}):
            self.assertEqual(policy._port_rate_limit(2222, "sshd"), 2)
            self.assertEqual(policy._port_rate_limit(22), 2)
            self.assertEqual(policy._port_rate_limit(80), 0)

    def test_policy_uses_rebound_config_dicts_not_import_time_aliases(self):
        import auto_xdp.policy as policy
        old_proc = policy.cfg._SYN_RATE_BY_PROC
        old_service = policy.cfg._SYN_RATE_BY_SERVICE
        try:
            policy.cfg._SYN_RATE_BY_PROC = {"sshd": 3}
            policy.cfg._SYN_RATE_BY_SERVICE = {"ssh": 4}
            with mock.patch.object(policy, "service_name", return_value="ssh"):
                self.assertEqual(policy._port_rate_limit(2222, "sshd"), 3)
                self.assertEqual(policy._port_rate_limit(22), 4)
        finally:
            policy.cfg._SYN_RATE_BY_PROC = old_proc
            policy.cfg._SYN_RATE_BY_SERVICE = old_service

    def test_bind_ip_is_exposed_keeps_wildcard_but_filters_loopback_and_private(self):
        with mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_LOOPBACK", True), \
             mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_BIND_CIDRS", ["10.0.0.0/8", "fd00::/8"]):
            exclude_nets = _discovery_exclude_networks()

        self.assertTrue(_bind_ip_is_exposed("0.0.0.0", exclude_nets))
        self.assertTrue(_bind_ip_is_exposed("::", exclude_nets))
        self.assertFalse(_bind_ip_is_exposed("127.0.0.1", exclude_nets))
        self.assertFalse(_bind_ip_is_exposed("::1", exclude_nets))
        self.assertFalse(_bind_ip_is_exposed("10.1.2.3", exclude_nets))
        self.assertFalse(_bind_ip_is_exposed("fd00::1234", exclude_nets))
        self.assertTrue(_bind_ip_is_exposed("203.0.113.10", exclude_nets))

    def test_get_listening_ports_filters_loopback_and_configured_bind_cidrs(self):
        fake_psutil = types.SimpleNamespace(CONN_LISTEN="LISTEN", CONN_ESTABLISHED="ESTABLISHED")
        fake_connections = [
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 22),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("127.0.0.1", 8080),
            ),
            make_conn(
                family=socket.AF_INET6,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("::1", 8443),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("10.0.0.5", 9000),
            ),
            make_conn(
                family=socket.AF_INET6,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("fd00::5", 9443),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("203.0.113.10", 443),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="ESTABLISHED",
                laddr=make_addr("203.0.113.10", 443),
                raddr=make_addr("198.51.100.10", 50000),
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("0.0.0.0", 53),
                raddr=None,
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("127.0.0.1", 5353),
                raddr=None,
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("10.0.0.10", 9999),
                raddr=None,
            ),
        ]

        with mock.patch("auto_xdp.discovery.psutil", fake_psutil), \
             mock.patch("auto_xdp.discovery._net_connections", return_value=fake_connections), \
             mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_LOOPBACK", True), \
             mock.patch("auto_xdp.config.DISCOVERY_EXCLUDE_BIND_CIDRS", ["10.0.0.0/8", "fd00::/8"]):
            state = discovery_mod.get_listening_ports()

        self.assertEqual(state.tcp, {22, 443})
        self.assertEqual(state.udp, {53})
        self.assertEqual(len(state.established), 1)

    def test_sync_once_merges_permanent_ports_and_trusted_ips(self):
        backend = mock.Mock()
        state = state_mod.ObservedState(tcp={80}, udp={53}, sctp=set(), established={b"flow"})

        with mock.patch.object(syncer_mod, "get_listening_ports", return_value=state), \
             mock.patch.object(policy_mod.cfg, "TCP_PERMANENT", {22: "ssh"}), \
             mock.patch.object(policy_mod.cfg, "UDP_PERMANENT", {123: "ntp"}), \
             mock.patch.object(policy_mod.cfg, "SCTP_PERMANENT", {3868: "diameter"}), \
             mock.patch.object(policy_mod.cfg, "TRUSTED_SRC_IPS", {"203.0.113.8/32": "office"}):
            syncer_mod.sync_once(backend, dry_run=True)

        backend.reconcile.assert_called_once()
        desired_state, dry_run, observed_state = backend.reconcile.call_args.args
        self.assertTrue(dry_run)
        self.assertEqual(observed_state, state)
        self.assertEqual(desired_state.tcp_ports, {22, 80})
        self.assertEqual(desired_state.udp_ports, {53, 123})
        self.assertEqual(desired_state.sctp_ports, {3868})
        self.assertEqual(desired_state.trusted_cidrs, {"203.0.113.8/32"})

    def test_resolve_desired_state_merges_ports_and_policy_targets(self):
        observed = state_mod.ObservedState(
            tcp={80, 2222},
            udp={53},
            sctp={2905},
            tcp_processes={2222: "sshd"},
            udp_processes={53: "named"},
        )

        def fake_service_name(port, proto):
            services = {
                (22, "tcp"): "ssh",
                (53, "udp"): "domain",
                (123, "udp"): "ntp",
            }
            if (port, proto) not in services:
                return ""
            return services[(port, proto)]

        with mock.patch.object(policy_mod, "service_name", side_effect=fake_service_name), \
             mock.patch.object(policy_mod.cfg, "_SYN_RATE_BY_PROC", {"sshd": 2}), \
             mock.patch.object(policy_mod.cfg, "_SYN_RATE_BY_SERVICE", {"ssh": 2}), \
             mock.patch.object(policy_mod.cfg, "_UDP_RATE_BY_PROC", {"named": 5000}), \
             mock.patch.object(policy_mod.cfg, "_UDP_RATE_BY_SERVICE", {"domain": 5000}), \
             mock.patch.object(policy_mod.cfg, "TCP_PERMANENT", {22: "ssh"}), \
             mock.patch.object(policy_mod.cfg, "UDP_PERMANENT", {123: "ntp"}), \
             mock.patch.object(policy_mod.cfg, "SCTP_PERMANENT", {3868: "diameter"}), \
             mock.patch.object(policy_mod.cfg, "TRUSTED_SRC_IPS", {"203.0.113.8/32": "office"}), \
             mock.patch.object(policy_mod.cfg, "ACL_RULES", [{"proto": "tcp", "cidr": "203.0.113.0/24", "ports": [22, 443]}]), \
             mock.patch.object(policy_mod.cfg, "BOGON_FILTER_ENABLED", True), \
             mock.patch.object(policy_mod.cfg, "RATE_LIMIT_SOURCE_PREFIX_V4", 24), \
             mock.patch.object(policy_mod.cfg, "RATE_LIMIT_SOURCE_PREFIX_V6", 64), \
             mock.patch.object(policy_mod.cfg, "XDP_TCP_TIMEOUT_SECONDS", 600.0), \
             mock.patch.object(policy_mod.cfg, "XDP_UDP_TIMEOUT_SECONDS", 120.0), \
             mock.patch.object(policy_mod.cfg, "XDP_CONNTRACK_REFRESH_SECONDS", 45.0), \
             mock.patch.object(policy_mod.cfg, "XDP_ICMP_BURST_PACKETS", 200), \
             mock.patch.object(policy_mod.cfg, "XDP_ICMP_RATE_PPS", 50.0), \
             mock.patch.object(policy_mod.cfg, "XDP_UDP_GLOBAL_WINDOW_SECONDS", 2.0), \
             mock.patch.object(policy_mod.cfg, "XDP_RATE_WINDOW_SECONDS", 0.5), \
             mock.patch.object(policy_mod.cfg, "XDP_SYN_TIMEOUT_SECONDS", 10.0):
            desired = policy_mod.resolve_desired_state(observed)

        self.assertEqual(desired.tcp_ports, {22, 80, 2222})
        self.assertEqual(desired.udp_ports, {53, 123})
        self.assertEqual(desired.sctp_ports, {2905, 3868})
        self.assertEqual(desired.trusted_cidrs, {"203.0.113.8/32"})
        self.assertEqual(desired.tcp_syn_rate_limits, {22: 2, 2222: 2})
        self.assertEqual(desired.udp_rate_limits, {53: 5000})
        self.assertEqual(desired.acl_rules, {("tcp", "203.0.113.0/24"): frozenset({22, 443})})
        self.assertTrue(desired.bogon_filter_enabled)
        self.assertEqual(desired.rate_limit_source_prefix_v4, 24)
        self.assertEqual(desired.rate_limit_source_prefix_v6, 64)
        self.assertEqual(
            desired.xdp_runtime_config,
            (
                600_000_000_000,
                120_000_000_000,
                45_000_000_000,
                200,
                20_000_000,
                2_000_000_000,
                500_000_000,
                10_000_000_000,
            ),
        )

    def test_xdp_backend_reconcile_adds_and_removes_runtime_state(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = FakePortMap({22, 80})
        backend.udp_map = FakePortMap({53, 9999})
        backend.sctp_map = FakePortMap({3868, 9899})
        backend.trusted_map = FakeTrustedMap({"203.0.113.1/32"})
        backend.conntrack_map = FakeConntrackMap({b"keep"})
        backend.udp_conntrack_map = FakeConntrackMap({b"udp-keep"})
        backend.syn_rate_map = FakeSynRateMap({22: 1})
        backend.syn_agg_rate_map = FakeSynRateMap()
        backend.tcp_conn_limit_map = FakeSynRateMap()
        backend.udp_rate_map = FakeUdpPortMap()
        backend.udp_agg_rate_map = FakeUdpPortMap()
        backend.acl_maps = None
        backend.runtime_config_map = FakeRuntimeConfigMap()
        backend.bogon_cfg_map = None
        backend.observability_cfg_map = FakeArrayCfgMap({0})
        backend.sit4_map = None
        backend._conntrack_stale_rounds = {}
        backend._tcp_policy_map = None
        backend._udp_policy_map = None
        runtime_cfg = (
            600_000_000_000,
            120_000_000_000,
            45_000_000_000,
            200,
            20_000_000,
            2_000_000_000,
            500_000_000,
        )
        desired = state_mod.DesiredState(
            tcp_ports={22, 443},
            udp_ports={53},
            sctp_ports={3868, 2905},
            trusted_cidrs={"198.51.100.5/32"},
            conntrack_entries={b"keep", b"seed"},
            tcp_syn_rate_limits={22: 2},
            tcp_syn_agg_rate_limits={22: 16},
            tcp_conn_limits={22: 32},
            udp_rate_limits={53: 5000},
            udp_agg_rate_limits={53: 6000000},
            drop_events_enabled=False,
            xdp_runtime_config=runtime_cfg,
        )
        observed = state_mod.ObservedState(tcp_processes={22: "sshd"}, udp_processes={53: "named"})

        with mock.patch.object(cfg, "TCP_PERMANENT", {22: "ssh"}), \
             mock.patch.object(cfg, "UDP_PERMANENT", {53: "dns"}), \
             mock.patch.object(cfg, "SCTP_PERMANENT", {3868: "diameter"}), \
             mock.patch.object(cfg, "TRUSTED_SRC_IPS", {"198.51.100.5/32": "office"}):
            backend.reconcile(desired, dry_run=False, observed_state=observed)

        self.assertEqual(backend.tcp_map.ops, [(443, 1, False), (80, 0, False)])
        self.assertEqual(backend.udp_map.ops, [(9999, 0, False)])
        self.assertEqual(backend.sctp_map.ops, [(2905, 1, False), (9899, 0, False)])
        self.assertEqual(backend.trusted_map.set_ops, [("198.51.100.5/32", 1, False)])
        self.assertEqual(backend.trusted_map.delete_ops, [("203.0.113.1/32", False)])
        self.assertEqual(backend.conntrack_map.ops, [(b"seed", False)])
        self.assertEqual(backend.conntrack_map.delete_ops, [])
        self.assertEqual(backend.conntrack_map.delete_port_ops, [({80}, False)])
        self.assertEqual(backend.udp_conntrack_map.delete_port_ops, [({9999}, False)])
        self.assertEqual(backend.syn_rate_map.set_ops, [(22, 2, False)])
        self.assertEqual(backend.syn_agg_rate_map.set_ops, [(22, 16, False)])
        self.assertEqual(backend.tcp_conn_limit_map.set_ops, [(22, 32, False)])
        self.assertEqual(backend.udp_rate_map.set_ops, [(53, 5000, False)])
        self.assertEqual(backend.udp_agg_rate_map.set_ops, [(53, 6000000, False)])
        self.assertEqual(backend.runtime_config_map.ops, [(runtime_cfg, False)])
        self.assertEqual(backend.observability_cfg_map.ops, [(0, 0, False)])

    def test_xdp_backend_stale_conntrack_removal_requires_repeated_misses(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = FakePortMap()
        backend.udp_map = FakePortMap()
        backend.sctp_map = FakePortMap()
        backend.trusted_map = FakeTrustedMap()
        backend.conntrack_map = FakeConntrackMap({b"stale"})
        backend.udp_conntrack_map = FakeConntrackMap()
        backend.syn_rate_map = None
        backend.syn_agg_rate_map = None
        backend.tcp_conn_limit_map = None
        backend.udp_rate_map = None
        backend.udp_agg_rate_map = None
        backend.acl_maps = None
        backend.bogon_cfg_map = None
        backend.observability_cfg_map = FakeArrayCfgMap()
        backend.sit4_map = None
        backend.runtime_config_map = FakeRuntimeConfigMap()
        backend._tcp_policy_map = None
        backend._udp_policy_map = None
        backend._conntrack_stale_rounds = {}

        desired = state_mod.DesiredState()

        backend.reconcile(desired, dry_run=False, observed_state=state_mod.ObservedState())
        self.assertEqual(backend.conntrack_map.delete_ops, [])
        self.assertEqual(backend._conntrack_stale_rounds, {b"stale": 1})

        backend.reconcile(desired, dry_run=False, observed_state=state_mod.ObservedState())
        self.assertEqual(backend.conntrack_map.delete_ops, [(b"stale", False)])
        self.assertEqual(backend._conntrack_stale_rounds, {})

    def test_xdp_backend_reseeds_conntrack_entries_missing_from_kernel_but_still_cached(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = FakePortMap()
        backend.udp_map = FakePortMap()
        backend.sctp_map = FakePortMap()
        backend.trusted_map = FakeTrustedMap()
        backend.conntrack_map = FakeConntrackMap({b"seed"})
        backend.udp_conntrack_map = FakeConntrackMap()
        backend.syn_rate_map = None
        backend.syn_agg_rate_map = None
        backend.tcp_conn_limit_map = None
        backend.udp_rate_map = None
        backend.udp_agg_rate_map = None
        backend.acl_maps = None
        backend.bogon_cfg_map = None
        backend.observability_cfg_map = FakeArrayCfgMap()
        backend.sit4_map = None
        backend.runtime_config_map = FakeRuntimeConfigMap()
        backend._tcp_policy_map = None
        backend._udp_policy_map = None
        backend._conntrack_stale_rounds = {}
        backend.conntrack_map.existing_keys = mock.Mock(return_value=set())

        backend.reconcile(
            state_mod.DesiredState(conntrack_entries={b"seed"}),
            dry_run=False,
            observed_state=state_mod.ObservedState(),
        )

        backend.conntrack_map.existing_keys.assert_called_once_with({b"seed"})
        self.assertEqual(backend.conntrack_map.ops, [(b"seed", False)])
        self.assertEqual(backend.conntrack_map.delete_ops, [])

    def test_bpf_conntrack_map_delete_dest_ports_matches_ct_key_dport(self):
        conntrack = bpf_maps_mod.BpfConntrackMap.__new__(bpf_maps_mod.BpfConntrackMap)
        conntrack._dport_offset = 2
        deleted = []

        def ct_key(dest_port: int) -> bytes:
            key = bytearray(12)
            struct.pack_into("!H", key, 2, dest_port)
            return bytes(key)

        conntrack._cache = {
            ct_key(22),
            ct_key(80),
            ct_key(443),
        }
        conntrack._iter_raw_keys = mock.Mock(side_effect=AssertionError("should use cache"))
        conntrack.delete = mock.Mock(side_effect=lambda key, dry_run=False: deleted.append((key, dry_run)) or True)

        removed = bpf_maps_mod.BpfConntrackMap.delete_dest_ports(conntrack, {80, 443}, dry_run=False)

        self.assertEqual(removed, 2)
        self.assertEqual(len(deleted), 2)
        self.assertEqual({struct.unpack_from("!H", key, 2)[0] for key, _ in deleted}, {80, 443})

    def test_listening_port_processes_reuses_pid_lookup_cache(self):
        calls = []

        class FakePsutil:
            CONN_LISTEN = "LISTEN"

            @staticmethod
            def Process(pid):
                calls.append(pid)
                return types.SimpleNamespace(name=lambda: {77: "sshd", 88: "named"}[pid])

        conns = [
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 22),
                pid=77,
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 2222),
                pid=77,
            ),
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_DGRAM,
                status="",
                laddr=make_addr("0.0.0.0", 53),
                pid=88,
            ),
        ]

        with mock.patch.object(discovery_mod, "psutil", FakePsutil), \
             mock.patch.object(discovery_mod, "_net_connections", object()):
            state = discovery_mod.get_listening_ports(cached_conns=conns)

        self.assertEqual(state.tcp_processes, {22: "sshd", 2222: "sshd"})
        self.assertEqual(state.udp_processes, {53: "named"})
        self.assertEqual(calls, [77, 88])

    def test_service_name_reads_local_services_file_once(self):
        services_mod._service_map.cache_clear()

        fake_services = "ssh 22/tcp\nhttp 80/tcp\nntp 123/udp\n"
        open_mock = mock.mock_open(read_data=fake_services)

        with mock.patch("builtins.open", open_mock):
            self.assertEqual(services_mod.service_name(22, "tcp"), "ssh")
            self.assertEqual(services_mod.service_name(123, "udp"), "ntp")
            self.assertEqual(services_mod.service_name(9999, "tcp"), "")
            self.assertEqual(services_mod.service_name(80, "tcp"), "http")

        open_mock.assert_called_once_with("/etc/services", "r", encoding="utf-8", errors="ignore")

    def test_bpf_map_dry_run_does_not_mutate_cached_state(self):
        array_map = bpf_maps_mod.BpfArrayMap.__new__(bpf_maps_mod.BpfArrayMap)
        array_map.path = "/tmp/tcp_whitelist"
        array_map._cache = {22}
        array_map.set(80, 1, dry_run=True)
        array_map.set(22, 0, dry_run=True)
        self.assertEqual(array_map._cache, {22})

        lpm_map = bpf_maps_mod.BpfLpmMap.__new__(bpf_maps_mod.BpfLpmMap)
        lpm_map.path = "/tmp/trusted_ipv4"
        lpm_map._cache = {"203.0.113.1/32"}
        lpm_map.set("198.51.100.5/32", 1, dry_run=True)
        lpm_map.delete("203.0.113.1/32", dry_run=True)
        self.assertEqual(lpm_map._cache, {"203.0.113.1/32"})

        acl_map = bpf_maps_mod.BpfAclMap.__new__(bpf_maps_mod.BpfAclMap)
        acl_map.path = "/tmp/tcp_acl_v4"
        acl_map._family = socket.AF_INET
        acl_map._cache = {"203.0.113.0/24": frozenset({22})}
        acl_map.set("198.51.100.0/24", [443], dry_run=True)
        acl_map.delete("203.0.113.0/24", dry_run=True)
        self.assertEqual(acl_map._cache, {"203.0.113.0/24": frozenset({22})})

        conntrack_map = bpf_maps_mod.BpfConntrackMap.__new__(bpf_maps_mod.BpfConntrackMap)
        conntrack_map.path = "/tmp/tcp_conntrack"
        conntrack_map._dport_offset = 2
        conntrack_map._cache = {b"keep"}
        conntrack_map.set(b"seed", dry_run=True)
        conntrack_map.delete(b"keep", dry_run=True)
        self.assertEqual(conntrack_map._cache, {b"keep"})

        rate_map = bpf_maps_mod.BpfSynRatePortsMap.__new__(bpf_maps_mod.BpfSynRatePortsMap)
        rate_map.path = "/tmp/syn_rate_ports"
        rate_map._cache = {22: 2}
        rate_map.set(80, 10, dry_run=True)
        rate_map.delete(22, dry_run=True)
        self.assertEqual(rate_map._cache, {22: 2})

    def test_xdp_backend_apply_rate_map_delta_applies_precomputed_syn_limits(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.syn_rate_map = FakeSynRateMap({22: 1, 8080: 5})

        def fake_service_name(port, proto):
            services = {22: "ssh", 80: "http"}
            if port not in services:
                return ""
            return services[port]

        with mock.patch.object(xdp_backend_mod, "service_name", side_effect=fake_service_name):
            backend._apply_rate_map_delta(
                backend.syn_rate_map,
                {22: 2, 2222: 2},
                {8080},
                dry_run=False,
                kind="tcp",
                port_procs={2222: "sshd"},
            )

        self.assertCountEqual(
            backend.syn_rate_map.set_ops,
            [(22, 2, False), (2222, 2, False)],
        )
        self.assertEqual(backend.syn_rate_map.delete_ops, [(8080, False)])

    def test_xdp_backend_dry_run_does_not_advance_stale_conntrack_rounds(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = FakePortMap()
        backend.udp_map = FakePortMap()
        backend.sctp_map = FakePortMap()
        backend.trusted_map = FakeTrustedMap()
        backend.conntrack_map = FakeConntrackMap({b"stale"})
        backend.udp_conntrack_map = FakeConntrackMap()
        backend.syn_rate_map = None
        backend.syn_agg_rate_map = None
        backend.tcp_conn_limit_map = None
        backend.udp_rate_map = None
        backend.udp_agg_rate_map = None
        backend.acl_maps = None
        backend.bogon_cfg_map = None
        backend.observability_cfg_map = FakeArrayCfgMap()
        backend.sit4_map = None
        backend.runtime_config_map = FakeRuntimeConfigMap()
        backend._tcp_policy_map = None
        backend._udp_policy_map = None
        backend._conntrack_stale_rounds = {}

        backend.reconcile(state_mod.DesiredState(), dry_run=True, observed_state=state_mod.ObservedState())

        self.assertEqual(backend._conntrack_stale_rounds, {})
        self.assertEqual(backend.conntrack_map.delete_ops, [])

    def test_udp_port_rate_limit_prefers_process_name_then_service_name(self):
        import auto_xdp.policy as policy
        def fake_service_name(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                return ""
            return services[port]

        with mock.patch.object(policy, "service_name", side_effect=fake_service_name), \
             mock.patch.object(policy.cfg, "_UDP_RATE_BY_PROC", {"named": 5000}), \
             mock.patch.object(policy.cfg, "_UDP_RATE_BY_SERVICE", {"domain": 5000, "ntp": 500}):
            self.assertEqual(policy._udp_port_rate_limit(5353, "named"), 5000)
            self.assertEqual(policy._udp_port_rate_limit(53), 5000)
            self.assertEqual(policy._udp_port_rate_limit(123), 500)
            self.assertEqual(policy._udp_port_rate_limit(12345), 0)

    def test_syn_aggregate_and_tcp_conn_limits_derive_from_syn_rate(self):
        import auto_xdp.policy as policy
        with mock.patch.object(policy, "service_name", side_effect=lambda port, proto: "ssh" if port == 22 else "http"), \
             mock.patch.object(policy.cfg, "_SYN_RATE_BY_SERVICE", {"ssh": 2}), \
             mock.patch.object(policy.cfg, "_SYN_AGG_RATE_BY_SERVICE", {}), \
             mock.patch.object(policy.cfg, "_TCP_CONN_BY_SERVICE", {}):
            self.assertEqual(policy._syn_aggregate_rate_limit(22), 16)
            self.assertEqual(policy._tcp_conn_limit(22), 32)
            self.assertEqual(policy._syn_aggregate_rate_limit(80), 0)
            self.assertEqual(policy._tcp_conn_limit(80), 0)

    def test_udp_aggregate_byte_limit_uses_explicit_or_derived_values(self):
        import auto_xdp.policy as policy
        def fake_service_name(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                return ""
            return services[port]

        with mock.patch.object(policy, "service_name", side_effect=fake_service_name), \
             mock.patch.object(policy.cfg, "_UDP_RATE_BY_SERVICE", {"domain": 5000, "ntp": 500}), \
             mock.patch.object(policy.cfg, "_UDP_AGG_BYTES_BY_SERVICE", {"ntp": 900000}):
            self.assertEqual(policy._udp_aggregate_byte_limit(53), 6000000)
            self.assertEqual(policy._udp_aggregate_byte_limit(123), 900000)
            self.assertEqual(policy._udp_aggregate_byte_limit(9999), 0)

    def test_xdp_backend_apply_rate_map_delta_sets_rates_for_udp_ports(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.udp_rate_map = FakeUdpPortMap({53: 1000, 9999: 5})

        def fake_service_name(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                return ""
            return services[port]

        with mock.patch.object(xdp_backend_mod, "service_name", side_effect=fake_service_name):
            backend._apply_rate_map_delta(
                backend.udp_rate_map,
                {53: 5000, 123: 500},
                {9999},
                dry_run=False,
                kind="udp",
            )

        self.assertCountEqual(
            backend.udp_rate_map.set_ops,
            [(53, 5000, False), (123, 500, False)],
        )
        self.assertEqual(backend.udp_rate_map.delete_ops, [(9999, False)])

    def test_xdp_backend_apply_rate_map_delta_sets_byte_limits_for_udp_ports(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.udp_agg_rate_map = FakeUdpPortMap({53: 1000, 9999: 5})

        backend._apply_rate_map_delta(
            backend.udp_agg_rate_map,
            {53: 6000000, 123: 900000},
            {9999},
            dry_run=False,
            kind="udp_agg",
        )

        self.assertCountEqual(
            backend.udp_agg_rate_map.set_ops,
            [(53, 6000000, False), (123, 900000, False)],
        )
        self.assertEqual(backend.udp_agg_rate_map.delete_ops, [(9999, False)])

    def test_xdp_backend_close_closes_all_maps(self):
        backend = backends_mod.XdpBackend.__new__(backends_mod.XdpBackend)
        backend.tcp_map = FakePortMap()
        backend.udp_map = FakePortMap()
        backend.sctp_map = FakePortMap()
        backend.trusted_map = FakeTrustedMap()
        backend.conntrack_map = FakeConntrackMap()
        backend.udp_conntrack_map = FakeConntrackMap()
        backend._tcp_policy_map = None
        backend._udp_policy_map = None
        backend.syn_rate_map = FakeSynRateMap()
        backend.syn_agg_rate_map = FakeSynRateMap()
        backend.tcp_conn_limit_map = FakeSynRateMap()
        backend.udp_rate_map = FakeUdpPortMap()
        backend.udp_agg_rate_map = FakeUdpPortMap()
        backend.acl_maps = None
        backend.runtime_config_map = FakeRuntimeConfigMap()
        backend.bogon_cfg_map = None
        backend.observability_cfg_map = FakeArrayCfgMap()
        backend.sit4_map = None

        backend.close()

        self.assertTrue(backend.tcp_map.closed)
        self.assertTrue(backend.udp_map.closed)
        self.assertTrue(backend.sctp_map.closed)
        self.assertTrue(backend.trusted_map.closed)
        self.assertTrue(backend.conntrack_map.closed)
        self.assertTrue(backend.udp_conntrack_map.closed)
        self.assertTrue(backend.runtime_config_map.closed)
        self.assertTrue(backend.observability_cfg_map.closed)

    def test_nftables_backend_ensure_ruleset_keeps_existing_complete_ruleset(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        existing = subprocess.CompletedProcess(
            ["nft"],
            0,
            stdout=(
                f"set {cfg.NFT_TCP_SET}\n"
                f"set {cfg.NFT_UDP_SET}\n"
                f"set {cfg.NFT_SCTP_SET}\n"
                f"set {cfg.NFT_TRUSTED_SET4}\n"
                "chain input\n"
            ),
        )

        with mock.patch.object(nftables_mod, "_run_nft", return_value=existing) as run_nft:
            backend._ensure_ruleset()

        run_nft.assert_called_once_with(["list", "table", cfg.NFT_FAMILY, cfg.NFT_TABLE], check=False)

    def test_nftables_backend_ensure_ruleset_recreates_incomplete_ruleset(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        existing = subprocess.CompletedProcess(["nft"], 0, stdout="table inet auto_xdp { }")
        deleted = subprocess.CompletedProcess(["nft"], 0, stdout="")
        created = subprocess.CompletedProcess(["nft"], 0, stdout="")

        with mock.patch.object(nftables_mod, "_run_nft", side_effect=[existing, deleted, created]) as run_nft:
            backend._ensure_ruleset()

        self.assertEqual(run_nft.call_args_list[1], mock.call(["delete", "table", cfg.NFT_FAMILY, cfg.NFT_TABLE], check=True))
        create_call = run_nft.call_args_list[2]
        self.assertEqual(create_call.args[0], ["-f", "-"])
        self.assertIn(f"set {cfg.NFT_TCP_SET}", create_call.kwargs["input_text"])

    def test_nftables_backend_refreshes_caches_from_existing_sets(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        backend._tcp_cache = set()
        backend._udp_cache = set()
        backend._sctp_cache = set()
        backend._trusted_cache = set()

        with mock.patch.object(
            nftables_mod,
            "_run_nft",
            side_effect=[
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 22, 443 }"),
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 53 }"),
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 3868 }"),
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 198.51.100.0/24 }"),
                subprocess.CompletedProcess(["nft"], 0, stdout="elements = { 2001:db8::/64 }"),
            ],
        ):
            backend._refresh_caches()

        self.assertEqual(backend._tcp_cache, {22, 443})
        self.assertEqual(backend._udp_cache, {53})
        self.assertEqual(backend._sctp_cache, {3868})
        self.assertEqual(backend._trusted_cache, {"198.51.100.0/24", "2001:db8::/64"})

    def test_nftables_backend_apply_reconcile_plan_emits_incremental_updates(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        backend._tcp_cache = {22, 80}
        backend._udp_cache = {53, 9999}
        backend._sctp_cache = {3868, 9899}
        backend._trusted_cache = {"203.0.113.1/32"}

        plan = state_mod.ReconcilePlan(
            tcp_ports_to_add={443},
            tcp_ports_to_remove={80},
            udp_ports_to_remove={9999},
            sctp_ports_to_add={2905},
            sctp_ports_to_remove={9899},
            trusted_cidrs_to_add={"198.51.100.5/32"},
            trusted_cidrs_to_remove={"203.0.113.1/32"},
        )

        with mock.patch.object(nftables_mod, "_run_nft") as run_nft:
            backend.apply_reconcile_plan(
                plan,
                dry_run=False,
                desired_state=state_mod.DesiredState(),
            )

        self.assertEqual(run_nft.call_count, 2)
        ports_script = run_nft.call_args_list[0].kwargs["input_text"]
        trusted_script = run_nft.call_args_list[1].kwargs["input_text"]
        self.assertIn("delete element inet auto_xdp tcp_ports { 80 }", ports_script)
        self.assertIn("add element inet auto_xdp tcp_ports { 443 }", ports_script)
        self.assertIn("delete element inet auto_xdp udp_ports { 9999 }", ports_script)
        self.assertIn("add element inet auto_xdp sctp_ports { 2905 }", ports_script)
        self.assertIn("delete element inet auto_xdp sctp_ports { 9899 }", ports_script)
        self.assertIn("delete element inet auto_xdp trusted_v4 { 203.0.113.1/32 }", trusted_script)
        self.assertIn("add element inet auto_xdp trusted_v4 { 198.51.100.5/32 }", trusted_script)

    def test_nftables_backend_dry_run_does_not_mutate_caches(self):
        backend = backends_mod.NftablesBackend.__new__(backends_mod.NftablesBackend)
        backend._tcp_cache = {22, 80}
        backend._udp_cache = {53, 9999}
        backend._sctp_cache = {3868, 9899}
        backend._trusted_cache = {"203.0.113.1/32"}

        plan = state_mod.ReconcilePlan(
            tcp_ports_to_add={443},
            tcp_ports_to_remove={80},
            udp_ports_to_remove={9999},
            sctp_ports_to_add={2905},
            sctp_ports_to_remove={9899},
            trusted_cidrs_to_add={"198.51.100.5/32"},
            trusted_cidrs_to_remove={"203.0.113.1/32"},
        )

        with mock.patch.object(nftables_mod, "_run_nft"):
            backend.apply_reconcile_plan(plan, dry_run=True, desired_state=state_mod.DesiredState())

        self.assertEqual(backend._tcp_cache, {22, 80})
        self.assertEqual(backend._udp_cache, {53, 9999})
        self.assertEqual(backend._sctp_cache, {3868, 9899})
        self.assertEqual(backend._trusted_cache, {"203.0.113.1/32"})

    def test_open_backend_validates_requested_backend(self):
        status = backends_mod.BackendStatus(
            "xdp",
            False,
            "required XDP maps missing",
            {"missing_maps": "/sys/fs/bpf/xdp_fw/tcp_whitelist"},
            {"bpftool": True, "required_maps": False},
        )
        with mock.patch.object(backends_mod.XdpBackend, "probe", return_value=status):
            with self.assertRaisesRegex(RuntimeError, "failed checks: required_maps"):
                syncer_mod.open_backend(syncer_mod.BACKEND_XDP)

        with self.assertRaisesRegex(RuntimeError, "Unsupported backend"):
            syncer_mod.open_backend("invalid")

    def test_open_backend_prefers_xdp_and_falls_back_to_nftables(self):
        with mock.patch.object(syncer_mod, "XdpBackend") as xdp_backend:
            xdp_backend.probe.return_value = backends_mod.BackendStatus("xdp", True)
            xdp_backend.return_value = "xdp-backend"
            backend = syncer_mod.open_backend(syncer_mod.BACKEND_AUTO)
        self.assertEqual(backend, "xdp-backend")
        xdp_backend.assert_called_once_with()

        with mock.patch.object(syncer_mod, "XdpBackend") as xdp_backend, \
             mock.patch.object(syncer_mod, "NftablesBackend") as nft_backend:
            xdp_backend.probe.return_value = backends_mod.BackendStatus("xdp", False, "required XDP maps missing")
            nft_backend.probe.return_value = backends_mod.BackendStatus("nftables", True)
            nft_backend.return_value = "nft-backend"
            backend = syncer_mod.open_backend(syncer_mod.BACKEND_AUTO)
        self.assertEqual(backend, "nft-backend")
        nft_backend.assert_called_once_with()

    def test_xdp_probe_checks_runtime_prerequisites(self):
        with mock.patch.object(xdp_backend_mod.shutil, "which", return_value=None):
            status = xdp_backend_mod.XdpBackend.probe()
        self.assertFalse(status.available)
        self.assertEqual(status.reason, "bpftool not found")
        self.assertEqual(status.failed_checks, ["bpftool"])
        self.assertEqual(status.details["bpftool"], "not found")

        with mock.patch.object(xdp_backend_mod.shutil, "which", return_value="/usr/sbin/bpftool"), \
             mock.patch.object(xdp_backend_mod.os.path, "exists", return_value=False):
            status = xdp_backend_mod.XdpBackend.probe()
        self.assertFalse(status.available)
        self.assertEqual(status.reason, "required XDP maps missing")
        self.assertEqual(status.failed_checks, ["required_maps"])
        self.assertIn(cfg.TCP_MAP_PATH, status.details["missing_maps"])

        def fake_exists(path):
            return path in cfg.REQUIRED_XDP_MAP_PATHS

        with mock.patch.object(xdp_backend_mod.shutil, "which", return_value="/usr/sbin/bpftool"), \
             mock.patch.object(xdp_backend_mod.os.path, "exists", side_effect=fake_exists), \
             mock.patch.object(cfg, "XDP_OBJ_PATH", "/tmp/xdp_firewall.o"):
            status = xdp_backend_mod.XdpBackend.probe()
        self.assertFalse(status.available)
        self.assertEqual(status.reason, "configured XDP object file missing")
        self.assertEqual(status.failed_checks, ["xdp_obj"])
        self.assertEqual(status.details["xdp_obj_path"], "/tmp/xdp_firewall.o")

    def test_backend_status_formats_reason_checks_and_details(self):
        status = backends_mod.BackendStatus(
            "xdp",
            False,
            "required XDP maps missing",
            {"missing_maps": "/sys/fs/bpf/xdp_fw/tcp_whitelist"},
            {"bpftool": True, "required_maps": False},
        )

        self.assertEqual(
            status.format_message(),
            "required XDP maps missing; failed checks: required_maps; "
            "missing_maps=/sys/fs/bpf/xdp_fw/tcp_whitelist",
        )

    def test_drain_proc_events_detects_exec_and_exit_notifications(self):
        payload = make_proc_event_message(proc_events_mod._PROC_EVENT_EXEC)

        class FakeSocket:
            def recv(self, size):
                return payload

        fake_sock = FakeSocket()
        with mock.patch.object(proc_events_mod.select, "select", side_effect=[([fake_sock], [], []), ([], [], [])]):
            triggered = proc_events_mod.drain_proc_events(fake_sock)

        self.assertTrue(triggered)

    def test_main_runs_one_sync_and_closes_backend(self):
        backend = mock.MagicMock()
        backend.__enter__.return_value = backend
        backend.__exit__.side_effect = lambda *args: backend.close()
        trusted_ips = {}

        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--backend",
            "nftables",
            "--trusted-ip",
            "198.51.100.8",
            "office",
            "--log-level",
            "debug",
        ]), mock.patch.object(cfg, "TRUSTED_SRC_IPS", trusted_ips), \
             mock.patch.object(cli_mod, "open_backend", return_value=backend) as open_backend, \
             mock.patch.object(cli_mod, "sync_once") as sync_once:
            cli_mod.main()

        open_backend.assert_called_once_with("nftables")
        sync_once.assert_called_once_with(backend, False)
        backend.close.assert_called_once_with()
        self.assertEqual(trusted_ips, {"198.51.100.8/32": "office"})

    def test_main_watch_mode_delegates_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--dry-run",
            "--backend",
            "auto",
        ]), mock.patch.object(cli_mod, "watch") as watch:
            cli_mod.main()

        watch.assert_called_once_with(
            True, "auto", cfg.TOML_CONFIG_PATH, {}, cli_log_level=None
        )

    def test_main_uses_configured_preferred_backend_as_default(self):
        backend = mock.MagicMock()
        backend.__enter__.return_value = backend
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--config",
            "/tmp/test.toml",
        ]), mock.patch.object(
            cli_mod,
            "load_toml_config",
            return_value={"daemon": {"preferred_backend": "nftables"}},
        ), mock.patch.object(cli_mod, "open_backend", return_value=backend) as open_backend, \
             mock.patch.object(cli_mod, "sync_once") as sync_once:
            old_backend = cfg.PREFERRED_BACKEND
            try:
                cli_mod.main()
            finally:
                cfg.PREFERRED_BACKEND = old_backend

        open_backend.assert_called_once_with("nftables")
        sync_once.assert_called_once_with(backend, False)

    def test_main_watch_mode_passes_custom_config_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--config",
            "/tmp/test.toml",
        ]), mock.patch.object(cli_mod, "watch") as watch:
            cli_mod.main()

        watch.assert_called_once_with(
            mock.ANY, mock.ANY, "/tmp/test.toml", {},
            cli_log_level=None,
        )

    def test_main_watch_mode_passes_cli_trusted_ips_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--trusted-ip", "1.2.3.4", "myhost",
            "--trusted-ip", "10.0.0.0/8", "internal",
        ]), mock.patch.object(cli_mod, "watch") as watch:
            cli_mod.main()

        watch.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY,
            {"1.2.3.4/32": "myhost", "10.0.0.0/8": "internal"},
            cli_log_level=None,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
