import socket
import struct
import subprocess
import sys
import re
import types
import unittest
from pathlib import Path
from unittest import mock

import support


xdp = support.load_module("xdp_port_sync_test", "xdp_port_sync.py")


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
        self.closed = False

    def active_keys(self):
        return set(self._active)

    def set(self, key, dry_run=False):
        self.ops.append((key, dry_run))
        self._active.add(key)
        return True

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


def make_proc_event_message(what: int) -> bytes:
    payload = struct.pack("I", what)
    cn = struct.pack("IIIIHH", xdp._CN_IDX_PROC, 1, 0, 0, len(payload), 0) + payload
    msg_len = xdp._NLMSG_HDRLEN + len(cn)
    hdr = struct.pack("IHHII", msg_len, xdp._NLMSG_MIN_TYPE, 0, 0, 0)
    padded_len = (msg_len + 3) & ~3
    return hdr + cn + (b"\x00" * (padded_len - msg_len))


class XdpPortSyncTests(unittest.TestCase):
    def test_udp_malformed_drop_only_rejects_port_zero(self):
        source = (Path(__file__).resolve().parents[2] / "xdp_firewall.c").read_text()
        self.assertRegex(
            source,
            r"if\s*\(\s*udp->source\s*==\s*0\s*\|\|\s*udp->dest\s*==\s*0\s*\)",
        )
        self.assertNotIn("udp->source == udp->dest", source)

    def test_render_nft_ports_sorts_ports(self):
        self.assertEqual(xdp._render_nft_ports({443, 22, 80}), "{ 22, 80, 443 }")

    def test_port_rate_limit_prefers_process_name_then_service_name(self):
        import auto_xdp.policy as policy
        with mock.patch.object(policy.socket, "getservbyport", side_effect=lambda port, proto: "ssh" if port == 22 else "http"), \
             mock.patch.object(policy, "_SYN_RATE_BY_PROC", {"sshd": 2}), \
             mock.patch.object(policy, "_SYN_RATE_BY_SERVICE", {"ssh": 2}):
            self.assertEqual(xdp._port_rate_limit(2222, "sshd"), 2)
            self.assertEqual(xdp._port_rate_limit(22), 2)
            self.assertEqual(xdp._port_rate_limit(80), 0)

    def test_bind_ip_is_exposed_keeps_wildcard_but_filters_loopback_and_private(self):
        with mock.patch.object(xdp.cfg, "DISCOVERY_EXCLUDE_LOOPBACK", True), \
             mock.patch.object(xdp, "DISCOVERY_EXCLUDE_BIND_CIDRS", ["10.0.0.0/8", "fd00::/8"]):
            exclude_nets = xdp._discovery_exclude_networks()

        self.assertTrue(xdp._bind_ip_is_exposed("0.0.0.0", exclude_nets))
        self.assertTrue(xdp._bind_ip_is_exposed("::", exclude_nets))
        self.assertFalse(xdp._bind_ip_is_exposed("127.0.0.1", exclude_nets))
        self.assertFalse(xdp._bind_ip_is_exposed("::1", exclude_nets))
        self.assertFalse(xdp._bind_ip_is_exposed("10.1.2.3", exclude_nets))
        self.assertFalse(xdp._bind_ip_is_exposed("fd00::1234", exclude_nets))
        self.assertTrue(xdp._bind_ip_is_exposed("203.0.113.10", exclude_nets))

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

        with mock.patch.object(xdp, "psutil", fake_psutil), \
             mock.patch.object(xdp, "_net_connections", return_value=fake_connections), \
             mock.patch.object(xdp.cfg, "DISCOVERY_EXCLUDE_LOOPBACK", True), \
             mock.patch.object(xdp, "DISCOVERY_EXCLUDE_BIND_CIDRS", ["10.0.0.0/8", "fd00::/8"]):
            state = xdp.get_listening_ports()

        self.assertEqual(state.tcp, {22, 443})
        self.assertEqual(state.udp, {53})
        self.assertEqual(state.established, set())

    def test_sync_once_merges_permanent_ports_and_trusted_ips(self):
        backend = mock.Mock()
        state = xdp.PortState(tcp={80}, udp={53}, sctp=set(), established={b"flow"})

        with mock.patch.object(xdp, "get_listening_ports", return_value=state), \
             mock.patch.object(xdp, "_net_connections", return_value=[]), \
             mock.patch.object(xdp, "TCP_PERMANENT", {22: "ssh"}), \
             mock.patch.object(xdp, "UDP_PERMANENT", {123: "ntp"}), \
             mock.patch.object(xdp, "SCTP_PERMANENT", {3868: "diameter"}), \
             mock.patch.object(xdp, "TRUSTED_SRC_IPS", {"203.0.113.8/32": "office"}):
            xdp.sync_once(backend, dry_run=True)

        backend.sync_ports.assert_called_once_with(
            {22, 80},
            {53, 123},
            {3868},
            {"203.0.113.8/32"},
            set(),
            True,
            cached_conns=[],
        )

    def test_xdp_backend_sync_ports_adds_and_removes_runtime_state(self):
        backend = xdp.XdpBackend.__new__(xdp.XdpBackend)
        backend.tcp_map = FakePortMap({22, 80})
        backend.udp_map = FakePortMap({53, 9999})
        backend.sctp_map = FakePortMap({3868, 9899})
        backend.trusted_map = FakeTrustedMap({"203.0.113.1/32"})
        backend.conntrack_map = FakeConntrackMap({b"keep"})
        backend.syn_rate_map = FakeSynRateMap({22: 1})
        backend.syn_agg_rate_map = FakeSynRateMap()
        backend.tcp_conn_limit_map = FakeSynRateMap()
        backend.udp_rate_map = FakeUdpPortMap()
        backend.udp_agg_rate_map = FakeUdpPortMap()
        backend.acl_maps = None
        backend.bogon_cfg_map = None
        backend._sync_syn_rate = mock.Mock()
        backend._sync_syn_agg_rate = mock.Mock()
        backend._sync_tcp_conn_limit = mock.Mock()
        backend._sync_udp_rate = mock.Mock()
        backend._sync_udp_agg_rate = mock.Mock()

        with mock.patch.object(xdp, "TCP_PERMANENT", {22: "ssh"}), \
             mock.patch.object(xdp, "UDP_PERMANENT", {53: "dns"}), \
             mock.patch.object(xdp, "SCTP_PERMANENT", {3868: "diameter"}), \
             mock.patch.object(xdp, "TRUSTED_SRC_IPS", {"198.51.100.5/32": "office"}):
            backend.sync_ports(
                tcp_target={22, 443},
                udp_target={53},
                sctp_target={3868, 2905},
                trusted_target={"198.51.100.5/32"},
                conntrack_target={b"keep", b"seed"},
                dry_run=False,
            )

        self.assertEqual(backend.tcp_map.ops, [(443, 1, False), (80, 0, False)])
        self.assertEqual(backend.udp_map.ops, [(9999, 0, False)])
        self.assertEqual(backend.sctp_map.ops, [(2905, 1, False), (9899, 0, False)])
        self.assertEqual(backend.trusted_map.set_ops, [("198.51.100.5/32", 1, False)])
        self.assertEqual(backend.trusted_map.delete_ops, [("203.0.113.1/32", False)])
        self.assertEqual(backend.conntrack_map.ops, [])
        backend._sync_syn_rate.assert_called_once_with({22, 443}, False, None)
        backend._sync_syn_agg_rate.assert_called_once_with({22, 443}, False, None)
        backend._sync_tcp_conn_limit.assert_called_once_with({22, 443}, False, None)
        backend._sync_udp_rate.assert_called_once_with({53}, False, None)
        backend._sync_udp_agg_rate.assert_called_once_with({53}, False, None)

    def test_xdp_backend_sync_syn_rate_uses_proc_names_and_service_names(self):
        import auto_xdp.policy as policy
        backend = xdp.XdpBackend.__new__(xdp.XdpBackend)
        backend.syn_rate_map = FakeSynRateMap({22: 1, 8080: 5})

        class FakePsutil:
            CONN_LISTEN = "LISTEN"

            @staticmethod
            def Process(pid):
                return types.SimpleNamespace(name=lambda: {77: "sshd"}[pid])

        conns = [
            make_conn(
                family=socket.AF_INET,
                conn_type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("0.0.0.0", 2222),
                pid=77,
            )
        ]

        def fake_getservbyport(port, proto):
            services = {22: "ssh", 80: "http"}
            if port not in services:
                raise OSError("unknown service")
            return services[port]

        with mock.patch.object(xdp, "psutil", FakePsutil), \
             mock.patch.object(xdp, "_net_connections", return_value=conns), \
             mock.patch.object(policy.socket, "getservbyport", side_effect=fake_getservbyport), \
             mock.patch.object(policy, "_SYN_RATE_BY_PROC", {"sshd": 2}), \
             mock.patch.object(policy, "_SYN_RATE_BY_SERVICE", {"ssh": 2}):
            backend._sync_syn_rate({22, 80, 2222}, dry_run=False)

        self.assertCountEqual(
            backend.syn_rate_map.set_ops,
            [(22, 2, False), (2222, 2, False)],
        )
        self.assertEqual(backend.syn_rate_map.delete_ops, [(8080, False)])

    def test_udp_port_rate_limit_prefers_process_name_then_service_name(self):
        import auto_xdp.policy as policy
        def fake_getservbyport(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                raise OSError("unknown service")
            return services[port]

        with mock.patch.object(policy.socket, "getservbyport", side_effect=fake_getservbyport), \
             mock.patch.object(policy, "_UDP_RATE_BY_PROC", {"named": 5000}), \
             mock.patch.object(policy, "_UDP_RATE_BY_SERVICE", {"domain": 5000, "ntp": 500}):
            self.assertEqual(xdp._udp_port_rate_limit(5353, "named"), 5000)
            self.assertEqual(xdp._udp_port_rate_limit(53), 5000)
            self.assertEqual(xdp._udp_port_rate_limit(123), 500)
            self.assertEqual(xdp._udp_port_rate_limit(12345), 0)

    def test_syn_aggregate_and_tcp_conn_limits_derive_from_syn_rate(self):
        import auto_xdp.policy as policy
        with mock.patch.object(policy.socket, "getservbyport", side_effect=lambda port, proto: "ssh" if port == 22 else "http"), \
             mock.patch.object(policy, "_SYN_RATE_BY_SERVICE", {"ssh": 2}), \
             mock.patch.object(policy, "_SYN_AGG_RATE_BY_SERVICE", {}), \
             mock.patch.object(policy, "_TCP_CONN_BY_SERVICE", {}):
            self.assertEqual(xdp._syn_aggregate_rate_limit(22), 16)
            self.assertEqual(xdp._tcp_conn_limit(22), 32)
            self.assertEqual(xdp._syn_aggregate_rate_limit(80), 0)
            self.assertEqual(xdp._tcp_conn_limit(80), 0)

    def test_udp_aggregate_byte_limit_uses_explicit_or_derived_values(self):
        import auto_xdp.policy as policy
        def fake_getservbyport(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                raise OSError("unknown service")
            return services[port]

        with mock.patch.object(policy.socket, "getservbyport", side_effect=fake_getservbyport), \
             mock.patch.object(policy, "_UDP_RATE_BY_SERVICE", {"domain": 5000, "ntp": 500}), \
             mock.patch.object(policy, "_UDP_AGG_BYTES_BY_SERVICE", {"ntp": 900000}):
            self.assertEqual(xdp._udp_aggregate_byte_limit(53), 6000000)
            self.assertEqual(xdp._udp_aggregate_byte_limit(123), 900000)
            self.assertEqual(xdp._udp_aggregate_byte_limit(9999), 0)

    def test_xdp_backend_sync_udp_rate_sets_rates_for_udp_ports(self):
        import auto_xdp.policy as policy
        backend = xdp.XdpBackend.__new__(xdp.XdpBackend)
        backend.udp_rate_map = FakeUdpPortMap({53: 1000, 9999: 5})

        def fake_getservbyport(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                raise OSError("unknown service")
            return services[port]

        with mock.patch.object(policy.socket, "getservbyport", side_effect=fake_getservbyport), \
             mock.patch.object(policy, "_UDP_RATE_BY_SERVICE", {"domain": 5000, "ntp": 500}):
            backend._sync_udp_rate({53, 123}, dry_run=False)

        self.assertCountEqual(
            backend.udp_rate_map.set_ops,
            [(53, 5000, False), (123, 500, False)],
        )
        self.assertEqual(backend.udp_rate_map.delete_ops, [(9999, False)])

    def test_xdp_backend_sync_udp_aggregate_sets_byte_limits_for_udp_ports(self):
        import auto_xdp.policy as policy
        backend = xdp.XdpBackend.__new__(xdp.XdpBackend)
        backend.udp_agg_rate_map = FakeUdpPortMap({53: 1000, 9999: 5})

        def fake_getservbyport(port, proto):
            services = {53: "domain", 123: "ntp"}
            if port not in services:
                raise OSError("unknown service")
            return services[port]

        with mock.patch.object(policy.socket, "getservbyport", side_effect=fake_getservbyport), \
             mock.patch.object(policy, "_UDP_RATE_BY_SERVICE", {"domain": 5000}), \
             mock.patch.object(policy, "_UDP_AGG_BYTES_BY_SERVICE", {"ntp": 900000}):
            backend._sync_udp_agg_rate({53, 123}, dry_run=False)

        self.assertCountEqual(
            backend.udp_agg_rate_map.set_ops,
            [(53, 6000000, False), (123, 900000, False)],
        )
        self.assertEqual(backend.udp_agg_rate_map.delete_ops, [(9999, False)])

    def test_xdp_backend_close_closes_all_maps(self):
        backend = xdp.XdpBackend.__new__(xdp.XdpBackend)
        backend.tcp_map = FakePortMap()
        backend.udp_map = FakePortMap()
        backend.sctp_map = FakePortMap()
        backend.trusted_map = FakeTrustedMap()
        backend.conntrack_map = FakeConntrackMap()
        backend.syn_rate_map = FakeSynRateMap()
        backend.syn_agg_rate_map = FakeSynRateMap()
        backend.tcp_conn_limit_map = FakeSynRateMap()
        backend.udp_rate_map = FakeUdpPortMap()
        backend.udp_agg_rate_map = FakeUdpPortMap()
        backend.acl_maps = None
        backend.bogon_cfg_map = None

        backend.close()

        self.assertTrue(backend.tcp_map.closed)
        self.assertTrue(backend.udp_map.closed)
        self.assertTrue(backend.sctp_map.closed)
        self.assertTrue(backend.trusted_map.closed)
        self.assertTrue(backend.conntrack_map.closed)
        self.assertTrue(backend.syn_rate_map.closed)
        self.assertTrue(backend.syn_agg_rate_map.closed)
        self.assertTrue(backend.tcp_conn_limit_map.closed)
        self.assertTrue(backend.udp_rate_map.closed)
        self.assertTrue(backend.udp_agg_rate_map.closed)

    def test_nftables_backend_ensure_ruleset_keeps_existing_complete_ruleset(self):
        backend = xdp.NftablesBackend.__new__(xdp.NftablesBackend)
        existing = subprocess.CompletedProcess(
            ["nft"],
            0,
            stdout=(
                f"set {xdp.NFT_TCP_SET}\n"
                f"set {xdp.NFT_UDP_SET}\n"
                f"set {xdp.NFT_SCTP_SET}\n"
                f"set {xdp.NFT_TRUSTED_SET4}\n"
                "chain input\n"
            ),
        )

        with mock.patch.object(xdp, "_run_nft", return_value=existing) as run_nft:
            backend._ensure_ruleset()

        run_nft.assert_called_once_with(["list", "table", xdp.NFT_FAMILY, xdp.NFT_TABLE], check=False)

    def test_nftables_backend_ensure_ruleset_recreates_incomplete_ruleset(self):
        backend = xdp.NftablesBackend.__new__(xdp.NftablesBackend)
        existing = subprocess.CompletedProcess(["nft"], 0, stdout="table inet auto_xdp { }")
        deleted = subprocess.CompletedProcess(["nft"], 0, stdout="")
        created = subprocess.CompletedProcess(["nft"], 0, stdout="")

        with mock.patch.object(xdp, "_run_nft", side_effect=[existing, deleted, created]) as run_nft:
            backend._ensure_ruleset()

        self.assertEqual(run_nft.call_args_list[1], mock.call(["delete", "table", xdp.NFT_FAMILY, xdp.NFT_TABLE], check=True))
        create_call = run_nft.call_args_list[2]
        self.assertEqual(create_call.args[0], ["-f", "-"])
        self.assertIn(f"set {xdp.NFT_TCP_SET}", create_call.kwargs["input_text"])

    def test_nftables_backend_apply_targets_flushes_and_reloads_sets(self):
        backend = xdp.NftablesBackend.__new__(xdp.NftablesBackend)

        with mock.patch.object(xdp, "_run_nft") as run_nft:
            backend._apply_targets({443, 22}, {53}, {3868}, dry_run=False)

        run_nft.assert_called_once()
        self.assertEqual(run_nft.call_args.args[0], ["-f", "-"])
        script = run_nft.call_args.kwargs["input_text"]
        self.assertIn("flush set inet auto_xdp tcp_ports", script)
        self.assertIn("add element inet auto_xdp tcp_ports { 22, 443 }", script)
        self.assertIn("add element inet auto_xdp udp_ports { 53 }", script)
        self.assertIn("add element inet auto_xdp sctp_ports { 3868 }", script)

    def test_open_backend_validates_requested_backend(self):
        with mock.patch.object(xdp.os.path, "exists", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "required XDP maps missing"):
                xdp.open_backend(xdp.BACKEND_XDP)

            with self.assertRaisesRegex(RuntimeError, "Unsupported backend"):
                xdp.open_backend("invalid")

    def test_open_backend_prefers_xdp_and_falls_back_to_nftables(self):
        exists_map = {path: True for path in xdp.REQUIRED_XDP_MAP_PATHS}

        with mock.patch.object(xdp.os.path, "exists", side_effect=lambda path: exists_map.get(path, False)), \
             mock.patch.object(xdp, "XdpBackend", return_value="xdp-backend") as xdp_backend:
            backend = xdp.open_backend(xdp.BACKEND_AUTO)
        self.assertEqual(backend, "xdp-backend")
        xdp_backend.assert_called_once_with()

        with mock.patch.object(xdp.os.path, "exists", return_value=False), \
             mock.patch.object(xdp, "NftablesBackend", return_value="nft-backend") as nft_backend:
            backend = xdp.open_backend(xdp.BACKEND_AUTO)
        self.assertEqual(backend, "nft-backend")
        nft_backend.assert_called_once_with()

    def test_drain_proc_events_detects_exec_and_exit_notifications(self):
        payload = make_proc_event_message(xdp._PROC_EVENT_EXEC)

        class FakeSocket:
            def recv(self, size):
                return payload

        fake_sock = FakeSocket()
        with mock.patch.object(xdp.select, "select", side_effect=[([fake_sock], [], []), ([], [], [])]):
            triggered = xdp.drain_proc_events(fake_sock)

        self.assertTrue(triggered)

    def test_main_runs_one_sync_and_closes_backend(self):
        backend = mock.Mock()
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
        ]), mock.patch.object(xdp, "TRUSTED_SRC_IPS", trusted_ips), \
             mock.patch.object(xdp, "open_backend", return_value=backend) as open_backend, \
             mock.patch.object(xdp, "sync_once") as sync_once:
            xdp.main()

        open_backend.assert_called_once_with("nftables")
        sync_once.assert_called_once_with(backend, False)
        backend.close.assert_called_once_with()
        self.assertEqual(trusted_ips, {"198.51.100.8/32": "office"})

    def test_main_watch_mode_delegates_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--interval",
            "5",
            "--dry-run",
            "--backend",
            "auto",
        ]), mock.patch.object(xdp, "watch") as watch:
            xdp.main()

        watch.assert_called_once_with(
            5, True, "auto", xdp.TOML_CONFIG_PATH, {}, cli_log_level=None
        )

    def test_main_watch_mode_passes_custom_config_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--config",
            "/tmp/test.toml",
        ]), mock.patch.object(xdp, "watch") as watch:
            xdp.main()

        watch.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY, "/tmp/test.toml", {},
            cli_log_level=None,
        )

    def test_main_watch_mode_passes_cli_trusted_ips_to_watch(self):
        with mock.patch.object(sys, "argv", [
            "xdp_port_sync.py",
            "--watch",
            "--trusted-ip", "1.2.3.4", "myhost",
            "--trusted-ip", "10.0.0.0/8", "internal",
        ]), mock.patch.object(xdp, "watch") as watch:
            xdp.main()

        watch.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY, mock.ANY,
            {"1.2.3.4/32": "myhost", "10.0.0.0/8": "internal"},
            cli_log_level=None,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
