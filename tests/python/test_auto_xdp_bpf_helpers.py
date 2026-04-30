import io
import socket
import struct
import sys
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

import support


helpers = support.load_module("auto_xdp_bpf_helpers_test", "auto_xdp_bpf_helpers.py")


def make_addr(ip: str, port: int):
    return types.SimpleNamespace(ip=ip, port=port)


class AutoXdpBpfHelpersTests(unittest.TestCase):
    def test_pack_ct_key_ipv4(self):
        conn = types.SimpleNamespace(
            family=socket.AF_INET,
            laddr=make_addr("192.0.2.10", 443),
            raddr=make_addr("198.51.100.20", 50000),
        )

        packed = helpers.pack_ct_key(conn)
        expected = struct.pack(
            "!HH4s4s",
            50000,
            443,
            socket.inet_aton("198.51.100.20"),
            socket.inet_aton("192.0.2.10"),
        )
        self.assertEqual(packed, expected)

    def test_pack_ct_key_ipv6(self):
        conn = types.SimpleNamespace(
            family=socket.AF_INET6,
            laddr=make_addr("2001:db8::10", 443),
            raddr=make_addr("2001:db8::20", 50000),
        )

        packed = helpers.pack_ct_key(conn)
        expected = struct.pack(
            "!HH16s16s",
            50000,
            443,
            socket.inet_pton(socket.AF_INET6, "2001:db8::20"),
            socket.inet_pton(socket.AF_INET6, "2001:db8::10"),
        )
        self.assertEqual(packed, expected)

    def test_iter_established_tcp_filters_connections(self):
        fake_psutil = types.SimpleNamespace(CONN_ESTABLISHED="ESTABLISHED")
        fake_psutil.net_connections = lambda kind: [
            types.SimpleNamespace(
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                status="ESTABLISHED",
                laddr=make_addr("192.0.2.1", 80),
                raddr=make_addr("198.51.100.1", 50000),
            ),
            types.SimpleNamespace(
                family=socket.AF_INET6,
                type=socket.SOCK_DGRAM,
                status="ESTABLISHED",
                laddr=make_addr("2001:db8::1", 53),
                raddr=make_addr("2001:db8::2", 5353),
            ),
            types.SimpleNamespace(
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
                status="LISTEN",
                laddr=make_addr("192.0.2.2", 22),
                raddr=None,
            ),
        ]

        with mock.patch.object(helpers, "psutil", fake_psutil):
            conns = list(helpers.iter_established_tcp())

        self.assertEqual(len(conns), 1)
        self.assertEqual(conns[0].laddr.port, 80)

    def test_cmd_pin_maps_pins_each_reported_map(self):
        check_output = mock.Mock(
            side_effect=[
                '{"map_ids": [7, 8]}',
                '{"name": "tcp_whitelist"}',
                '{"name": "udp_whitelist"}',
            ]
        )

        with mock.patch.object(helpers.subprocess, "check_output", check_output), \
             mock.patch.object(helpers.subprocess, "check_call") as check_call:
            rc = helpers.cmd_pin_maps(42, "/sys/fs/bpf/xdp_fw")

        self.assertEqual(rc, 0)
        self.assertEqual(check_call.call_count, 2)
        check_call.assert_any_call(
            ["bpftool", "map", "pin", "id", "7", "/sys/fs/bpf/xdp_fw/tcp_whitelist"]
        )
        check_call.assert_any_call(
            ["bpftool", "map", "pin", "id", "8", "/sys/fs/bpf/xdp_fw/udp_whitelist"]
        )

    def test_cmd_pin_maps_falls_back_to_nested_maps_list(self):
        check_output = mock.Mock(
            side_effect=[
                '{"maps": [{"id": 99}]}',
                '{"name": "pkt_counters"}',
            ]
        )

        with mock.patch.object(helpers.subprocess, "check_output", check_output), \
             mock.patch.object(helpers.subprocess, "check_call") as check_call:
            rc = helpers.cmd_pin_maps(11, "/pins")

        self.assertEqual(rc, 0)
        check_call.assert_called_once_with(
            ["bpftool", "map", "pin", "id", "99", "/pins/pkt_counters"]
        )

    def test_cmd_pin_maps_returns_error_when_no_map_ids_exist(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), \
             mock.patch.object(helpers.subprocess, "check_output", return_value="{}"):
            rc = helpers.cmd_pin_maps(1, "/pins")

        self.assertEqual(rc, 1)
        self.assertIn("no map ids found", stderr.getvalue())

    def test_cmd_seed_tcp_conntrack_prints_zero_without_psutil(self):
        stdout = io.StringIO()
        with redirect_stdout(stdout), mock.patch.object(helpers, "psutil", None):
            rc = helpers.cmd_seed_tcp_conntrack("/pins/tcp_ct4", "/pins/tcp_ct6")

        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue().strip(), "0")

    def test_cmd_seed_tcp_conntrack_reports_map_open_failure(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr), \
             mock.patch.object(helpers, "psutil", object()), \
             mock.patch.object(helpers.os.path, "exists", return_value=True), \
             mock.patch.object(helpers, "obj_get", side_effect=OSError(2, "missing")):
            rc = helpers.cmd_seed_tcp_conntrack("/pins/tcp_ct4", "/pins/tcp_ct6")

        self.assertEqual(rc, 1)
        self.assertIn("failed to open map", stderr.getvalue())

    def test_cmd_seed_tcp_conntrack_seeds_all_established_connections(self):
        connections = [
            types.SimpleNamespace(
                family=socket.AF_INET,
                laddr=make_addr("192.0.2.10", 443),
                raddr=make_addr("198.51.100.20", 50000),
            ),
            types.SimpleNamespace(
                family=socket.AF_INET6,
                laddr=make_addr("2001:db8::10", 443),
                raddr=make_addr("2001:db8::20", 50001),
            ),
        ]

        stdout = io.StringIO()
        with redirect_stdout(stdout), \
             mock.patch.object(helpers, "psutil", object()), \
             mock.patch.object(helpers.os.path, "exists", return_value=True), \
             mock.patch.object(helpers, "obj_get", side_effect=[123, 124]), \
             mock.patch.object(helpers, "iter_established_tcp", return_value=connections), \
             mock.patch.object(helpers, "bpf") as bpf_call, \
             mock.patch.object(helpers.os, "close") as close_call, \
             mock.patch.object(helpers.time, "monotonic_ns", return_value=99):
            rc = helpers.cmd_seed_tcp_conntrack("/pins/tcp_ct4", "/pins/tcp_ct6")

        self.assertEqual(rc, 0)
        self.assertEqual(stdout.getvalue().strip(), "2")
        self.assertEqual(bpf_call.call_count, 2)
        close_call.assert_has_calls([mock.call(123), mock.call(124)])

    def test_main_dispatches_seed_subcommand(self):
        with mock.patch.object(sys, "argv", [
            "auto_xdp_bpf_helpers.py",
            "seed-tcp-conntrack",
            "--map-path-v4",
            "/pins/tcp_ct4",
            "--map-path-v6",
            "/pins/tcp_ct6",
        ]), mock.patch.object(helpers, "cmd_seed_tcp_conntrack", return_value=0) as seed_cmd:
            rc = helpers.main()

        self.assertEqual(rc, 0)
        seed_cmd.assert_called_once_with("/pins/tcp_ct4", "/pins/tcp_ct6")

    def test_main_dispatches_pin_maps_subcommand(self):
        with mock.patch.object(sys, "argv", [
            "auto_xdp_bpf_helpers.py",
            "pin-maps",
            "--prog-id",
            "7",
            "--pin-dir",
            "/pins",
        ]), mock.patch.object(helpers, "cmd_pin_maps", return_value=0) as pin_cmd:
            rc = helpers.main()

        self.assertEqual(rc, 0)
        pin_cmd.assert_called_once_with(7, "/pins")


if __name__ == "__main__":
    unittest.main(verbosity=2)
