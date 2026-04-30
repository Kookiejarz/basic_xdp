import subprocess
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock

import auto_xdp.admin.main as admin_main
import auto_xdp.admin_cli as admin_cli


class AdminCliTests(unittest.TestCase):
    def test_config_init_writes_default_template(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"

            rc = admin_cli.main(["--config", str(config_path), "config", "init"])

            self.assertEqual(rc, 0)
            self.assertTrue(config_path.exists())
            text = config_path.read_text()
            self.assertIn("[daemon]", text)
            self.assertIn("[slots]", text)
            self.assertIn('default_action = "drop"', text)

    def test_trust_add_normalizes_cidr(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.toml"
            config_path.write_text("[trusted_ips]\n")

            rc = admin_cli.main(
                [
                    "--config",
                    str(config_path),
                    "trust",
                    "add",
                    "203.0.113.9",
                    "office",
                ]
            )

            self.assertEqual(rc, 0)
            text = config_path.read_text()
            self.assertIn('"203.0.113.9/32" = "office"', text)

    def test_slot_load_builtin_sctp_reuses_shared_maps_and_updates_config(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            bpf_pin_dir = root / "bpf"
            handlers_dir = root / "handlers"
            (bpf_pin_dir / "handlers").mkdir(parents=True)
            handlers_dir.mkdir()

            for path in (
                bpf_pin_dir / "slot_ctx_map",
                bpf_pin_dir / "sctp_whitelist",
                bpf_pin_dir / "sctp_conntrack",
                bpf_pin_dir / "proto_handlers",
            ):
                path.touch()
            (handlers_dir / "sctp_handler.o").touch()

            calls: list[list[str]] = []

            def fake_run(cmd, capture_output=False, text=False):
                calls.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0, "", "")

            with mock.patch("auto_xdp.admin_cli.subprocess.run", side_effect=fake_run):
                rc = admin_cli.main(
                    [
                        "--config",
                        str(config_path),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "--handlers-dir",
                        str(handlers_dir),
                        "slot",
                        "load",
                        "sctp",
                    ]
                )

            self.assertEqual(rc, 0)
            self.assertEqual(len(calls), 2)
            self.assertIn("slot_ctx_map", calls[0])
            self.assertIn("sctp_whitelist", calls[0])
            self.assertIn("sctp_conntrack", calls[0])
            self.assertEqual(calls[1][:5], ["bpftool", "map", "update", "pinned", str(bpf_pin_dir / "proto_handlers")])
            text = config_path.read_text()
            self.assertIn('[slots]', text)
            self.assertIn('enabled = ["sctp"]', text)

    def test_slot_list_excludes_port_handler_candidates(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            bpf_pin_dir = root / "bpf"
            handlers_dir = root / "handlers"
            handlers_dir.mkdir()
            bpf_pin_dir.mkdir()
            (bpf_pin_dir / "proto_handlers").touch()
            (handlers_dir / "minecraft_handler.c").write_text(
                'struct { int x; } tcp_ct4 SEC(".maps");\nSEC("xdp/minecraft") int x(void *ctx) { return 0; }\n'
            )
            (handlers_dir / "minecraft_handler.o").touch()

            stdout = StringIO()
            with mock.patch("sys.stdout", stdout):
                rc = admin_cli.main(
                    [
                        "--config",
                        str(config_path),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "--handlers-dir",
                        str(handlers_dir),
                        "slot",
                        "list",
                    ]
                )

            self.assertEqual(rc, 0)
            output = stdout.getvalue()
            self.assertIn("Available handlers:", output)
            self.assertNotIn("minecraft_handler", output)
            self.assertNotIn("minecraft", output)

    def test_port_handler_list_shows_available_local_handler_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            config_path = root / "config.toml"
            bpf_pin_dir = root / "bpf"
            handlers_dir = root / "handlers"
            handlers_dir.mkdir()
            bpf_pin_dir.mkdir()
            (handlers_dir / "gre_handler.o").touch()
            (handlers_dir / "custom_47_demo.o").touch()
            (handlers_dir / "minecraft_handler.c").write_text(
                'struct { int x; } tcp_ct4 SEC(".maps");\nSEC("xdp/minecraft") int x(void *ctx) { return 0; }\n'
            )
            (handlers_dir / "minecraft_handler.o").touch()

            stdout = StringIO()
            with mock.patch("sys.stdout", stdout):
                rc = admin_cli.main(
                    [
                        "--config",
                        str(config_path),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "--handlers-dir",
                        str(handlers_dir),
                        "port-handler",
                        "list",
                    ]
                )

            self.assertEqual(rc, 0)
            output = stdout.getvalue()
            self.assertIn("Available local port handler files:", output)
            self.assertIn("minecraft_handler", output)
            self.assertIn(str(handlers_dir / "minecraft_handler.o"), output)
            self.assertNotIn("custom_47_demo", output)
            self.assertNotIn(str(handlers_dir / "gre_handler.o"), output)

    def test_admin_main_backend_json_matches_backend_snapshot(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            env_config = root / "auto_xdp.env"
            run_state_dir = root / "run"
            bpf_pin_dir = root / "bpf"
            bin_dir = root / "bin"
            run_state_dir.mkdir()
            bpf_pin_dir.mkdir()
            bin_dir.mkdir()

            env_config.write_text('IFACES="eth9"\nPREFERRED_BACKEND="auto"\n')
            (run_state_dir / "backend").write_text("xdp\n")
            (run_state_dir / "xdp_mode").write_text("native\n")
            for path in (
                bpf_pin_dir / "pkt_counters",
                bpf_pin_dir / "tcp_ct4",
                bpf_pin_dir / "tcp_ct6",
                bpf_pin_dir / "udp_ct4",
                bpf_pin_dir / "udp_ct6",
            ):
                path.touch()

            (bin_dir / "ip").write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' '2: eth9: <BROADCAST> mtu 1500 xdp'\n"
            )
            (bin_dir / "tc").write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"filter\" ]; then\n"
                "  printf '%s\\n' 'filter protocol all pref 49152 bpf chain 0'\n"
                "fi\n"
            )
            (bin_dir / "bpftool").write_text(
                "#!/bin/sh\n"
                "case \"$*\" in\n"
                "  *\"tcp_ct4\"*) printf '%s\\n' '[{\"key\":[1]}]' ;;\n"
                "  *\"tcp_ct6\"*) printf '%s\\n' '[{\"key\":[1]}]' ;;\n"
                "  *\"udp_ct4\"*) printf '%s\\n' '[{\"key\":[1]}]' ;;\n"
                "  *\"udp_ct6\"*) printf '%s\\n' '[]' ;;\n"
                "  *) printf '%s\\n' '[]' ;;\n"
                "esac\n"
            )
            for name in ("ip", "tc", "bpftool"):
                (bin_dir / name).chmod(0o755)

            with mock.patch.dict("os.environ", {"PATH": f"{bin_dir}:{Path('/usr/bin')}:{Path('/bin')}"}, clear=False), \
                 mock.patch("sys.stdout.write") as write_mock:
                rc = admin_main.main(
                    [
                        "--env-config",
                        str(env_config),
                        "--bpf-pin-dir",
                        str(bpf_pin_dir),
                        "--run-state-dir",
                        str(run_state_dir),
                        "backend",
                        "--json",
                    ]
                )

            self.assertEqual(rc, 0)
            output = "".join(call.args[0] for call in write_mock.call_args_list).strip()
            self.assertIn('"backend": "xdp"', output)
            self.assertIn('"interfaces": ["eth9"]', output)
            self.assertIn('"conntrack": {"tcp": 2, "udp": 1}', output)


if __name__ == "__main__":
    unittest.main()
