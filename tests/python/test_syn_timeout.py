"""Tests for half-open (SYN-only) conntrack TTL reduction."""
import ctypes
import struct
import time
import unittest
from unittest import mock

_CT_SYN_PENDING = 1 << 63


def _make_fake_map(entries: dict[bytes, int], key_len: int = 12):
    """Return a minimal BpfConntrackMap-compatible object for gc_expired testing.

    entries: {key_bytes: raw_u64_stored_value}
    """
    from auto_xdp.bpf import maps as bpf_maps

    instance = mock.MagicMock(spec=bpf_maps.BpfConntrackMap)
    instance._key_len = key_len
    instance._key = ctypes.create_string_buffer(key_len)
    instance._val = ctypes.create_string_buffer(8)
    instance._lookup_attr = ctypes.create_string_buffer(128)
    instance._cache = set()
    instance.deleted_keys = []

    entry_list = list(entries.items())

    def fake_iter():
        for k, _ in entry_list:
            yield k

    instance._iter_raw_keys.side_effect = fake_iter

    def fake_delete(k):
        instance.deleted_keys.append(k)
        return True

    instance.delete.side_effect = fake_delete

    def fake_bpf(cmd, attr):
        key_bytes = bytes(instance._key.raw[:key_len])
        val = entries.get(key_bytes)
        if val is None:
            import errno
            raise OSError(errno.ENOENT, "not found")
        struct.pack_into("=Q", instance._val, 0, val)

    return instance, fake_bpf


class SynTimeoutConfigTests(unittest.TestCase):
    def setUp(self):
        import auto_xdp.config as cfg
        cfg.apply_toml_config({})  # reset to defaults before each test

    def test_config_has_syn_timeout_default(self):
        import auto_xdp.config as cfg
        self.assertEqual(cfg.XDP_SYN_TIMEOUT_SECONDS, 30.0)

    def test_apply_toml_sets_syn_timeout(self):
        import auto_xdp.config as cfg
        cfg.apply_toml_config({
            "xdp": {"runtime": {"syn_timeout_seconds": 5.0}},
        })
        self.assertEqual(cfg.XDP_SYN_TIMEOUT_SECONDS, 5.0)

    def test_apply_toml_keeps_default_when_absent(self):
        import auto_xdp.config as cfg
        cfg.apply_toml_config({})
        self.assertEqual(cfg.XDP_SYN_TIMEOUT_SECONDS, 30.0)

    def test_apply_toml_rejects_negative_syn_timeout(self):
        import auto_xdp.config as cfg
        cfg.apply_toml_config({
            "xdp": {"runtime": {"syn_timeout_seconds": -1.0}},
        })
        self.assertEqual(cfg.XDP_SYN_TIMEOUT_SECONDS, 30.0)


class SynTimeoutPolicyTests(unittest.TestCase):
    def test_xdp_runtime_config_has_syn_timeout_as_8th_element(self):
        import auto_xdp.config as cfg
        import auto_xdp.policy as policy
        cfg.apply_toml_config({})
        result = policy._xdp_runtime_config()
        self.assertEqual(len(result), 8)
        expected_syn_ns = int(cfg.XDP_SYN_TIMEOUT_SECONDS * 1_000_000_000)
        self.assertEqual(result[7], expected_syn_ns)

    def test_desired_state_runtime_config_default_has_8_elements(self):
        from auto_xdp.state import DesiredState
        state = DesiredState()
        self.assertEqual(len(state.xdp_runtime_config), 8)
        self.assertEqual(state.xdp_runtime_config[7], 30_000_000_000)


class GcExpiredSynFlagTests(unittest.TestCase):
    """gc_expired must handle CT_SYN_PENDING flag in stored ktime values."""

    def test_established_entry_expired_gets_deleted(self):
        """Normal established entry (no flag) older than tcp_timeout is deleted."""
        from auto_xdp.bpf import maps as bpf_maps

        now_ns = time.monotonic_ns()
        old_ts = now_ns - 400_000_000_000  # 400s old, > 300s tcp_timeout
        key = b"\x00" * 12
        instance, fake_bpf = _make_fake_map({key: old_ts})

        with mock.patch.object(bpf_maps, "bpf", side_effect=fake_bpf):
            result = bpf_maps.BpfConntrackMap.gc_expired(instance, 300_000_000_000)

        self.assertEqual(result, 1)

    def test_half_open_entry_expired_by_syn_timeout_gets_deleted(self):
        """Entry with SYN_PENDING flag, age > syn_timeout_ns, must be deleted."""
        from auto_xdp.bpf import maps as bpf_maps

        now_ns = time.monotonic_ns()
        old_ts = now_ns - 15_000_000_000   # 15s old
        stored_val = old_ts | _CT_SYN_PENDING
        key = b"\x01" * 12
        instance, fake_bpf = _make_fake_map({key: stored_val})

        with mock.patch.object(bpf_maps, "bpf", side_effect=fake_bpf):
            result = bpf_maps.BpfConntrackMap.gc_expired(
                instance, 300_000_000_000, syn_timeout_ns=10_000_000_000
            )

        self.assertEqual(result, 1, "15s-old half-open entry must be GC'd (syn_timeout=10s)")

    def test_half_open_entry_not_yet_expired_is_kept(self):
        """Entry with SYN_PENDING flag, age < syn_timeout_ns, must NOT be deleted."""
        from auto_xdp.bpf import maps as bpf_maps

        now_ns = time.monotonic_ns()
        recent_ts = now_ns - 3_000_000_000  # 3s old
        stored_val = recent_ts | _CT_SYN_PENDING
        key = b"\x02" * 12
        instance, fake_bpf = _make_fake_map({key: stored_val})

        with mock.patch.object(bpf_maps, "bpf", side_effect=fake_bpf):
            result = bpf_maps.BpfConntrackMap.gc_expired(
                instance, 300_000_000_000, syn_timeout_ns=10_000_000_000
            )

        self.assertEqual(result, 0, "3s-old half-open entry must not be GC'd (syn_timeout=10s)")

    def test_half_open_without_syn_timeout_arg_uses_tcp_timeout(self):
        """Without syn_timeout_ns, flag is masked and tcp_timeout governs."""
        from auto_xdp.bpf import maps as bpf_maps

        now_ns = time.monotonic_ns()
        # 15s old half-open: should NOT be deleted against 300s tcp_timeout
        recent_ts = now_ns - 15_000_000_000
        stored_val = recent_ts | _CT_SYN_PENDING
        key = b"\x03" * 12
        instance, fake_bpf = _make_fake_map({key: stored_val})

        with mock.patch.object(bpf_maps, "bpf", side_effect=fake_bpf):
            result = bpf_maps.BpfConntrackMap.gc_expired(instance, 300_000_000_000)

        self.assertEqual(result, 0, "15s half-open must not be deleted by 300s tcp_timeout alone")


class BpfRuntimeConfigMapStructTests(unittest.TestCase):
    def test_struct_fmt_has_8_fields(self):
        from auto_xdp.bpf.maps import BpfRuntimeConfigMap
        count = struct.calcsize(BpfRuntimeConfigMap._STRUCT_FMT) // 8
        self.assertEqual(count, 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
