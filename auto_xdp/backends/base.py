"""Abstract backend interface."""
from __future__ import annotations


class PortBackend:
    name = "backend"

    def sync_ports(
        self,
        tcp_target: set[int],
        udp_target: set[int],
        sctp_target: set[int],
        trusted_target: set[str],
        conntrack_target: set[bytes],
        dry_run: bool,
        cached_conns=None,
    ) -> None:
        raise NotImplementedError

    def close(self) -> None:
        return None
