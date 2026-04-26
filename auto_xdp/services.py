"""Local service-name resolution without NSS lookups."""
from __future__ import annotations

import logging
from functools import lru_cache

log = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _service_map() -> dict[tuple[str, int], str]:
    services: dict[tuple[str, int], str] = {}
    try:
        with open("/etc/services", "r", encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                fields = line.split()
                if len(fields) < 2 or "/" not in fields[1]:
                    continue
                name = fields[0]
                port_str, proto = fields[1].split("/", 1)
                if proto not in {"tcp", "udp"}:
                    continue
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                services.setdefault((proto, port), name)
    except OSError as exc:
        log.debug("Could not read /etc/services: %s", exc)
    return services


def service_name(port: int, proto: str) -> str:
    """Resolve a TCP/UDP service name from /etc/services, or return an empty string."""
    return _service_map().get((proto, port), "")
