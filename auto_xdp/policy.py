"""Rate-limit policy resolution helpers for port sync and firewall rules."""

from auto_xdp import config as cfg
from auto_xdp.services import service_name
from auto_xdp.state import DesiredState, ExposureDecision, ObservedState, RuntimeEndpoint

_NS_PER_SECOND = 1_000_000_000


def _seconds_to_ns(value: float) -> int:
    return int(value * _NS_PER_SECOND)


def _xdp_runtime_config() -> tuple[int, int, int, int, int, int, int, int]:
    icmp_ns_per_token = 0
    if cfg.XDP_ICMP_RATE_PPS > 0:
        icmp_ns_per_token = max(1, int(_NS_PER_SECOND / cfg.XDP_ICMP_RATE_PPS))
    return (
        0,
        0,
        0,
        cfg.XDP_ICMP_BURST_PACKETS,
        icmp_ns_per_token,
        _seconds_to_ns(cfg.XDP_UDP_GLOBAL_WINDOW_SECONDS),
        _seconds_to_ns(cfg.XDP_RATE_WINDOW_SECONDS),
        0,
    )


def _explicit_lookup(
    port: int,
    proc: str,
    proc_limits: dict[str, int],
    service_limits: dict[str, int],
) -> int | None:
    """Return explicit operator value for the port, or None if no entry matches.

    Critically distinguishes "explicit 0 (pin off)" from "missing entry"
    (which lets callers apply default-tier values).
    """
    if proc and proc in proc_limits:
        return proc_limits[proc]
    svc = service_name(port, "tcp")
    if svc and svc in service_limits:
        return service_limits[svc]
    return None


def _is_sensitive(port: int, proc: str) -> bool:
    """A port is sensitive iff the owning proc/service has rate <= threshold.

    Rate 0 (pin off) is exempt, not sensitive — it does not promote
    the port to the strict tier.
    """
    threshold = cfg.XDP_SENSITIVE_PORT_THRESHOLD
    if proc:
        rate = cfg._SYN_RATE_BY_PROC.get(proc)
        if rate is not None and 0 < rate <= threshold:
            return True
    svc = service_name(port, "tcp")
    if svc:
        rate = cfg._SYN_RATE_BY_SERVICE.get(svc)
        if rate is not None and 0 < rate <= threshold:
            return True
    return False


def _resolve_service_limit(
    port: int,
    proto: str,
    proc: str,
    proc_limits: dict[str, int],
    service_limits: dict[str, int],
) -> int:
    if proc:
        limit = proc_limits.get(proc)
        if limit is not None:
            return limit
    svc = service_name(port, proto)
    if not svc:
        return 0
    return service_limits.get(svc, 0)


def _port_rate_limit(port: int, proc: str = "") -> int:
    # Proc-table is authoritative explicit override (inc. explicit 0 = pin off).
    if proc and proc in cfg._SYN_RATE_BY_PROC:
        return cfg._SYN_RATE_BY_PROC[proc]
    # Service-table entry ≤ threshold acts as a sensitivity marker; the resolver
    # applies the strict default rather than the raw service value.
    if _is_sensitive(port, proc):
        return cfg.XDP_DEFAULT_TCP_SYN_RATE_STRICT
    # Explicit service-table value above the sensitive threshold.
    explicit = _explicit_lookup(
        port, proc, cfg._SYN_RATE_BY_PROC, cfg._SYN_RATE_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    return cfg.XDP_DEFAULT_TCP_SYN_RATE


def _syn_aggregate_rate_limit(port: int, proc: str = "") -> int:
    explicit = _explicit_lookup(
        port, proc, cfg._SYN_AGG_RATE_BY_PROC, cfg._SYN_AGG_RATE_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    if _is_sensitive(port, proc):
        return cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE_STRICT
    return cfg.XDP_DEFAULT_TCP_SYN_AGG_RATE


def rate_map_entries_v6(v4_entries: int) -> int:
    """Derive the v6 inner-map capacity from the v4 one.

    Ports carrying the global v4 default use the operator's global v6
    value; per-port overrides derive as v4/4 with a floor of 64."""
    if v4_entries == cfg.RATE_MAP_ENTRIES_V4:
        return cfg.RATE_MAP_ENTRIES_V6
    return max(v4_entries // 4, 64)


def _rate_map_entries(port: int, proc: str = "") -> int:
    """v4 inner rate-map capacity for a rate-limited port."""
    explicit = _explicit_lookup(
        port, proc, cfg._RATE_MAP_ENTRIES_BY_PROC, cfg._RATE_MAP_ENTRIES_BY_SERVICE,
    )
    if explicit is not None:
        return explicit
    return cfg.RATE_MAP_ENTRIES_V4


def _udp_port_rate_limit(port: int, proc: str = "") -> int:
    """Return the UDP rate limit for a port, or 0 to skip rate limiting."""
    return _resolve_service_limit(port, "udp", proc, cfg._UDP_RATE_BY_PROC, cfg._UDP_RATE_BY_SERVICE)


def _udp_aggregate_byte_limit(port: int, proc: str = "") -> int:
    limit = _resolve_service_limit(
        port, "udp", proc, cfg._UDP_AGG_BYTES_BY_PROC, cfg._UDP_AGG_BYTES_BY_SERVICE
    )
    if limit > 0:
        return limit
    base = _udp_port_rate_limit(port, proc)
    return base * 1200 if base > 0 else 0


def _resolve_port_limits(
    ports: set[int],
    process_names: dict[int, str],
    resolver,
) -> dict[int, int]:
    """Return resolver(port, proc) for every port — including 0 (pin off).

    Pre-default-on, this filtered out 0 to keep the desired-state map small.
    Now every auto-discovered port produces an entry so default-tier values
    propagate to the BPF policy map."""
    return {port: resolver(port, process_names.get(port, "")) for port in ports}


def _desired_acl_rules() -> dict[tuple[str, str], frozenset[int]]:
    desired: dict[tuple[str, str], frozenset[int]] = {}
    for rule in cfg.ACL_RULES:
        proto = rule["proto"]
        cidr = rule["cidr"]
        ports = rule["ports"]
        if not ports:
            continue
        desired[(proto, cidr)] = frozenset(ports)
    return desired


def _unit_name(value: object) -> str:
    return str(value).strip().removesuffix(".service")


def _container_label_match(value: object, labels: dict[str, str]) -> bool:
    if isinstance(value, dict):
        return all(labels.get(str(key)) == str(label) for key, label in value.items())
    if isinstance(value, str) and "=" in value:
        key, label = value.split("=", 1)
        return labels.get(key.strip()) == label.strip()
    return False


def _container_resolver_matches(endpoint: RuntimeEndpoint, resolve: dict) -> bool:
    identity_keys = {"container_id", "container_name", "container_label"}
    if not identity_keys.intersection(resolve):
        return False
    if endpoint.attribution_state != "exact" or not endpoint.container_runtime:
        return False
    runtime = str(resolve.get("container_runtime", "")).strip().lower()
    if runtime and runtime != endpoint.container_runtime:
        return False
    container_id = str(resolve.get("container_id", "")).strip().lower()
    if container_id and not endpoint.container_id.startswith(container_id):
        return False
    container_name = str(resolve.get("container_name", "")).strip()
    if container_name and container_name != endpoint.container_name:
        return False
    label = resolve.get("container_label")
    return not label or _container_label_match(label, endpoint.container_labels)


def _subject_for_endpoint(endpoint: RuntimeEndpoint) -> tuple[str, dict] | None:
    """Resolve runtime evidence to an explicitly configured policy subject."""
    if endpoint.attribution_state in {"unknown", "ambiguous"} or not endpoint.subject:
        return None
    for name, spec in cfg.SUBJECTS.items():
        resolve = spec.get("resolve", {}) if isinstance(spec, dict) else {}
        if not isinstance(resolve, dict):
            continue
        if _container_resolver_matches(endpoint, resolve):
            return name, spec
        unit = resolve.get("systemd_unit")
        process = resolve.get("process_name")
        if unit and _unit_name(unit) == _unit_name(endpoint.subject):
            return name, spec
        if process and str(process) == endpoint.subject:
            return name, spec
        if not unit and not process and str(name) == endpoint.subject:
            return name, spec
    return None


def _grant_for(endpoint: RuntimeEndpoint, subject: dict) -> tuple[bool, str, str]:
    exposure = subject.get("exposure", {})
    zone = exposure.get(endpoint.ingress_zone, {}) if isinstance(exposure, dict) else {}
    if not isinstance(zone, dict):
        return False, "no exposure grant for ingress zone", ""
    if bool(zone.get("deny", False)):
        return False, "subject explicitly denies this ingress zone", ""
    protocol = zone.get(endpoint.protocol, {})
    if not isinstance(protocol, dict):
        return False, "no exposure grant for protocol", ""
    ports = protocol.get("ports", [])
    if endpoint.host_port not in {int(port) for port in ports}:
        return False, "port is not listed in the exposure grant", ""
    protection = subject.get("protection", {})
    profile = str(protection.get("profile", "")) if isinstance(protection, dict) else ""
    return True, "matched explicit exposure grant", profile


def resolve_exposure_decisions(observed: ObservedState) -> list[ExposureDecision]:
    """Compile runtime endpoints against explicit workload exposure grants."""
    decisions: list[ExposureDecision] = []
    for endpoint in observed.endpoints:
        resolved = _subject_for_endpoint(endpoint)
        if resolved is None:
            decisions.append(
                ExposureDecision(
                    endpoint, "drop", "unknown or unapproved workload ownership"
                )
            )
            continue
        subject_name, subject = resolved
        allowed, reason, profile = _grant_for(endpoint, subject)
        decisions.append(
            ExposureDecision(
                endpoint,
                "allow" if allowed else "drop",
                reason,
                subject_name,
                profile,
            )
        )

    # A global port map cannot safely express two incompatible owners. Keep
    # the whole port closed when the inventory proves shared/ambiguous ownership.
    grouped: dict[tuple[str, int], list[ExposureDecision]] = {}
    for decision in decisions:
        grouped.setdefault(
            (decision.endpoint.protocol, decision.endpoint.host_port), []
        ).append(decision)
    for group in grouped.values():
        if len(group) < 2:
            continue
        if any(item.endpoint.attribution_state in {"unknown", "ambiguous"} for item in group):
            for item in group:
                item.action = "drop"
                item.reason = "shared port has unknown or ambiguous ownership"
        elif len({(item.subject, item.protection_profile) for item in group}) > 1:
            for item in group:
                item.action = "drop"
                item.reason = "shared port has incompatible subject protection"
    return decisions


def _service_aware_desired_state(observed: ObservedState) -> DesiredState:
    decisions = resolve_exposure_decisions(observed)
    zone_tcp_ports: dict[str, set[int]] = {}
    zone_udp_ports: dict[str, set[int]] = {}
    for item in decisions:
        if item.action != "allow":
            continue
        target = zone_tcp_ports if item.endpoint.protocol == "tcp" else zone_udp_ports
        if item.endpoint.protocol in {"tcp", "udp"}:
            target.setdefault(item.endpoint.ingress_zone, set()).add(item.endpoint.host_port)
    allowed = {
        (item.endpoint.protocol, item.endpoint.host_port)
        for item in decisions
        if item.action == "allow"
    }
    # The current global maps represent public exposure. Private/trusted grants
    # are carried separately and enforced by the zone-aware backend path.
    public_is_global = not cfg.ZONES.get("public", {}).get("interfaces", [])
    public_tcp_ports = {
        item.endpoint.host_port for item in decisions
        if item.action == "allow" and item.endpoint.protocol == "tcp"
        and item.endpoint.ingress_zone == "public" and public_is_global
    }
    public_udp_ports = {
        item.endpoint.host_port for item in decisions
        if item.action == "allow" and item.endpoint.protocol == "udp"
        and item.endpoint.ingress_zone == "public" and public_is_global
    }
    # SCTP remains global-map only until its slot handlers accept an interface
    # key; never widen it when a public zone is interface-scoped.
    sctp_ports = {
        item.endpoint.host_port for item in decisions
        if item.action == "allow" and item.endpoint.protocol == "sctp"
        and item.endpoint.ingress_zone == "public" and public_is_global
    }
    # Resolve protection for every allowed endpoint, while only the public
    # subset enters the global XDP maps. Zone-only ports are admitted by the
    # interface/port maps installed by the zone-aware backend.
    allowed_tcp_ports = {port for proto, port in allowed if proto == "tcp"}
    allowed_udp_ports = {port for proto, port in allowed if proto == "udp"}
    desired = _desired_state_for_ports(
        ObservedState(
            tcp=allowed_tcp_ports,
            udp=allowed_udp_ports,
            sctp=sctp_ports,
            tcp_processes={port: observed.tcp_processes.get(port, "") for port in allowed_tcp_ports},
            udp_processes={port: observed.udp_processes.get(port, "") for port in allowed_udp_ports},
        ),
    )
    desired.tcp_ports = public_tcp_ports
    desired.udp_ports = public_udp_ports
    desired.exposure_decisions = decisions
    desired.zone_tcp_ports = zone_tcp_ports
    desired.zone_udp_ports = zone_udp_ports
    return desired


def _desired_state_for_ports(observed: ObservedState) -> DesiredState:
    tcp_ports = set(observed.tcp)
    udp_ports = set(observed.udp)
    sctp_ports = set(observed.sctp)
    tcp_syn_rate_limits = _resolve_port_limits(
        tcp_ports, observed.tcp_processes, _port_rate_limit
    )
    udp_rate_limits = _resolve_port_limits(
        udp_ports, observed.udp_processes, _udp_port_rate_limit
    )
    tcp_rate_map_entries = {
        port: _rate_map_entries(port, observed.tcp_processes.get(port, ""))
        for port, rate in tcp_syn_rate_limits.items() if rate > 0
    }
    udp_rate_map_entries = {
        port: _rate_map_entries(port, observed.udp_processes.get(port, ""))
        for port, rate in udp_rate_limits.items() if rate > 0
    }

    return DesiredState(
        tcp_ports=tcp_ports,
        udp_ports=udp_ports,
        sctp_ports=sctp_ports,
        trusted_cidrs=set(cfg.TRUSTED_SRC_IPS),
        tcp_syn_rate_limits=tcp_syn_rate_limits,
        tcp_syn_agg_rate_limits=_resolve_port_limits(
            tcp_ports, observed.tcp_processes, _syn_aggregate_rate_limit
        ),
        udp_rate_limits=udp_rate_limits,
        tcp_rate_map_entries=tcp_rate_map_entries,
        udp_rate_map_entries=udp_rate_map_entries,
        udp_agg_rate_limits=_resolve_port_limits(
            udp_ports, observed.udp_processes, _udp_aggregate_byte_limit
        ),
        acl_rules=_desired_acl_rules(),
        bogon_filter_enabled=cfg.BOGON_FILTER_ENABLED,
        drop_events_enabled=cfg.DROP_EVENTS_ENABLED,
        rate_limit_source_prefix_v4=cfg.RATE_LIMIT_SOURCE_PREFIX_V4,
        rate_limit_source_prefix_v6=cfg.RATE_LIMIT_SOURCE_PREFIX_V6,
        udp_global_byte_rate=cfg.XDP_UDP_GLOBAL_BYTE_RATE,
        xdp_runtime_config=_xdp_runtime_config(),
    )


def resolve_desired_state(observed: ObservedState) -> DesiredState:
    return _service_aware_desired_state(observed)
