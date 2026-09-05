# Auto XDP: workload-aware exposure

Auto XDP has two decisions in separate layers:

```text
operator intent + live endpoint + workload attribution + ingress zone
                              -> effective exposure
```

`LISTEN != AUTHORIZATION`. The control plane discovers runtime endpoints and
compiles only approved endpoints into the existing XDP or nftables backend.
The dataplane never needs to understand PIDs, systemd, containers, or policy
files.

## Runtime objects

`RuntimeEndpoint` records protocol, bind address, port, bind scope, ingress
zone, subject, attribution state, and evidence source. Bind scope is descriptive:
`0.0.0.0:5432` is a wildcard bind, not a public-access grant.

Attribution is evidence, not authentication:

| State | Evidence | Exposure behavior |
|---|---|---|
| `exact` | systemd cgroup or socket activation target | may match a grant |
| `delegated` | explicit process-name mapping | may match a grant |
| `shared` | more than one owner on a port | only compatible grants may match |
| `ambiguous` / `unknown` | no safe owner | deny; never widen exposure |

The Linux observer uses SOCK_DIAG, `/proc`, systemd socket listings, and
systemd cgroup paths. Docker/Podman attribution is not silently inferred; it is
a follow-up feature with its own runtime evidence.

## Policy

Policy is TOML because it is the project's existing configuration format:

```toml
[policy]
mode = "enforce" # observe | audit | enforce

[zones.public]
interfaces = []

[zones.trusted]
interfaces = ["tailscale0", "wg0"]

[unknown_subjects]
public = "deny"
trusted = "deny"

[subjects.website.resolve]
systemd_unit = "nginx.service"

[subjects.website.exposure.public.tcp]
ports = [80, 443]

[subjects.website.protection]
profile = "web"
```

The resolver evaluates, in order:

1. a live endpoint exists;
2. its ownership matches a configured subject;
3. the subject has a grant for its zone, protocol, and port;
4. the optional protection profile is attached to that already-authorized port.

No listener, service-name catalog, trusted source, or protection profile can
create an exposure grant. Public grants use the global port maps; non-public
grants use interface-index/port maps (or equivalent nftables interface rules).
When several owners share one port, incompatible protection profiles close the
port because the runtime inventory cannot prove one compatible policy.

`observe` prints endpoint evidence and makes no backend changes. `audit` also
compares the runtime inventory with grants and makes no backend changes.
`enforce` reconciles the approved live set. Every decision can be printed with
`xdp_port_sync.py --mode audit --explain`; reconcile latency is logged in
milliseconds.

## Control and data planes

```text
systemd / sockets / containers
              |
              v
       Runtime endpoint observer
              |
              v
       Workload attribution
              |
              +--> Exposure grants
              +--> Protection profiles
              |
              v
       Policy reconciler + explanation
              |
              v
       XDP maps or atomic nftables ruleset
              |
              v
       XDP ingress -> Linux network stack
```

XDP consumes ingress-interface/protocol/port policy, source ACLs, rate limits,
and handler state. The resolver carries the profile name for decisions and
explanations; profile-specific behavior is still deferred, so V1 applies the
existing generic protection maps to every authorized endpoint. Exposure
authorization, asymmetric ingress-only reconciliation, and stateless
protection do not require symmetric routing or project-owned connection
tracking.

If a future stateful feature needs kernel conntrack, it must capability-detect
the kernel facility and retain a restricted stateless fallback. Auto XDP does
not implement IP fragment reassembly.

## Safety rules

- Malformed TCP/UDP packets, truncated Ethernet/VLAN/IP headers, and IP
  fragments that cannot be classified safely are dropped before policy lookup.
- Unsupported protected protocol cases are dropped or explicitly delegated to
  a backend that can classify them.
- A missing or failed discovery snapshot does not replace the last known-good
  backend state with an empty policy.
- New protection state is prepared before a newly authorized port is exposed;
  closing a port happens before its supporting state is removed.
- Relay, TUI, and packet telemetry are observability only and cannot widen or
  disable enforcement.

## Current implementation map

| Concern | Implementation |
|---|---|
| endpoint model | `auto_xdp/state.py` |
| socket and cgroup observation | `auto_xdp/discovery.py` |
| TOML policy validation | `auto_xdp/config.py` |
| grant compilation and explanations | `auto_xdp/policy.py` |
| observe/audit/enforce and latency | `auto_xdp/syncer.py`, `auto_xdp/cli.py` |
| fast ingress enforcement | `bpf/xdp_firewall.c`, `bpf/include/`, and zone-port maps |
| backend application | `auto_xdp/backends/xdp.py`, `nftables.py` |

## V1 boundary

Implemented here: TCP/UDP/SCTP endpoint inventory, normal systemd and socket
activation attribution, separate bind scope and ingress zone, explicit grants,
explainable decisions, effective-port reconciliation, stale exposure removal,
latency measurement, and fail-closed structural parsing.

Implemented after the V1 baseline: Docker/Podman published-port attribution,
including NAT-only publications, and the approval workflow.

Deferred until separately evidenced: a service-specific profile implementation,
optional kernel conntrack lookup, destination-address/CIDR zone keys, strict
per-packet workload authentication, full L7 inspection, custom BPF conntrack,
and upstream volumetric mitigation.
