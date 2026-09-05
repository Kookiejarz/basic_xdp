# Roadmap / TODO

This is a working list, not a release commitment. Prefer small, measurable
changes that reuse the existing CLI, relay, and BPF maps.

## P0 — Control plane and queries

- [ ] Add stable `--json` output to existing read commands (`backend`, `ports`,
      `conntrack`, `stats`, `config show`) before introducing another API.
- [ ] Add `axdp inspect` for an IP, port, or flow. Show the effective policy,
      matching trust/ACL/blocklist entries, conntrack state, rate limits,
      counters, and the reason a packet would be allowed or dropped.
- [ ] Add one health view covering backend probes, loaded program/map ABI,
      last successful reconciliation, relay status, and threat-intel freshness.
- [ ] Make policy changes previewable (`--dry-run`) and report the exact desired
      versus applied delta through the same reconciliation path used in production.
- [ ] Keep a bounded local event history for time-range queries. Start with the
      Python standard library (`sqlite3`) and configurable retention.
- [ ] Add a versioned local Unix-socket control API only when CLI JSON is not
      sufficient for an actual external consumer.

## P1 — SYN-flood hardening

- [ ] Benchmark the current per-source/per-prefix SYN limits plus Linux
      `tcp_syncookies` against an XDP SYN-proxy/cookie design. Record CPU cost,
      handshake success, false drops, and state-map pressure.
- [ ] If the benchmark justifies it, add an opt-in, per-port XDP SYN-cookie mode
      for IPv4 and IPv6 with secret rotation, ACK validation, TCP-option handling,
      telemetry, and a safe fallback to the kernel TCP stack.
- [ ] Test retransmits, asymmetric paths, NAT, ECN, MSS/window scaling,
      timestamps, IPv6 extension headers, malformed ACKs, and secret rotation.

## P1 — Explainable risk assessment

- [ ] Define a normalized signal schema from existing telemetry: source IP/CIDR,
      destination port, verdict/reason, packet and byte rates, SYN/ACK ratio,
      distinct ports, recurrence, conntrack outcome, and threat-intel source age.
- [ ] Replace the current binary blocklist-only view with a decaying 0–100 risk
      score whose contributing signals can be shown by `axdp inspect`.
- [ ] Run scoring in observe-only mode first; risk must not automatically block
      traffic until false-positive limits are measured on replayed traffic.
- [ ] Expose score, confidence, evidence, first/last seen, and expiry through the
      CLI JSON contract and TUI.
- [ ] Add bounded cardinality and retention so spoofed source addresses cannot
      exhaust userspace storage or BPF maps.

## P2 — Risk prediction and response

- [ ] Build short rolling aggregates and an EWMA baseline for each host/service;
      alert on rate, distribution, and scan-pattern changes before adding ML.
- [ ] Backtest predictions against captured/replayed incidents and publish
      precision, recall, lead time, and false positives by service type.
- [ ] Recommend a mitigation with an explanation and simulated policy delta.
      Keep application opt-in and time-bounded, with hysteresis and rollback.
- [ ] Consider a trained model only after enough labeled incidents exist and the
      baseline demonstrably misses useful attacks. Version models and features,
      detect drift, and keep the deterministic score as fallback.

## Later / conditional

- [ ] Prometheus/OpenTelemetry export, once the JSON/query contract is stable.
- [ ] Signed policy bundles and multi-host coordination, when a real multi-host
      deployment requires them.
- [ ] Pluggable threat-intelligence feeds with provenance, freshness, and
      conflict handling; never let a failed refresh erase the last good state.

