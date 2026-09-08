#pragma once
#include "common.h"

struct udp_validation_key_v4 {
    __be16 sport;
    __be16 dport;
    __be32 saddr;
    __be32 daddr;
};

struct udp_validation_key_v6 {
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
};

struct trusted_v4_key {
    __u32 prefixlen;
    __be32 addr;
};

struct trusted_v6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct zone_port_key {
    __u32 ifindex;
    __u32 port;
};

/*
 * TCP admission result.  A non-zero allow with profile_id == 0 selects the
 * legacy generic/per-port path.  A non-zero profile_id makes successful
 * profile execution a prerequisite for exposure.
 *
 * Keep this layout in sync with userspace's "=IIQQ" packing.
 */
struct tcp_endpoint_policy {
    __u32 allow;
    __u32 profile_id;
    __u64 policy_generation;
    __u64 profile_generation;
};

// Global ICMP token-bucket state (single entry, protected by spin lock)
struct icmp_token_bucket {
    struct bpf_spin_lock lock;
    __u32 _pad;           // explicit: aligns tokens to offset 8
    __u64 tokens;
    __u64 last_refill_ns; // ktime_ns of last refill; 0 = uninitialized
};

// Global UDP sliding-window rate limiter: shared state, spinlock-protected.
// byte_rate_max is runtime-configurable via bpftool; set to 0 to disable.
// Spinlock must be the first field so the BPF verifier can locate it without BTF.
struct udp_global_state {
    struct bpf_spin_lock lock;  // offset 0
    __u32 byte_rate_max;        // offset 4 — max bytes/s; 0 = disabled
    __u64 window_start_ns;      // offset 8  — ktime_ns of current bucket; 0 = uninit
    __u64 prev_bytes;           // offset 16 — byte count in previous 1-s bucket
    __u64 curr_bytes;           // offset 24 — byte count in current 1-s bucket
    __u64 blocked_until_ns;     // offset 32 — ktime_ns until which all traffic is blocked; 0 = not blocked
};

// Per-CPU local byte accumulator for the two-level UDP global rate limiter.
// Each CPU accumulates bytes here without any locking and flushes to the shared
// udp_global_state only when the batch threshold is reached.
struct udp_percpu_local {
    __u64 local_bytes;
    __u64 blocked_until_ns;     // per-CPU copy of the block verdict for the fast-drop path
};

struct tcp_port_policy_cfg {
    __u32 syn_rate_max;             /* view idx 0 */
    __u32 syn_agg_rate_max;         /* view idx 1 */
    __u32 _reserved2;               /* view idx 2 — retained for ABI stability */
    __u32 source_prefix_v4;         /* view idx 3 */
    __u32 source_prefix_v6;         /* view idx 4 */
    __u32 _reserved5;               /* view idx 5 — retained for ABI stability */
    __u32 _reserved6;               /* view idx 6 — retained for ABI stability */
    __u32 _pad;                     /* view idx 7 */
};

struct udp_port_policy_cfg {
    __u32 rate_max;
    __u32 agg_rate_max;
    __u32 source_prefix_v4;
    __u32 source_prefix_v6;
    __u32 _pad0;
    __u32 _pad1;
};

struct syn_rate_val {
    __u64 state; /* upper 32 bits: window tick; lower 32 bits: count */
};

struct prefix_rate_key_v4 {
    __be32 addr;
    __u32 dest_port;
};

struct prefix_rate_key_v6 {
    __u32 addr[4];
    __u32 dest_port;
};

struct prefix_rate_val {
    __u64 state;
};

// Per-CIDR port ACL: source CIDR → list of allowed destination ports.
// ACL entries bypass rate limiting and take priority over the port whitelist.
// TCP and UDP are configured independently via separate maps.
#define ACL_MAX_PORTS 64

struct acl_val {
    __u32 count;
    __u16 ports[ACL_MAX_PORTS];
};

static __always_inline void fill_udp_validation_key_v4(struct udp_validation_key_v4 *out, const struct flow_key *key)
{
    out->sport = key->sport;
    out->dport = key->dport;
    out->saddr = (__be32)key->saddr[0];
    out->daddr = (__be32)key->daddr[0];
}

static __always_inline void fill_udp_validation_key_v6(struct udp_validation_key_v6 *out, const struct flow_key *key)
{
    out->sport = key->sport;
    out->dport = key->dport;
    __builtin_memcpy(out->saddr, key->saddr, sizeof(out->saddr));
    __builtin_memcpy(out->daddr, key->daddr, sizeof(out->daddr));
}
