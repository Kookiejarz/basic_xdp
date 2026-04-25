#pragma once
#include "common.h"

struct ct_key {
    __u8 family;
    __u8 pad[3];
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
} __attribute__((aligned(8)));

struct trusted_v4_key {
    __u32 prefixlen;
    __be32 addr;
};

struct trusted_v6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

// Global ICMP token-bucket state (single entry, protected by spin lock)
struct icmp_token_bucket {
    struct bpf_spin_lock lock;
    __u32 _pad;           // explicit: aligns tokens to offset 8
    __u64 tokens;
    __u64 last_refill_ns; // ktime_ns of last refill; 0 = uninitialized
};

// Global UDP two-bucket sliding-window rate limiter state.
// byte_rate_max is runtime-configurable via bpftool; set to 0 to disable.
struct udp_global_tb {
    struct bpf_spin_lock lock;
    __u32 byte_rate_max;     // max bytes per 1-second window; 0 = disabled
    __u64 window_start_ns;   // ktime_ns of current bucket's start; 0 = uninit
    __u64 prev_bytes;        // byte count in the previous 1-second bucket
    __u64 curr_bytes;        // byte count in the current 1-second bucket
};

// Per-port SYN rate limit config, populated at runtime by xdp_port_sync.
// Key: dest port (host byte order). Value: rate_max SYNs/window (0 = disabled).
// Ports absent from this map are NOT rate-limited (e.g. HTTP/HTTPS).
struct syn_rate_port_cfg {
    __u32 rate_max; // max SYNs per source IP per cfg_syn_window_ns; 0 = skip
    __u32 _pad;
};

// Per-IP SYN rate limiter state
struct syn_rate_key {
    __u8  family;
    __u8  pad[3];
    __u32 addr[4]; // IPv4: addr[0] only; IPv6: all 4 words
    __u32 _pad2;   // explicit: makes aligned(8) trailing pad visible (20→24 bytes)
} __attribute__((aligned(8)));

struct syn_rate_val {
    __u64 window_start_ns;
    __u32 count;
    __u32 _pad;
};

struct prefix_rate_key {
    __u8  family;
    __u8  pad[3];
    __u32 addr[4];   // IPv4: masked /24 in addr[0]; IPv6: masked /64 in addr[0..1]
    __u32 dest_port;
    __u32 _pad2;
} __attribute__((aligned(8)));

struct prefix_rate_val {
    __u64 window_start_ns;
    __u64 units;
};

struct tcp_src_conn_key {
    __u8  family;
    __u8  pad[3];
    __u32 addr[4];
    __u32 dest_port;
    __u32 _pad2;
} __attribute__((aligned(8)));

struct tcp_src_conn_val {
    __u64 last_seen_ns;
    __u32 count;
    __u32 _pad;
};

// Per-CIDR port ACL: source CIDR → list of allowed destination ports.
// ACL entries bypass rate limiting and take priority over the port whitelist.
// TCP and UDP are configured independently via separate maps.
#define ACL_MAX_PORTS 64

struct acl_val {
    __u32 count;
    __u16 ports[ACL_MAX_PORTS];
};
