#pragma once
#include "keys.h"

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct ct_key);
    __type(value, __u64); // ktime_ns at insert for future timeout handling
} tcp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct trusted_v4_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} trusted_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct trusted_v6_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} trusted_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct ct_key);
    __type(value, __u64); // ktime_ns of the most recent outbound UDP packet
} udp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // port number (host byte order) as array index
    __type(value, __u32); // 1 = allow
} tcp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // port number (host byte order) as array index
    __type(value, __u32); // 1 = allow
} udp_whitelist SEC(".maps");

// Shared SCTP whitelist / conntrack maps.
// The main program pins them so the optional slot handler and tc egress tracker
// can reuse the same fds instead of creating private copies.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} sctp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ct_key);
    __type(value, __u64);
} sctp_conntrack SEC(".maps");

// Global ICMP token-bucket state (single entry, protected by spin lock)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_token_bucket);
} icmp_tb SEC(".maps");

// Global UDP two-bucket sliding-window rate limiter state.
// byte_rate_max is runtime-configurable via bpftool; set to 0 to disable.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct udp_global_tb);
} udp_global_rl SEC(".maps");

// Bogon filter toggle: 0 = disabled, non-zero = enabled (default on).
// Written at runtime by xdp_port_sync from config.toml [firewall].bogon_filter.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} bogon_cfg SEC(".maps");

// Per-port SYN rate limit config, populated at runtime by xdp_port_sync.
// Key: dest port (host byte order). Value: rate_max SYNs/window (0 = disabled).
// Ports absent from this map are NOT rate-limited (e.g. HTTP/HTTPS).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct syn_rate_port_cfg);
} syn_rate_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536); // tracks up to 64K concurrent source IPs
    __type(key, struct syn_rate_key);
    __type(value, struct syn_rate_val);
} syn_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct syn_rate_port_cfg);
} udp_rate_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct syn_rate_port_cfg);
} syn_agg_rate_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct syn_rate_port_cfg);
} tcp_conn_limit_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct syn_rate_port_cfg);
} udp_agg_rate_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct syn_rate_key);
    __type(value, struct syn_rate_val);
} udp_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct prefix_rate_key);
    __type(value, struct prefix_rate_val);
} syn_agg_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct prefix_rate_key);
    __type(value, struct prefix_rate_val);
} udp_agg_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct tcp_src_conn_key);
    __type(value, struct tcp_src_conn_val);
} tcp_src_conn_map SEC(".maps");

// Per-CIDR port ACL: source CIDR → list of allowed destination ports.
// ACL entries bypass rate limiting and take priority over the port whitelist.
// TCP and UDP are configured independently via separate maps.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct trusted_v4_key);
    __type(value, struct acl_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} tcp_acl_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct trusted_v6_key);
    __type(value, struct acl_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} tcp_acl_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct trusted_v4_key);
    __type(value, struct acl_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} udp_acl_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1024);
    __type(key, struct trusted_v6_key);
    __type(value, struct acl_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} udp_acl_v6 SEC(".maps");

// 256-entry prog_array: index = final IP protocol number (post ext-hdr traversal).
// Userspace loads handler .o files and updates this map to enable per-protocol
// inspection without modifying the main program.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} proto_handlers SEC(".maps");

// Default action when bpf_tail_call() returns (no handler in slot).
// 0 = XDP_PASS (default, backward-compatible), 1 = XDP_DROP (strict mode).
// Configurable at runtime via bpftool or axdp; mirrors config.toml [slots].default_action.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} slot_def_action SEC(".maps");
