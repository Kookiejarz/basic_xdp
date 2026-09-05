#pragma once
#include "keys.h"
#include "map_sizes.h"

/* Note: pkt_counters (PERCPU_ARRAY) and pkt_ringbuf (RINGBUF) are declared
 * in common.h alongside the count() and emit_drop() helpers that use them.
 * All other SEC(".maps") map definitions are below. */

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

// Zone-only exposure for ports that must not be globally public. A hit here
// authorizes the port on the ingress interface; the global whitelist remains
// the fast path for public grants.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct zone_port_key);
    __type(value, __u32);
} tcp_zone_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct zone_port_key);
    __type(value, __u32);
} udp_zone_whitelist SEC(".maps");

// Shared SCTP whitelist map for the optional stateless slot handler.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} sctp_whitelist SEC(".maps");

// Global ICMP token-bucket state (single entry, protected by spin lock)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_token_bucket);
} icmp_tb SEC(".maps");

// Global UDP rate limiter: single shared entry, spinlock-protected.
// All CPUs write to this after flushing their per-CPU local accumulator.
// Must be BPF_MAP_TYPE_ARRAY (not PERCPU) so the spinlock is truly shared.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct udp_global_state);
} udp_global_rl SEC(".maps");

// Per-CPU local byte accumulator for the two-level UDP global rate limiter.
// Each CPU accumulates here without locking; flushes to udp_global_rl in batches.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct udp_percpu_local);
} udp_percpu_acc SEC(".maps");

// Per-port TCP policy config, populated at runtime by xdp_port_sync.
// Key: dest port (host byte order). Value: stateless SYN protection controls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct tcp_port_policy_cfg);
} tcp_port_policies SEC(".maps");

/* Per-port rate-limit isolation: outer array indexed directly by dport.
 * Each occupied slot holds a per-port LRU created by userspace (hash-type
 * inner maps may differ in max_entries since kernel 5.10 — no flag needed;
 * BPF_F_INNER_MAP is ARRAY-only and htab creation rejects it with EINVAL).
 * NULL slot = no rate limit configured for that port. */
#define RATE_MAP_DEFAULT_ENTRIES_V4 16384
#define RATE_MAP_DEFAULT_ENTRIES_V6 4096

/* Inner defs use __uint(key_size/value_size), not __type(): the inner map is a
 * type-only template (never instantiated as a map), so clang's BTF pruning
 * emits only a FWD for structs referenced solely through its pointer fields
 * and libbpf then fails at object open with "can't determine value size". */
#define DEFINE_RATE_OUTER_V4(name)                                  \
    struct {                                                        \
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);                   \
        __uint(max_entries, 65536);                                 \
        __type(key, __u32);                                         \
        __array(values, struct {                                    \
            __uint(type, BPF_MAP_TYPE_LRU_HASH);                    \
            __uint(max_entries, RATE_MAP_DEFAULT_ENTRIES_V4);       \
            __uint(key_size, sizeof(struct syn_rate_key_v4));       \
            __uint(value_size, sizeof(struct syn_rate_val));        \
        });                                                         \
    } name SEC(".maps")

#define DEFINE_RATE_OUTER_V6(name)                                  \
    struct {                                                        \
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);                   \
        __uint(max_entries, 65536);                                 \
        __type(key, __u32);                                         \
        __array(values, struct {                                    \
            __uint(type, BPF_MAP_TYPE_LRU_HASH);                    \
            __uint(max_entries, RATE_MAP_DEFAULT_ENTRIES_V6);       \
            __uint(key_size, sizeof(struct syn_rate_key_v6));       \
            __uint(value_size, sizeof(struct syn_rate_val));        \
        });                                                         \
    } name SEC(".maps")

/* Per-source SYN rate state, one inner LRU per rate-limited port. */
DEFINE_RATE_OUTER_V4(syn4);
DEFINE_RATE_OUTER_V6(syn6);

// Per-port UDP policy config, populated at runtime by xdp_port_sync.
// Key: dest port (host byte order). Value: packet-rate and aggregate-byte-rate controls.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct udp_port_policy_cfg);
} udp_port_policies SEC(".maps");

/* Per-source UDP rate state, one inner LRU per rate-limited port. */
DEFINE_RATE_OUTER_V4(udprt4);
DEFINE_RATE_OUTER_V6(udprt6);

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct prefix_rate_key_v4);
    __type(value, struct prefix_rate_val);
} synag4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct prefix_rate_key_v6);
    __type(value, struct prefix_rate_val);
} synag6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct prefix_rate_key_v4);
    __type(value, struct prefix_rate_val);
} udpag4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct prefix_rate_key_v6);
    __type(value, struct prefix_rate_val);
} udpag6 SEC(".maps");

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

// Allowed outer IPv4 source addresses for 6in4 tunnels (RFC 4213, proto 41).
// Key: outer source IPv4 in network byte order. Value: 1 = allow.
// XDP passes proto-41 packets only from IPs present here; all others are
// dropped at line rate before the kernel spends CPU on SIT decapsulation.
// Populated at runtime from config.toml [tunnel].sit4_endpoints.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __be32);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} sit4_endpoints SEC(".maps");

// 256-entry prog_array: index = final IP protocol number (post ext-hdr traversal).
// Userspace loads handler .o files and updates this map to enable per-protocol
// inspection without modifying the main program.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} proto_handlers SEC(".maps");

// Per-port TCP/UDP handler prog arrays (key = dest port, host byte order).
// Userspace loads a handler .o and updates the fd at the port's index to enable
// per-service deep inspection without modifying or reloading the main program.
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} tcp_port_handlers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} udp_port_handlers SEC(".maps");

// Handler-blocked source IPs: src → blocked_until_ns (ktime).
// Port handlers write here on DROP verdict; the main program checks this after
// whitelist confirms the port is open, before dispatching to the handler again.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct syn_rate_key_v4);
    __type(value, __u64);  // blocked_until_ns
} hblk4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct syn_rate_key_v6);
    __type(value, __u64);  // blocked_until_ns
} hblk6 SEC(".maps");

// Handler-validated UDP sessions: 5-tuple → validated_until_ns.
// UDP port handlers write here on PASS to create a fast path for subsequent
// packets from the same 5-tuple, bypassing the handler until TTL expires.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct udp_validation_key_v4);
    __type(value, __u64);  // validated_until_ns
} udp_hv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct udp_validation_key_v6);
    __type(value, __u64);  // validated_until_ns
} udp_hv6 SEC(".maps");

// AbuseIPDB threat-intel blocklist (IPv4 only — upstream does not publish
// IPv6 lists). Populated by Python syncer from borestad/blocklist-abuseipdb.
// max_entries is a ceiling, not a preallocation: BPF_F_NO_PREALLOC means
// memory only grows with actual inserts. Sized with headroom to fit
// s100-90d (~267k entries) without truncation.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 262144);
    __type(key, struct trusted_v4_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} abuseipdb_v4 SEC(".maps");
