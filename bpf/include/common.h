#pragma once
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "handlers/xdp_slot_ctx.h"

#ifndef bool
typedef _Bool bool;
#define true  1
#define false 0
#endif

/* struct vlan_hdr is not reliably defined in BPF compilation headers on all
 * distros (<linux/if_vlan.h> may only forward-declare it).  Define it here
 * directly; ETH_P_8021Q / ETH_P_8021AD come from <linux/if_ether.h>. */
struct vlan_hdr {
    __be16  h_vlan_TCI;
    __be16  h_vlan_encapsulated_proto;
};

// These two macros are not exposed under the BPF compilation path of <linux/ip.h>, so define them manually
#ifndef IP_MF
#define IP_MF     0x2000  // More Fragments bit
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF  // Fragment offset mask
#endif

#define IPV6_FRAG_DROP_SENTINEL 0xFF
#define VLAN_MAX_DEPTH 4
#define CT_FAMILY_IPV4 2
#define CT_FAMILY_IPV6 10


// Runtime-configurable constants in .rodata.
// Defaults match the original behaviour.  A libbpf/skeleton loader can
// override these before bpf_object__load(), allowing tuning without
// recompilation.  volatile const prevents LLVM from folding them into
// immediates; always cache into a local variable when used more than once
// in a single function.


// Conntrack timeouts and refresh intervals (nanoseconds)
volatile const __u64 cfg_tcp_timeout_ns    = 300ULL * 1000000000ULL; // 5 min
volatile const __u64 cfg_udp_timeout_ns    = 60ULL  * 1000000000ULL; // 1 min
volatile const __u64 cfg_ct_refresh_ns     = 30ULL  * 1000000000ULL; // 30 s

// ICMP token-bucket rate limiter
volatile const __u64 cfg_icmp_token_max    = 100ULL; // burst capacity (packets)
volatile const __u64 cfg_icmp_ns_per_token = 1000000000ULL / 100ULL; // 10 ms

// Global UDP sliding-window and per-IP SYN/UDP rate-limit window (nanoseconds)
volatile const __u64 cfg_udp_global_window_ns = 1000000000ULL; // 1 s
volatile const __u64 cfg_syn_window_ns        = 1000000000ULL; // 1 s

// bogon_cfg and slot_def_action remain BPF maps: both are written at
// runtime (Python / bpftool post-load) and therefore cannot be placed in
// the frozen .rodata section without switching to a pre-load skeleton.

// default 10,000 pps; 0 = disabled (documented; actual value lives in map)
#define UDP_GLOBAL_DEFAULT_RATE  10000U

// BPF Maps: hot-updatable TCP/UDP port whitelists (ARRAY implementation)
// The ARRAY map uses the port number (host byte order) as the array index (__u32 key).
// max_entries = 65536 covers all valid ports.
// Usage: bpftool map update pinned /sys/fs/bpf/xdp_fw/tcp_whitelist \
//          key 0x50 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00



// Counter map: per-CPU array for lock-free packet accounting
// Read with: bpftool map dump pinned /sys/fs/bpf/xdp_fw/pkt_counters

enum xdp_counter_idx {
    CNT_TCP_NEW_ALLOW   = 0,  // TCP pure SYN packets allowed by tcp_whitelist
    CNT_TCP_ESTABLISHED = 1,  // TCP established/reply packets allowed by conntrack
    CNT_TCP_DROP        = 2,  // TCP packets dropped (not in whitelist / no conntrack)
    CNT_UDP_PASS        = 3,  // UDP packets allowed
    CNT_UDP_DROP        = 4,  // UDP packets dropped
    CNT_IPV4_OTHER      = 5,  // IPv4 non-TCP/UDP (ICMP, etc.) passed
    CNT_IPV6_OTHER      = 6,  // IPv6 non-TCP/UDP (ICMPv6, etc.) passed
    CNT_FRAG_DROP       = 7,  // Fragmented packets dropped
    CNT_NON_IP          = 8,  // Non-IP traffic (ARP, etc.) passed
    CNT_TCP_CT_MISS     = 9,  // TCP ACK packets dropped due to missing conntrack state
    CNT_ICMP_DROP       = 10, // ICMP/ICMPv6 echo packets dropped by token-bucket rate limiter
    CNT_SYN_RATE_DROP   = 11, // TCP SYN dropped by per-IP rate limiter (anti-brute-force)
    CNT_UDP_RATE_DROP        = 12, // UDP dropped by per-source-IP rate limiter
    CNT_UDP_GLOBAL_RATE_DROP = 13, // UDP dropped by the global sliding-window rate limiter
    CNT_TCP_MALFORM_NULL     = 14, // TCP NULL scan (all flags zero)
    CNT_TCP_MALFORM_XMAS     = 15, // TCP XMAS scan (FIN+URG+PSH)
    CNT_TCP_MALFORM_SYN_FIN  = 16, // TCP SYN+FIN contradictory flags
    CNT_TCP_MALFORM_SYN_RST  = 17, // TCP SYN+RST contradictory flags
    CNT_TCP_MALFORM_RST_FIN  = 18, // TCP RST+FIN contradictory flags
    CNT_TCP_MALFORM_DOFF     = 19, // TCP invalid data offset (doff < 5 or > 15 or truncated)
    CNT_TCP_MALFORM_PORT0    = 20, // TCP src or dst port is 0
    CNT_VLAN_DROP            = 21, // packet dropped: VLAN nesting exceeds VLAN_MAX_DEPTH
    CNT_SLOT_CALL            = 22, // packets dispatched to a slot handler via tail call
    CNT_SLOT_PASS            = 23, // slot miss: no handler, default_action=pass
    CNT_SLOT_DROP            = 24, // slot miss: no handler, default_action=drop
    CNT_UDP_MALFORM_PORT0    = 25, // UDP src or dst port is 0
    CNT_UDP_MALFORM_LEN      = 26, // UDP length field < 8 or exceeds packet boundary
    CNT_BOGON_DROP           = 27, // packet dropped: spoofed/reserved source address
    CNT_TCP_CONN_LIMIT_DROP  = 28, // TCP SYN dropped by per-source concurrent connection limit
    CNT_SYN_AGG_RATE_DROP    = 29, // TCP SYN dropped by per-prefix aggregate rate limiter
    CNT_UDP_AGG_RATE_DROP    = 30, // UDP dropped by per-prefix byte-rate limiter
    CNT_MAX                  = 31,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} pkt_counters SEC(".maps");

static __always_inline void count(enum xdp_counter_idx idx) {
    __u32 key = (__u32)idx;
    __u64 *val = bpf_map_lookup_elem(&pkt_counters, &key);
    if (val)
        (*val)++;
}

struct pkt_event {
    __u64 ts_ns;
    __u32 src_ip[4];   // v4: [0] only; v6: all 4 (network byte order)
    __u32 dst_ip[4];
    __u16 src_port;    // network byte order
    __u16 dst_port;
    __u8  proto;       // IPPROTO_TCP / UDP / ICMP / ICMPV6 …
    __u8  family;      // CT_FAMILY_IPV4=2 / CT_FAMILY_IPV6=10
    __u8  verdict;     // always 1 (DROP) for this ring buffer
    __u8  reason;      // xdp_counter_idx value
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} pkt_ringbuf SEC(".maps");

static __always_inline void emit_drop(
    __u8 proto, __u8 family,
    __u32 *src_ip, __u32 *dst_ip,
    __be16 sport, __be16 dport,
    __u8 reason)
{
    struct pkt_event *e = bpf_ringbuf_reserve(&pkt_ringbuf, sizeof(*e), 0);
    if (!e) return;
    e->ts_ns    = bpf_ktime_get_ns();
    e->proto    = proto;
    e->family   = family;
    e->verdict  = 1;
    e->reason   = reason;
    e->src_port = sport;
    e->dst_port = dport;
    __builtin_memcpy(e->src_ip, src_ip, 16);
    __builtin_memcpy(e->dst_ip, dst_ip, 16);
    bpf_ringbuf_submit(e, 0);
}
