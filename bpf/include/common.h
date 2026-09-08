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
#include "../../handlers/xdp_slot_ctx.h"
#include "../../handlers/xdp_profile_ctx.h"
#include "counters.h"
#include "flow_keys.h"

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
#define IPV6_EXTHDR_MALFORMED_SENTINEL 0xFE
#define VLAN_MAX_DEPTH 4
#define NS_PER_SEC 1000000000ULL

#define TCP_FLAG_FIN  0x01
#define TCP_FLAG_SYN  0x02
#define TCP_FLAG_RST  0x04
#define TCP_FLAG_ACK  0x10


// cfg_flags bits for xdp_runtime_cfg.cfg_flags.
// Zero means "all defaults" so old loaders remain compatible.
#define XDP_CFG_FLAG_BOGON_DISABLED       (1U << 0)  // bogon filter off (default: on)
#define XDP_CFG_FLAG_ABUSEIPDB_ENABLED    (1U << 1)  // AbuseIPDB active (default: off)
#define XDP_CFG_FLAG_DROP_EVENTS_DISABLED (1U << 2)  // ring-buf events off (default: on)
#define XDP_CFG_FLAG_SLOT_DROP            (1U << 3)  // unknown proto → drop (default: pass)

// Runtime tunables. Userspace writes this map from config.toml; zero fields
// fall back to defaults so old loaders remain compatible.
struct xdp_runtime_cfg {
    __u64 _reserved0;
    __u64 _reserved1;
    __u64 _reserved2;
    __u64 icmp_token_max;
    __u64 icmp_ns_per_token;
    __u64 udp_global_window_ns;
    __u64 rate_window_ns;
    __u64 _reserved7;
    __u32 cfg_flags;        // XDP_CFG_FLAG_* bits; replaces bogon_cfg/abuseipdb_cfg/observability_cfg/slot_def_action
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_runtime_cfg);
} xdp_runtime_cfg SEC(".maps");

static __always_inline struct xdp_runtime_cfg *runtime_cfg(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&xdp_runtime_cfg, &key);
}

// cfg_*_ns(): pre-fetched cfg pointer variants — callers that already hold a
// runtime_cfg() pointer use these to avoid redundant map lookups in hot paths.
static __always_inline __u64 cfg_udp_global_window_ns(struct xdp_runtime_cfg *cfg)
{
    return cfg && cfg->udp_global_window_ns ? cfg->udp_global_window_ns : NS_PER_SEC;
}

static __always_inline __u64 cfg_rate_window_ns(struct xdp_runtime_cfg *cfg)
{
    return cfg && cfg->rate_window_ns ? cfg->rate_window_ns : NS_PER_SEC;
}

// BPF Maps: hot-updatable TCP/UDP port whitelists (ARRAY implementation)
// The ARRAY map uses the port number (host byte order) as the array index (__u32 key).
// max_entries = 65536 covers all valid ports.
// Usage: bpftool map update pinned /sys/fs/bpf/xdp_fw/tcp_whitelist \
//          key 0x50 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00



// Counter map: per-CPU array for lock-free packet accounting
// Read with: bpftool map dump pinned /sys/fs/bpf/xdp_fw/pkt_counters

struct pkt_event {
    __u64 ts_ns;
    __u32 src_ip[4];   // v4: [0] only; v6: all 4 (network byte order)
    __u32 dst_ip[4];
    __u16 src_port;    // network byte order
    __u16 dst_port;
    __u8  proto;       // IPPROTO_TCP / UDP / ICMP / ICMPV6 …
    __u8  family;      // IPv4=2 / IPv6=10
    __u8  verdict;     // always 1 (DROP) for this ring buffer
    __u8  reason;      // xdp_counter_idx value
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); // 4 MiB
} pkt_ringbuf SEC(".maps");

static __always_inline bool drop_events_enabled(void)
{
    struct xdp_runtime_cfg *cfg = runtime_cfg();
    return !cfg || !(cfg->cfg_flags & XDP_CFG_FLAG_DROP_EVENTS_DISABLED);
}

static __always_inline void emit_packet_event(
    __u8 proto, __u8 family,
    const __u32 *src_ip, const __u32 *dst_ip,
    __be16 sport, __be16 dport,
    __u8 verdict,
    __u8 reason,
    __u64 now)
{
    if (!drop_events_enabled())
        return;
    struct pkt_event *e = bpf_ringbuf_reserve(&pkt_ringbuf, sizeof(*e), 0);
    if (!e) return;
    e->ts_ns    = now;
    e->proto    = proto;
    e->family   = family;
    e->verdict  = verdict;
    e->reason   = reason;
    e->src_port = sport;
    e->dst_port = dport;
    __builtin_memcpy(e->src_ip, src_ip, 16);
    __builtin_memcpy(e->dst_ip, dst_ip, 16);
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_drop(
    __u8 proto, __u8 family,
    const __u32 *src_ip, const __u32 *dst_ip,
    __be16 sport, __be16 dport,
    __u8 reason,
    __u64 now)
{
    emit_packet_event(proto, family, src_ip, dst_ip, sport, dport, 1, reason, now);
}

static __always_inline void emit_allow(
    __u8 proto, __u8 family,
    const __u32 *src_ip, const __u32 *dst_ip,
    __be16 sport, __be16 dport,
    __u8 reason,
    __u64 now)
{
    emit_packet_event(proto, family, src_ip, dst_ip, sport, dport, 2, reason, now);
}
