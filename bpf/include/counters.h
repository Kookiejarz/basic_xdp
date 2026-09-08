#pragma once
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>

/* Shared append-only packet counter ABI. */
enum xdp_counter_idx {
    CNT_TCP_NEW_ALLOW   = 0,
    CNT_TCP_PASS        = 1,
    CNT_TCP_DROP        = 2,
    CNT_UDP_PASS        = 3,
    CNT_UDP_DROP        = 4,
    CNT_IPV4_OTHER      = 5,
    CNT_IPV6_OTHER      = 6,
    CNT_FRAG_DROP       = 7,
    CNT_NON_IP          = 8,
    CNT_TCP_RESERVED    = 9,
    CNT_ICMP_DROP       = 10,
    CNT_SYN_RATE_DROP   = 11,
    CNT_UDP_RATE_DROP        = 12,
    CNT_UDP_GLOBAL_RATE_DROP = 13,
    CNT_TCP_MALFORM_NULL     = 14,
    CNT_TCP_MALFORM_XMAS     = 15,
    CNT_TCP_MALFORM_SYN_FIN  = 16,
    CNT_TCP_MALFORM_SYN_RST  = 17,
    CNT_TCP_MALFORM_RST_FIN  = 18,
    CNT_TCP_MALFORM_DOFF     = 19,
    CNT_TCP_MALFORM_PORT0    = 20,
    CNT_VLAN_DROP            = 21,
    CNT_SLOT_CALL            = 22,
    CNT_SLOT_PASS            = 23,
    CNT_SLOT_DROP            = 24,
    CNT_UDP_MALFORM_PORT0    = 25,
    CNT_UDP_MALFORM_LEN      = 26,
    CNT_BOGON_DROP           = 27,
    CNT_RESERVED_28          = 28,
    CNT_SYN_AGG_RATE_DROP    = 29,
    CNT_UDP_AGG_RATE_DROP    = 30,
    CNT_HANDLER_BLOCK_DROP   = 31,
    CNT_RESERVED_32          = 32,
    CNT_RESERVED_33          = 33,
    CNT_ABUSEIPDB_DROP           = 34,
    CNT_PROFILE_UNAVAILABLE_DROP = 35,
    CNT_PROFILE_ALLOW            = 36,
    CNT_PROFILE_DROP             = 37,
    CNT_MAX                      = 38,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} pkt_counters SEC(".maps");

static __always_inline void count(enum xdp_counter_idx idx)
{
    __u32 key = (__u32)idx;
    __u64 *value = bpf_map_lookup_elem(&pkt_counters, &key);
    if (value)
        (*value)++;
}

/* index 0 = total bytes, 1 = drop bytes, 2 = total packets, 3 = drops. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} byte_counters SEC(".maps");

static __always_inline void count_bytes(bool is_drop, __u32 pkt_len)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&byte_counters, &key);
    if (value)
        (*value) += pkt_len;
    key = 2;
    value = bpf_map_lookup_elem(&byte_counters, &key);
    if (value)
        (*value)++;
    if (is_drop) {
        key = 1;
        value = bpf_map_lookup_elem(&byte_counters, &key);
        if (value)
            (*value) += pkt_len;
        key = 3;
        value = bpf_map_lookup_elem(&byte_counters, &key);
        if (value)
            (*value)++;
    }
}
