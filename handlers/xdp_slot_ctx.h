#pragma once
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Context written by the main XDP program immediately before a
 * bpf_tail_call() into a protocol slot handler.  Handlers read
 * this via get_slot_ctx() to skip re-parsing headers already
 * validated by the main program.
 *
 *  family       : FAMILY_IPV4 (2) or FAMILY_IPV6 (10)
 *  ip_proto     : final L4 protocol number — for IPv6 this is the
 *                 result of skip_ipv6_exthdr(), never an ext-hdr type
 *  l3_offset    : byte offset from ctx->data to the IP/IPv6 header
 *  inner_offset : byte offset from ctx->data to the first byte past
 *                 all IP options / IPv6 extension headers (L4 payload)
 *  sport/dport  : source/destination port (network byte order);
 *                 0 for non-TCP/UDP protocol-level handlers
 *  saddr/daddr  : parsed source/destination addresses;
 *                 IPv4 uses word [0] only, IPv6 uses all four words
 *
 * Size is 44 bytes (multiple of 4 — satisfies bpf_xdp_adjust_meta alignment).
 */
struct xdp_slot_ctx {
    __u8   family;
    __u8   ip_proto;
    __u16  l3_offset;
    __u16  inner_offset;
    __be16 sport;
    __be16 dport;
    __u16  _pad;
    __u32  saddr[4];
    __u32  daddr[4];
};

/*
 * Per-CPU scratch map: fallback for generic/skb XDP mode where
 * bpf_xdp_adjust_meta is unsupported.  Native XDP uses the metadata
 * region instead and never touches this map on the read path.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_slot_ctx);
} slot_ctx_map SEC(".maps");

/*
 * Retrieve the slot context set by the main program before the tail call.
 * Native XDP: reads directly from the packet metadata region (no map lookup).
 * Generic XDP: falls back to slot_ctx_map.
 */
static __always_inline struct xdp_slot_ctx *get_slot_ctx(struct xdp_md *ctx)
{
    void *meta = (void *)(long)ctx->data_meta;
    void *data = (void *)(long)ctx->data;
    if (meta + sizeof(struct xdp_slot_ctx) <= data)
        return (struct xdp_slot_ctx *)meta;
    __u32 key = 0;
    return bpf_map_lookup_elem(&slot_ctx_map, &key);
}
