#pragma once
#include "common.h"

// TCP malformed packet check. Called after the basic 20-byte bounds check,
// before policy evaluation. Returns XDP_DROP (and increments the appropriate counter)
// for any packet that violates RFC 793 structural invariants.
// Returns 0 for valid packets, or a CNT_TCP_MALFORM_* reason code for drops.
// count() and emit_drop() are the caller's responsibility.
static __always_inline __u8 tcp_malformed_reason(struct tcphdr *tcp, void *data_end)
{
    __u8 doff = tcp->doff;
    if (doff < 5 || doff > 15)
        return (__u8)CNT_TCP_MALFORM_DOFF;
    if ((void *)tcp + ((__u32)doff * 4) > data_end)
        return (__u8)CNT_TCP_MALFORM_DOFF;
    if (tcp->source == 0 || tcp->dest == 0)
        return (__u8)CNT_TCP_MALFORM_PORT0;

    __u8 flags = ((__u8 *)tcp)[13];
    if (flags == 0)
        return (__u8)CNT_TCP_MALFORM_NULL;
    if ((flags & 0x03) == 0x03)
        return (__u8)CNT_TCP_MALFORM_SYN_FIN;
    if ((flags & 0x06) == 0x06)
        return (__u8)CNT_TCP_MALFORM_SYN_RST;
    if ((flags & 0x05) == 0x05)
        return (__u8)CNT_TCP_MALFORM_RST_FIN;
    if ((flags & 0x29) == 0x29)
        return (__u8)CNT_TCP_MALFORM_XMAS;
    return 0;
}

// Returns 0 for valid packets, or a CNT_UDP_MALFORM_* reason code for drops.
// count() and emit_drop() are the caller's responsibility.
// l4_avail = (u32)(data_end - udp): caller computes this via pointer subtraction
// (not addition) before the call so the verifier retains range tracking.
static __always_inline __u8 udp_malformed_reason(struct udphdr *udp, __u32 l4_avail)
{
    if (udp->source == 0 || udp->dest == 0)
        return (__u8)CNT_UDP_MALFORM_PORT0;
    __u16 ulen = bpf_ntohs(udp->len);
    if (ulen < 8 || ulen > l4_avail)
        return (__u8)CNT_UDP_MALFORM_LEN;
    return 0;
}

// IPv6 extension header traversal to prevent bypassing port checks

static __always_inline __u8 skip_ipv6_exthdr(
    void **trans_data, void *data_end, __u8 nexthdr)
{
    // Traverse at most 6 extension headers; treat more as anomalous and let the
    // caller apply its fail-closed policy.
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        switch (nexthdr) {
        case IPPROTO_HOPOPTS:  // 0  Hop-by-Hop options
        case IPPROTO_ROUTING:  // 43 Routing header
        case IPPROTO_DSTOPTS:  // 60 Destination options
        {
            __u8 *hdr = *trans_data;
            if ((void *)(hdr + 2) > data_end)
                return IPV6_EXTHDR_MALFORMED_SENTINEL;
            nexthdr = hdr[0];
            __u32 hdrlen = (((__u32)hdr[1] + 1) * 8);
            *trans_data += hdrlen;
            if (*trans_data > data_end)
                return IPV6_EXTHDR_MALFORMED_SENTINEL;
            break;
        }
        case IPPROTO_FRAGMENT: // 44 Fragment header (fixed 8 bytes)
        {
            __u8 *hdr = *trans_data;
            __u16 frag_off_flags;
            if ((void *)(hdr + 8) > data_end)
                return IPV6_EXTHDR_MALFORMED_SENTINEL;
            frag_off_flags = ((__u16)hdr[2] << 8) | hdr[3];
            if (frag_off_flags & 0xFFF8)
                return IPV6_FRAG_DROP_SENTINEL;
            nexthdr = hdr[0];
            *trans_data += 8;
            break;
        }
        default:
            // TCP / UDP / ICMPv6 / other: stop traversal
            return nexthdr;
        }
    }
    return IPV6_EXTHDR_MALFORMED_SENTINEL;
}

// Strip up to VLAN_MAX_DEPTH 802.1Q/802.1AD tags from the Ethernet frame.
// Returns false if the packet is truncated mid-tag (caller should XDP_DROP).
// After a successful return, if *eth_proto is still 0x8100/0x88a8 the nesting
// depth exceeds VLAN_MAX_DEPTH and the caller should DROP.
static __always_inline bool strip_vlan_tags(
    __be16 *eth_proto, void **l3_data, void *data_end)
{
    #pragma unroll
    for (int i = 0; i < VLAN_MAX_DEPTH; i++) {
        if (*eth_proto != bpf_htons(ETH_P_8021Q) &&
            *eth_proto != bpf_htons(ETH_P_8021AD))
            return true;
        struct vlan_hdr *vlan = *l3_data;
        if ((void *)(vlan + 1) > data_end)
            return false; // truncated: do not let it bypass XDP policy
        *eth_proto = vlan->h_vlan_encapsulated_proto;
        *l3_data   = (void *)(vlan + 1);
    }
    return true; // loop exhausted; caller checks whether eth_proto is still VLAN
}
