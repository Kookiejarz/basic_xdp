#pragma once
#include "maps.h"

static __always_inline bool tcp_exposure_allowed(struct xdp_md *ctx, __u32 dest_port)
{
    struct zone_port_key zone_key = {
        .ifindex = ctx->ingress_ifindex,
        .port = dest_port,
    };
    __u32 *zone_allow = bpf_map_lookup_elem(&tcp_zone_whitelist, &zone_key);
    if (zone_allow && *zone_allow)
        return true;
    __u32 *allow = bpf_map_lookup_elem(&tcp_whitelist, &dest_port);
    return allow && *allow;
}

static __always_inline bool udp_exposure_allowed(struct xdp_md *ctx, __u32 dest_port)
{
    struct zone_port_key zone_key = {
        .ifindex = ctx->ingress_ifindex,
        .port = dest_port,
    };
    __u32 *zone_allow = bpf_map_lookup_elem(&udp_zone_whitelist, &zone_key);
    if (zone_allow && *zone_allow)
        return true;
    __u32 *allow = bpf_map_lookup_elem(&udp_whitelist, &dest_port);
    return allow && *allow;
}

static __always_inline void fill_flow_key_v4(
    struct flow_key *key, __be32 saddr, __be32 daddr,
    __be16 sport, __be16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = CT_FAMILY_IPV4;
    key->sport = sport;
    key->dport = dport;
    key->saddr[0] = (__u32)saddr;
    key->daddr[0] = (__u32)daddr;
}

static __always_inline void fill_flow_key_v6(
    struct flow_key *key, const struct in6_addr *saddr, const struct in6_addr *daddr,
    __be16 sport, __be16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = CT_FAMILY_IPV6;
    key->sport = sport;
    key->dport = dport;
    __builtin_memcpy(key->saddr, saddr, sizeof(*saddr));
    __builtin_memcpy(key->daddr, daddr, sizeof(*daddr));
}
