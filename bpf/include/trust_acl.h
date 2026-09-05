#pragma once
#include "maps.h"

static __always_inline bool bogon_filter_active(void)
{
    struct xdp_runtime_cfg *cfg = runtime_cfg();
    return !cfg || !(cfg->cfg_flags & XDP_CFG_FLAG_BOGON_DISABLED);
}

static __always_inline bool is_bogon_v4(__be32 addr)
{
    __u32 a = bpf_ntohl(addr);
    __u8  o1 = a >> 24;
    if (o1 == 0)                                    return true; // 0.0.0.0/8
    if (o1 == 10)                                   return true; // 10.0.0.0/8
    if (o1 == 127)                                  return true; // 127.0.0.0/8
    if ((a & 0xFFC00000) == 0x64400000)             return true; // 100.64.0.0/10  CGNAT
    if ((a & 0xFFFF0000) == 0xA9FE0000)             return true; // 169.254.0.0/16 link-local
    if ((a & 0xFFF00000) == 0xAC100000)             return true; // 172.16.0.0/12
    if ((a & 0xFFFF0000) == 0xC0A80000)             return true; // 192.168.0.0/16
    if ((a & 0xF0000000) == 0xE0000000)             return true; // 224.0.0.0/4    multicast
    if ((a & 0xF0000000) == 0xF0000000)             return true; // 240.0.0.0/4    reserved
    return false;
}

static __always_inline bool is_bogon_v6(const struct in6_addr *addr)
{
    __u32 w0 = bpf_ntohl(addr->in6_u.u6_addr32[0]);
    __u32 w1 = bpf_ntohl(addr->in6_u.u6_addr32[1]);
    __u32 w2 = bpf_ntohl(addr->in6_u.u6_addr32[2]);
    __u32 w3 = bpf_ntohl(addr->in6_u.u6_addr32[3]);
    if (w0 == 0 && w1 == 0 && w2 == 0 && w3 == 0)  return true; // ::/128       unspecified
    if (w0 == 0 && w1 == 0 && w2 == 0 && w3 == 1)  return true; // ::1/128      loopback
    if ((w0 & 0xFE000000) == 0xFC000000)            return true; // fc00::/7     unique-local
    if ((w0 & 0xFFC00000) == 0xFE800000)            return true; // fe80::/10    link-local
    if ((w0 & 0xFF000000) == 0xFF000000)            return true; // ff00::/8     multicast
    if (w0 == 0 && w1 == 0 && w2 == 0x0000FFFF)    return true; // ::ffff:0:0/96 IPv4-mapped
    return false;
}

static __always_inline bool is_trusted_v4(__be32 saddr)
{
    struct trusted_v4_key tk = { .prefixlen = 32, .addr = saddr };
    __u32 *v = bpf_map_lookup_elem(&trusted_ipv4, &tk);
    return v && *v;
}

static __always_inline bool is_trusted_v6(const struct in6_addr *saddr)
{
    struct trusted_v6_key tk;
    tk.prefixlen = 128;
    __builtin_memcpy(tk.addr, saddr, 16);
    __u32 *v = bpf_map_lookup_elem(&trusted_ipv6, &tk);
    return v && *v;
}

static __always_inline bool acl_port_match(struct acl_val *v, __u32 port)
{
    __u16 p = (__u16)port;
    __u32 n = v->count < ACL_MAX_PORTS ? v->count : ACL_MAX_PORTS;
    for (__u32 i = 0; i < ACL_MAX_PORTS; i++) {
        if (i >= n) break;
        if (v->ports[i] == p) return true;
    }
    return false;
}

static __always_inline bool tcp_acl_allowed(const struct flow_key *key, __u32 port)
{
    if (key->family == CT_FAMILY_IPV4) {
        struct trusted_v4_key tk = {
            .prefixlen = 32,
            .addr = (__be32)key->saddr[0],
        };
        struct acl_val *av = bpf_map_lookup_elem(&tcp_acl_v4, &tk);
        return av && acl_port_match(av, port);
    }

    struct trusted_v6_key tk;
    tk.prefixlen = 128;
    __builtin_memcpy(tk.addr, key->saddr, 16);
    struct acl_val *av = bpf_map_lookup_elem(&tcp_acl_v6, &tk);
    return av && acl_port_match(av, port);
}

static __always_inline bool abuseipdb_active(void)
{
    struct xdp_runtime_cfg *cfg = runtime_cfg();
    return cfg && (cfg->cfg_flags & XDP_CFG_FLAG_ABUSEIPDB_ENABLED);
}

static __always_inline bool is_abuseipdb_v4(__be32 addr)
{
    struct trusted_v4_key k = { .prefixlen = 32, .addr = addr };
    __u32 *v = bpf_map_lookup_elem(&abuseipdb_v4, &k);
    return v && *v;
}
