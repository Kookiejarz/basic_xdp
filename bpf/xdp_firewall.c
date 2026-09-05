/* bpf/xdp_firewall.c — XDP entry point.
 * All helpers live under bpf/include/ as one translation unit. */

#include "include/common.h"
#include "include/keys.h"
#include "include/maps.h"
#include "include/trust_acl.h"
#include "include/rate_limit.h"
#include "include/port_dispatch.h"
#include "include/exposure.h"
#include "include/parse.h"
#include "include/slots.h"

/* --- Protocol dispatch functions --- */

static __always_inline int check_tcp_policy(
    struct xdp_md *ctx, struct flow_key *key, __u8 tcp_flags,
    __u32 dest_port, __u16 l3_off, __u16 inner_off)
{
    __u64 now = bpf_ktime_get_ns();
    struct xdp_runtime_cfg *cfg = runtime_cfg();

    if (!tcp_exposure_allowed(ctx, dest_port))
        goto drop;

    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
        bool bypass_rate = key->family == CT_FAMILY_IPV4
            ? is_trusted_v4((__be32)key->saddr[0])
            : is_trusted_v6((const struct in6_addr *)key->saddr);
        bypass_rate = bypass_rate || tcp_acl_allowed(key, dest_port);
        if (!bypass_rate && abuseipdb_active() && key->family == CT_FAMILY_IPV4 &&
            is_abuseipdb_v4((__be32)key->saddr[0])) {
            count(CNT_ABUSEIPDB_DROP);
            goto drop;
        }
        if (is_handler_blocked(key))
            goto drop;
        if (precheck_new_tcp_syn(key, dest_port, bypass_rate, now, cfg) == XDP_DROP)
            return XDP_DROP;
        try_tcp_port_dispatch(ctx, key, l3_off, inner_off, dest_port);
        count(CNT_TCP_NEW_ALLOW);
        emit_allow(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                   key->sport, key->dport, (__u8)CNT_TCP_NEW_ALLOW, now);
        return XDP_PASS;
    }

    try_tcp_port_dispatch(ctx, key, l3_off, inner_off, dest_port);
    count(CNT_TCP_PASS);
    return XDP_PASS;

drop:
    count(CNT_TCP_DROP);
    emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
              key->sport, key->dport, (__u8)CNT_TCP_DROP, now);
    return XDP_DROP;
}

static __always_inline int check_tcp_ipv4(
    struct xdp_md *ctx,
    struct iphdr *ip, void *trans_data, void *data_end,
    __u16 l3_off, __u16 inner_off)
{
    struct tcphdr *tcp = trans_data;
    struct flow_key key;

    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    __u8 malform = tcp_malformed_reason(tcp, data_end);
    if (malform) {
        count(malform);
        count(CNT_TCP_DROP);
        __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
        __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
        __u64 _now = bpf_ktime_get_ns();
        emit_drop(IPPROTO_TCP, CT_FAMILY_IPV4, s, d,
                  tcp->source, tcp->dest, malform, _now);
        return XDP_DROP;
    }

    __u8  tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);
    fill_flow_key_v4(&key, ip->saddr, ip->daddr, tcp->source, tcp->dest);

    // Malformed-packet check already ran above; fragments dropped before we arrive.
    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
        // Trust and ACLs can bypass mitigation, but never create exposure.
        // The shared TCP path below remains the authorization boundary.
    }

    return check_tcp_policy(ctx, &key, tcp_flags, dest_port, l3_off, inner_off);
}

static __always_inline int check_tcp_ipv6(
    struct xdp_md *ctx,
    struct ipv6hdr *ipv6, void *trans_data, void *data_end,
    __u16 l3_off, __u16 inner_off)
{
    struct tcphdr *tcp = trans_data;
    struct flow_key key;

    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    __u8 malform = tcp_malformed_reason(tcp, data_end);
    if (malform) {
        count(malform);
        count(CNT_TCP_DROP);
        __u32 s[4], d[4];
        __builtin_memcpy(s, &ipv6->saddr, 16);
        __builtin_memcpy(d, &ipv6->daddr, 16);
        __u64 _now = bpf_ktime_get_ns();
        emit_drop(IPPROTO_TCP, CT_FAMILY_IPV6, s, d,
                  tcp->source, tcp->dest, malform, _now);
        return XDP_DROP;
    }

    __u8 tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);
    fill_flow_key_v6(&key, &ipv6->saddr, &ipv6->daddr, tcp->source, tcp->dest);

    // Malformed-packet check already ran above; fragments dropped before we arrive.
    if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
        // Trust and ACLs can bypass mitigation, but never create exposure.
        // The shared TCP path below remains the authorization boundary.
    }

    return check_tcp_policy(ctx, &key, tcp_flags, dest_port, l3_off, inner_off);
}

static __always_inline int check_udp_ipv4(
    struct xdp_md *ctx,
    struct iphdr *ip, void *trans_data, void *data_end,
    __u16 l3_off, __u16 inner_off)
{
    struct udphdr *udp = trans_data;
    struct flow_key key;
    struct udp_validation_key_v4 validation_key;
    __u64 now = bpf_ktime_get_ns();
    struct xdp_runtime_cfg *cfg = runtime_cfg();

    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    __u32 l4_avail = (__u32)((__u8 *)data_end - (__u8 *)udp);
    __u8 malform = udp_malformed_reason(udp, l4_avail);
    if (malform) {
        count(malform);
        count(CNT_UDP_DROP);
        __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
        __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, s, d,
                  udp->source, udp->dest, malform, now);
        return XDP_DROP;
    }

    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);
    __u64 pkt_bytes = (__u64)bpf_ntohs(ip->tot_len);
    struct udp_port_policy_cfg *policy;

    fill_flow_key_v4(&key, ip->saddr, ip->daddr, udp->source, udp->dest);
    fill_udp_validation_key_v4(&validation_key, &key);

    if (!udp_exposure_allowed(ctx, dest_port)) {
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_UDP_DROP, now);
        return XDP_DROP;
    }

    // Trusted sources bypass the threat-intel blocklist and all rate limits at
    // all times — mirrors the TCP path, where a trusted SYN returns before the
    // AbuseIPDB/handler-block checks ever run.
    if (is_trusted_v4(ip->saddr)) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    if (abuseipdb_active() && is_abuseipdb_v4(ip->saddr)) {
        count(CNT_ABUSEIPDB_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_ABUSEIPDB_DROP, now);
        return XDP_DROP;
    }

    {
        // Reached only by untrusted sources (trusted returned above), so the
        // global UDP rate block applies unconditionally here.
        __u32 rl_key = 0;
        struct udp_percpu_local *local_pre = bpf_map_lookup_elem(&udp_percpu_acc, &rl_key);
        if (local_pre && udp_global_block_fast_path(local_pre, now) == XDP_DROP) {
            count(CNT_UDP_GLOBAL_RATE_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_UDP_GLOBAL_RATE_DROP, now);
            return XDP_DROP;
        }
    }

    {
        __u64 *valid_until = bpf_map_lookup_elem(&udp_hv4, &validation_key);
        if (valid_until && now < *valid_until) {
            count(CNT_UDP_PASS);
            return XDP_PASS;
        }
    }

    {
        struct trusted_v4_key tk = { .prefixlen = 32, .addr = ip->saddr };
        struct acl_val *av = bpf_map_lookup_elem(&udp_acl_v4, &tk);
        if (av && acl_port_match(av, dest_port)) {
            count(CNT_UDP_PASS);
            return XDP_PASS;
        }
    }

    if (is_handler_blocked(&key)) {
        count(CNT_HANDLER_BLOCK_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_HANDLER_BLOCK_DROP, now);
        return XDP_DROP;
    }
    policy = bpf_map_lookup_elem(&udp_port_policies, &dest_port);
    if (udp_rate_check(
            &key, now, dest_port,
            policy ? policy->rate_max : 0,
            policy ? policy->source_prefix_v4 : 32,
            policy ? policy->source_prefix_v6 : 128,
            cfg) == XDP_DROP) {
        count(CNT_UDP_RATE_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_UDP_RATE_DROP, now);
        return XDP_DROP;
    }
    if (udp_agg_rate_check(
            &key, now, dest_port, pkt_bytes,
            policy ? policy->agg_rate_max : 0,
            policy ? policy->source_prefix_v4 : 32,
            policy ? policy->source_prefix_v6 : 128,
            cfg) == XDP_DROP) {
        count(CNT_UDP_AGG_RATE_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_UDP_AGG_RATE_DROP, now);
        return XDP_DROP;
    }
    if (udp_global_rate_check(now, pkt_bytes, cfg) == XDP_DROP) {
        count(CNT_UDP_GLOBAL_RATE_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV4, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_UDP_GLOBAL_RATE_DROP, now);
        return XDP_DROP;
    }
    try_udp_port_dispatch(ctx, &key, l3_off, inner_off, dest_port);
    count(CNT_UDP_PASS);
    return XDP_PASS;
}

static __always_inline int check_udp_ipv6(
    struct xdp_md *ctx,
    struct ipv6hdr *ipv6, void *trans_data, void *data_end,
    __u16 l3_off, __u16 inner_off)
{
    struct udphdr *udp = trans_data;
    struct flow_key key;
    struct udp_validation_key_v6 validation_key;
    __u64 now = bpf_ktime_get_ns();
    struct xdp_runtime_cfg *cfg = runtime_cfg();
    struct udp_port_policy_cfg *policy;

    if ((void *)(udp + 1) > data_end)
        return XDP_DROP;

    __u32 l4_avail = (__u32)((__u8 *)data_end - (__u8 *)udp);
    __u8 malform = udp_malformed_reason(udp, l4_avail);
    if (malform) {
        count(malform);
        count(CNT_UDP_DROP);
        __u32 s[4], d[4];
        __builtin_memcpy(s, &ipv6->saddr, 16);
        __builtin_memcpy(d, &ipv6->daddr, 16);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, s, d,
                  udp->source, udp->dest, malform, now);
        return XDP_DROP;
    }

    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);
    __u64 pkt_bytes = (__u64)sizeof(*ipv6) + (__u64)bpf_ntohs(ipv6->payload_len);

    fill_flow_key_v6(&key, &ipv6->saddr, &ipv6->daddr, udp->source, udp->dest);
    fill_udp_validation_key_v6(&validation_key, &key);


    if (!udp_exposure_allowed(ctx, dest_port)) {
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_UDP_DROP, now);
        return XDP_DROP;
    }

    // Trusted sources bypass all rate limits at all times (parallel to the IPv4
    // path; the AbuseIPDB blocklist is IPv4-only, so there is nothing else to
    // skip here).
    if (is_trusted_v6(&ipv6->saddr)) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    {
        // Reached only by untrusted sources (trusted returned above), so the
        // global UDP rate block applies unconditionally here.
        __u32 rl_key = 0;
        struct udp_percpu_local *local_pre = bpf_map_lookup_elem(&udp_percpu_acc, &rl_key);
        if (local_pre && udp_global_block_fast_path(local_pre, now) == XDP_DROP) {
            count(CNT_UDP_GLOBAL_RATE_DROP);
            count(CNT_UDP_DROP);
            emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                      key.sport, key.dport, (__u8)CNT_UDP_GLOBAL_RATE_DROP, now);
            return XDP_DROP;
        }
    }

    {
        __u64 *valid_until = bpf_map_lookup_elem(&udp_hv6, &validation_key);
        if (valid_until && now < *valid_until) {
            count(CNT_UDP_PASS);
            return XDP_PASS;
        }
    }

    {
        struct trusted_v6_key tk;
        tk.prefixlen = 128;
        __builtin_memcpy(tk.addr, &ipv6->saddr, 16);
        struct acl_val *av = bpf_map_lookup_elem(&udp_acl_v6, &tk);
        if (av && acl_port_match(av, dest_port)) {
            count(CNT_UDP_PASS);
            return XDP_PASS;
        }
    }

    if (is_handler_blocked(&key)) {
        count(CNT_HANDLER_BLOCK_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_HANDLER_BLOCK_DROP, now);
        return XDP_DROP;
    }
    policy = bpf_map_lookup_elem(&udp_port_policies, &dest_port);
    if (udp_rate_check(
            &key, now, dest_port,
            policy ? policy->rate_max : 0,
            policy ? policy->source_prefix_v4 : 32,
            policy ? policy->source_prefix_v6 : 128,
            cfg) == XDP_DROP) {
        count(CNT_UDP_RATE_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_UDP_RATE_DROP, now);
        return XDP_DROP;
    }
    if (udp_agg_rate_check(
            &key, now, dest_port, pkt_bytes,
            policy ? policy->agg_rate_max : 0,
            policy ? policy->source_prefix_v4 : 32,
            policy ? policy->source_prefix_v6 : 128,
            cfg) == XDP_DROP) {
        count(CNT_UDP_AGG_RATE_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_UDP_AGG_RATE_DROP, now);
        return XDP_DROP;
    }
    if (udp_global_rate_check(now, pkt_bytes, cfg) == XDP_DROP) {
        count(CNT_UDP_GLOBAL_RATE_DROP);
        count(CNT_UDP_DROP);
        emit_drop(IPPROTO_UDP, CT_FAMILY_IPV6, key.saddr, key.daddr,
                  key.sport, key.dport, (__u8)CNT_UDP_GLOBAL_RATE_DROP, now);
        return XDP_DROP;
    }
    try_udp_port_dispatch(ctx, &key, l3_off, inner_off, dest_port);
    count(CNT_UDP_PASS);
    return XDP_PASS;
}

// ICMP token-bucket rate limiter: returns XDP_PASS or XDP_DROP.
// Tokens refill at (1e9/cfg->icmp_ns_per_token) per second up to cfg->icmp_token_max.
static __always_inline int icmp_rate_limit(void)
{
    __u32 key = 0;
    struct icmp_token_bucket *tb = bpf_map_lookup_elem(&icmp_tb, &key);
    if (!tb)
        return XDP_PASS; // fail-open: never block because of a map miss

    __u64 now = bpf_ktime_get_ns();
    struct xdp_runtime_cfg *cfg = runtime_cfg();
    __u64 token_max = (cfg && cfg->icmp_token_max) ? cfg->icmp_token_max : 100ULL;
    __u64 ns_per_token = (cfg && cfg->icmp_ns_per_token)
                       ? cfg->icmp_ns_per_token
                       : NS_PER_SEC / 100ULL;
    int ret;

    bpf_spin_lock(&tb->lock);

    if (tb->last_refill_ns == 0) {
        // First ICMP packet ever: start with a full bucket.
        tb->tokens = token_max;
        tb->last_refill_ns = now;
    } else {
        // Add whole tokens for elapsed time; advance the refill clock by the
        // consumed intervals only (prevents credit accumulation across idle gaps).
        __u64 elapsed = now - tb->last_refill_ns;
        __u64 new_tokens = elapsed / ns_per_token;
        if (new_tokens > 0) {
            tb->tokens += new_tokens;
            if (tb->tokens > token_max)
                tb->tokens = token_max;
            tb->last_refill_ns += new_tokens * ns_per_token;
        }
    }

    if (tb->tokens > 0) {
        tb->tokens--;
        ret = XDP_PASS;
    } else {
        ret = XDP_DROP;
    }

    bpf_spin_unlock(&tb->lock);
    return ret;
}

static __always_inline int _xdp_fw(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u64 now      = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    // Strip 802.1Q / QinQ VLAN tags so firewall rules apply to the inner
    // EtherType.  Without this, VLAN-tagged IP packets arrive with
    // h_proto=0x8100 and bypass all port/policy checks via CNT_NON_IP.
    __be16 eth_proto = eth->h_proto;
    void  *l3_data   = (void *)(eth + 1);

    if (!strip_vlan_tags(&eth_proto, &l3_data, data_end))
        return XDP_DROP; // truncated VLAN header cannot be classified safely

    // Drop packets with more VLAN layers than VLAN_MAX_DEPTH — no legitimate
    // traffic uses such deep nesting; deeper tags are a known bypass technique.
    if (eth_proto == bpf_htons(ETH_P_8021Q) ||
        eth_proto == bpf_htons(ETH_P_8021AD)) {
        count(CNT_VLAN_DROP);
        { __u32 z[4]; __builtin_memset(z, 0, 16);
          emit_drop(0, 0, z, z, 0, 0, (__u8)CNT_VLAN_DROP, now); }
        return XDP_DROP;
    }

    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3_data;
        if ((void *)(ip + 1) > data_end)
            return XDP_DROP;

        // Validate ihl before reading frag_off
        __u32 ip_hlen = ip->ihl * 4;
        if (ip_hlen < sizeof(*ip) || (void *)ip + ip_hlen > data_end)
            return XDP_DROP;

        // Drop IPv4 fragmented packets (rarely needed on personal servers, and fragments can bypass port filtering)
        if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
            count(CNT_FRAG_DROP);
            { __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
              __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
              emit_drop(ip->protocol, CT_FAMILY_IPV4, s, d, 0, 0, (__u8)CNT_FRAG_DROP, now); }
            return XDP_DROP;
        }

        void *trans_data = (void *)ip + ip_hlen;

        if (bogon_filter_active() && is_bogon_v4(ip->saddr)) {
            count(CNT_BOGON_DROP);
            { __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
              __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
              emit_drop(ip->protocol, CT_FAMILY_IPV4, s, d, 0, 0, (__u8)CNT_BOGON_DROP, now); }
            return XDP_DROP;
        }

        __u16 l3_off    = (__u16)((void *)ip - data);
        __u16 inner_off = (__u16)(trans_data - data);

        switch (ip->protocol) {
        case IPPROTO_TCP:
            return check_tcp_ipv4(ctx, ip, trans_data, data_end, l3_off, inner_off);
        case IPPROTO_UDP:
            return check_udp_ipv4(ctx, ip, trans_data, data_end, l3_off, inner_off);
        case IPPROTO_ICMP: {
            struct icmphdr *icmp = trans_data;
            if ((void *)(icmp + 1) > data_end) {
                count(CNT_IPV4_OTHER);
                return XDP_DROP;
            }
            __u8 icmp_type = icmp->type;
            // Control-plane messages required for PMTU discovery, traceroute,
            // and error feedback — never rate-limit these.
            if (icmp_type == ICMP_DEST_UNREACH  ||
                icmp_type == ICMP_TIME_EXCEEDED  ||
                icmp_type == ICMP_PARAMETERPROB) {
                count(CNT_IPV4_OTHER);
                return XDP_PASS;
            }
            // Echo request from untrusted source: token-bucket rate limit.
            if (icmp_type == ICMP_ECHO &&
                !is_trusted_v4(ip->saddr) &&
                icmp_rate_limit() == XDP_DROP) {
                count(CNT_ICMP_DROP);
                { __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
                  __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
                  emit_drop(IPPROTO_ICMP, CT_FAMILY_IPV4, s, d, 0, 0, (__u8)CNT_ICMP_DROP, now); }
                return XDP_DROP;
            }
            count(CNT_IPV4_OTHER);
            return XDP_PASS;
        }
        case IPPROTO_IPV6: {
            /* 6in4 tunnel (RFC 4213, proto 41): only pass packets whose outer
             * source IP is an explicitly configured tunnel endpoint.  Dropping
             * everything else at XDP speed prevents attackers from forging
             * proto-41 packets to exhaust kernel SIT-decapsulation CPU. */
            __be32 sit_key = ip->saddr;
            __u32 *sit_allow = bpf_map_lookup_elem(&sit4_endpoints, &sit_key);
            if (sit_allow && *sit_allow) {
                count(CNT_IPV4_OTHER);
                return XDP_PASS;
            }
            count(CNT_SLOT_DROP);
            { __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
              __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
              emit_drop(IPPROTO_IPV6, CT_FAMILY_IPV4, s, d, 0, 0, (__u8)CNT_SLOT_DROP, now); }
            return XDP_DROP;
        }
        default: {
            __u32 s[4] = { (__u32)ip->saddr, 0, 0, 0 };
            __u32 d[4] = { (__u32)ip->daddr, 0, 0, 0 };
            return dispatch_to_slot(ctx, CT_FAMILY_IPV4, ip->protocol,
                                    l3_off, inner_off, s, d);
        }
        }
    }

    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = l3_data;
        if ((void *)(ipv6 + 1) > data_end)
            return XDP_DROP;

        void *trans_data = (void *)(ipv6 + 1);

        __u8 nexthdr = skip_ipv6_exthdr(&trans_data, data_end, ipv6->nexthdr);
        // 0xFF is our dedicated sentinel for every IPv6 fragment.
        if (nexthdr == IPV6_FRAG_DROP_SENTINEL) {
            count(CNT_FRAG_DROP);
            { __u32 s[4], d[4];
              __builtin_memcpy(s, &ipv6->saddr, 16);
              __builtin_memcpy(d, &ipv6->daddr, 16);
              emit_drop(0, CT_FAMILY_IPV6, s, d, 0, 0, (__u8)CNT_FRAG_DROP, now); }
            return XDP_DROP;
        }
        if (nexthdr == IPV6_EXTHDR_MALFORMED_SENTINEL)
            return XDP_DROP;
        if (nexthdr == IPPROTO_NONE)
            return XDP_PASS;

        bool ndp_control = false;
        if (nexthdr == IPPROTO_ICMPV6 &&
            (void *)((struct icmp6hdr *)trans_data + 1) <= data_end) {
            __u8 icmp6_type = ((struct icmp6hdr *)trans_data)->icmp6_type;
            ndp_control = icmp6_type >= 133 && icmp6_type <= 137;
        }

        /* NDP, including DAD (NS from ::), is link-local control traffic and
         * must be admitted before the public-source bogon policy. */
        if (bogon_filter_active() && !ndp_control && is_bogon_v6(&ipv6->saddr)) {
            count(CNT_BOGON_DROP);
            { __u32 s[4], d[4];
              __builtin_memcpy(s, &ipv6->saddr, 16);
              __builtin_memcpy(d, &ipv6->daddr, 16);
              emit_drop(nexthdr, CT_FAMILY_IPV6, s, d, 0, 0, (__u8)CNT_BOGON_DROP, now); }
            return XDP_DROP;
        }

        __u16 l3_off    = (__u16)((void *)ipv6 - data);
        __u16 inner_off = (__u16)(trans_data - data);

        switch (nexthdr) {
        case IPPROTO_TCP:
            return check_tcp_ipv6(ctx, ipv6, trans_data, data_end, l3_off, inner_off);
        case IPPROTO_UDP:
            return check_udp_ipv6(ctx, ipv6, trans_data, data_end, l3_off, inner_off);
        case IPPROTO_ICMPV6: {
            // NDP (RS/RA/NS/NA/Redirect, types 133-137) must always pass —
            // dropping them breaks IPv6 neighbour discovery and routing.
            // Only echo requests (type 128) go through the shared token bucket.
            struct icmp6hdr *icmp6 = trans_data;
            if ((void *)(icmp6 + 1) > data_end) {
                count(CNT_IPV6_OTHER);
                return XDP_DROP;
            }
            if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST &&
                !is_trusted_v6(&ipv6->saddr) &&
                icmp_rate_limit() == XDP_DROP) {
                count(CNT_ICMP_DROP);
                { __u32 s[4], d[4];
                  __builtin_memcpy(s, &ipv6->saddr, 16);
                  __builtin_memcpy(d, &ipv6->daddr, 16);
                  emit_drop(IPPROTO_ICMPV6, CT_FAMILY_IPV6, s, d, 0, 0, (__u8)CNT_ICMP_DROP, now); }
                return XDP_DROP;
            }
            count(CNT_IPV6_OTHER);
            return XDP_PASS;
        }
        default: {
            __u32 s[4], d[4];
            __builtin_memcpy(s, &ipv6->saddr, 16);
            __builtin_memcpy(d, &ipv6->daddr, 16);
            return dispatch_to_slot(ctx, CT_FAMILY_IPV6, nexthdr,
                                    l3_off, inner_off, s, d);
        }
        }
    }

    count(CNT_NON_IP);
    return XDP_PASS;
}

SEC("xdp")
int xdp_port_whitelist(struct xdp_md *ctx) {
    int verdict = _xdp_fw(ctx);
    __u32 pkt_len = (__u32)((char *)(long)ctx->data_end - (char *)(long)ctx->data);
    count_bytes(verdict == XDP_DROP, pkt_len);
    return verdict;
}

char _license[] SEC("license") = "GPL";
