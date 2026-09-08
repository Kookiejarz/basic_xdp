#pragma once
#include "maps.h"

/*
 * Per-IP handler block check.
 */
static __always_inline void fill_handler_blocked_key_v4(
    struct syn_rate_key_v4 *k, const struct flow_key *ct)
{
    k->addr = (__be32)ct->saddr[0];
}

static __always_inline void fill_handler_blocked_key_v6(
    struct syn_rate_key_v6 *k, const struct flow_key *ct)
{
    __builtin_memcpy(k->addr, ct->saddr, sizeof(k->addr));
}

static __always_inline bool is_handler_blocked(const struct flow_key *ct)
{
    __u64 *until;

    if (ct->family == CT_FAMILY_IPV4) {
        struct syn_rate_key_v4 k;
        fill_handler_blocked_key_v4(&k, ct);
        until = bpf_map_lookup_elem(&hblk4, &k);
    } else {
        struct syn_rate_key_v6 k;
        fill_handler_blocked_key_v6(&k, ct);
        until = bpf_map_lookup_elem(&hblk6, &k);
    }

    return until && bpf_ktime_get_ns() < *until;
}

/*
 * Write parsed context into the per-CPU slot_ctx_map and attempt a
 * bpf_tail_call into tcp_port_handlers[dest_port].
 *
 * The metadata region is NOT adjusted: get_slot_ctx() in handlers will
 * fall back to the percpu map, which is correct for both native and
 * generic/skb XDP mode without the adj_meta / undo dance.
 *
 * If no handler is loaded for dest_port, bpf_tail_call() returns to the
 * caller; the caller then proceeds with its normal admission logic.
 */
static __always_inline void try_tcp_port_dispatch(
    struct xdp_md *ctx,
    const struct flow_key *ct,
    __u16 l3_off, __u16 inner_off,
    __u32 dest_port)
{
    __u32 zero = 0;
    struct xdp_slot_ctx *sc = bpf_map_lookup_elem(&slot_ctx_map, &zero);
    if (sc) {
        sc->family       = ct->family;
        sc->ip_proto     = IPPROTO_TCP;
        sc->l3_offset    = l3_off;
        sc->inner_offset = inner_off;
        sc->sport        = ct->sport;
        sc->dport        = ct->dport;
        sc->_pad         = 0;
        sc->saddr[0] = ct->saddr[0]; sc->saddr[1] = ct->saddr[1];
        sc->saddr[2] = ct->saddr[2]; sc->saddr[3] = ct->saddr[3];
        sc->daddr[0] = ct->daddr[0]; sc->daddr[1] = ct->daddr[1];
        sc->daddr[2] = ct->daddr[2]; sc->daddr[3] = ct->daddr[3];
    }
    count(CNT_SLOT_CALL);
    bpf_tail_call(ctx, &tcp_port_handlers, dest_port);
}

/*
 * Dispatch a protected TCP endpoint by profile identity.  A required profile
 * is part of admission, so every return from bpf_tail_call() is fail-closed.
 */
static __always_inline int dispatch_tcp_profile(
    struct xdp_md *ctx,
    const struct flow_key *ct,
    __u16 l3_off, __u16 inner_off,
    const struct tcp_endpoint_policy *policy)
{
    __u32 zero = 0;
    struct xdp_slot_ctx *sc = bpf_map_lookup_elem(&slot_ctx_map, &zero);
    struct xdp_profile_ctx *pc = bpf_map_lookup_elem(&profile_ctx_map, &zero);

    if (sc && pc) {
        sc->family       = ct->family;
        sc->ip_proto     = IPPROTO_TCP;
        sc->l3_offset    = l3_off;
        sc->inner_offset = inner_off;
        sc->sport        = ct->sport;
        sc->dport        = ct->dport;
        sc->_pad         = 0;
        sc->saddr[0] = ct->saddr[0]; sc->saddr[1] = ct->saddr[1];
        sc->saddr[2] = ct->saddr[2]; sc->saddr[3] = ct->saddr[3];
        sc->daddr[0] = ct->daddr[0]; sc->daddr[1] = ct->daddr[1];
        sc->daddr[2] = ct->daddr[2]; sc->daddr[3] = ct->daddr[3];
        pc->policy_generation = policy->policy_generation;
        pc->profile_generation = policy->profile_generation;
        pc->profile_id = policy->profile_id;
        pc->_pad = 0;

        count(CNT_SLOT_CALL);
        bpf_tail_call(ctx, &tcp_profile_handlers, policy->profile_id);
    }

    count(CNT_PROFILE_UNAVAILABLE_DROP);
    emit_drop(IPPROTO_TCP, ct->family, ct->saddr, ct->daddr,
              ct->sport, ct->dport, (__u8)CNT_PROFILE_UNAVAILABLE_DROP,
              bpf_ktime_get_ns());
    return XDP_DROP;
}

/* Same as try_tcp_port_dispatch but for UDP. */
static __always_inline void try_udp_port_dispatch(
    struct xdp_md *ctx,
    const struct flow_key *ct,
    __u16 l3_off, __u16 inner_off,
    __u32 dest_port)
{
    __u32 zero = 0;
    struct xdp_slot_ctx *sc = bpf_map_lookup_elem(&slot_ctx_map, &zero);
    if (sc) {
        sc->family       = ct->family;
        sc->ip_proto     = IPPROTO_UDP;
        sc->l3_offset    = l3_off;
        sc->inner_offset = inner_off;
        sc->sport        = ct->sport;
        sc->dport        = ct->dport;
        sc->_pad         = 0;
        sc->saddr[0] = ct->saddr[0]; sc->saddr[1] = ct->saddr[1];
        sc->saddr[2] = ct->saddr[2]; sc->saddr[3] = ct->saddr[3];
        sc->daddr[0] = ct->daddr[0]; sc->daddr[1] = ct->daddr[1];
        sc->daddr[2] = ct->daddr[2]; sc->daddr[3] = ct->daddr[3];
    }
    count(CNT_SLOT_CALL);
    bpf_tail_call(ctx, &udp_port_handlers, dest_port);
}
