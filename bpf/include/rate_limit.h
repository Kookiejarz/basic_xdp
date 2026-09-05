#pragma once
#include "maps.h"

static __always_inline __u32 mask_source_word(__u32 word, __u32 prefix_bits)
{
    if (prefix_bits >= 32)
        return word;
    if (prefix_bits == 0)
        return 0;

    __u32 mask = 0xFFFFFFFFU << (32 - prefix_bits);
    return word & bpf_htonl(mask);
}

static __always_inline void fill_masked_source_words(
    __u32 out[4], const __u32 in[4], __u8 family, __u32 prefix_v4, __u32 prefix_v6)
{
    out[0] = 0;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;

    if (family == CT_FAMILY_IPV4) {
        if (prefix_v4 > 32)
            prefix_v4 = 32;
        out[0] = mask_source_word(in[0], prefix_v4);
        return;
    }

    if (prefix_v6 > 128)
        prefix_v6 = 128;

    if (prefix_v6 >= 32) {
        out[0] = in[0];
        prefix_v6 -= 32;
    } else {
        out[0] = mask_source_word(in[0], prefix_v6);
        return;
    }

    if (prefix_v6 >= 32) {
        out[1] = in[1];
        prefix_v6 -= 32;
    } else {
        out[1] = mask_source_word(in[1], prefix_v6);
        return;
    }

    if (prefix_v6 >= 32) {
        out[2] = in[2];
        prefix_v6 -= 32;
    } else {
        out[2] = mask_source_word(in[2], prefix_v6);
        return;
    }

    out[3] = mask_source_word(in[3], prefix_v6);
}

static __always_inline void fill_source_rate_key_v4(
    struct syn_rate_key_v4 *rkey, const struct flow_key *key, __u32 prefix_v4)
{
    if (prefix_v4 > 32)
        prefix_v4 = 32;
    rkey->addr = (__be32)mask_source_word(key->saddr[0], prefix_v4);
}

static __always_inline void fill_source_rate_key_v6(
    struct syn_rate_key_v6 *rkey, const struct flow_key *key, __u32 prefix_v6)
{
    fill_masked_source_words(rkey->addr, key->saddr, CT_FAMILY_IPV6, 0, prefix_v6);
}

static __always_inline void fill_prefix_rate_key_v4(
    struct prefix_rate_key_v4 *rkey, const struct flow_key *key,
    __u32 dest_port, __u32 prefix_v4)
{
    if (prefix_v4 > 32)
        prefix_v4 = 32;
    rkey->addr = (__be32)mask_source_word(key->saddr[0], prefix_v4);
    rkey->dest_port = dest_port;
}

static __always_inline void fill_prefix_rate_key_v6(
    struct prefix_rate_key_v6 *rkey, const struct flow_key *key,
    __u32 dest_port, __u32 prefix_v6)
{
    fill_masked_source_words(rkey->addr, key->saddr, CT_FAMILY_IPV6, 0, prefix_v6);
    rkey->dest_port = dest_port;
}

/* Rate-map values are shared across CPUs.  Pack the window timestamp and the
 * count into one 64-bit state word so rollover and increment happen in one
 * cmpxchg.  This avoids the otherwise unavoidable race between resetting one
 * field and incrementing the other.  A 1 ms tick keeps normal rate windows
 * precise; clamping below half the 32-bit range keeps wraparound comparisons
 * unambiguous (about 24.8 days maximum).
 */
#define RATE_STATE_COUNT_MASK 0xFFFFFFFFULL
#define RATE_STATE_TICK_NS 1000000ULL
#define RATE_STATE_RETRIES 16

static __always_inline __u32 rate_state_tick(__u64 now)
{
    return (__u32)(now / RATE_STATE_TICK_NS);
}

static __always_inline __u32 rate_state_window_ticks(__u64 window_ns)
{
    __u64 ticks = window_ns / RATE_STATE_TICK_NS;
    if (window_ns % RATE_STATE_TICK_NS)
        ticks++;
    if (ticks == 0)
        return 1;
    if (ticks > 0x7FFFFFFFULL)
        return 0x7FFFFFFFU;
    return (__u32)ticks;
}

static __always_inline __u64 rate_state_pack(__u32 tick, __u32 count_value)
{
    return ((__u64)tick << 32) | (__u64)count_value;
}

#define WINDOW_RATE_CHECK(map, rkey, val_type, now, window_ns, increment, max)       \
    do {                                                                              \
        __u64 _inc64 = (__u64)(increment);                                            \
        __u64 _limit64 = (__u64)(max);                                                \
        if (_inc64 > _limit64 || _inc64 > 0xFFFFFFFFULL)                             \
            return XDP_DROP;                                                         \
        __u32 _inc = (__u32)_inc64;                                                   \
        __u32 _limit = (__u32)_limit64;                                               \
        __u32 _now_tick = rate_state_tick(now);                                       \
        __u32 _window_ticks = rate_state_window_ticks(window_ns);                     \
        for (int _attempt = 0; _attempt < RATE_STATE_RETRIES; _attempt++) {           \
            val_type *_rv = bpf_map_lookup_elem((map), &(rkey));                     \
            if (!_rv) {                                                               \
                val_type _new = { .state = rate_state_pack(_now_tick, _inc) };         \
                if (bpf_map_update_elem((map), &(rkey), &_new, BPF_NOEXIST) == 0)    \
                    return XDP_PASS;                                                  \
                continue;                                                             \
            }                                                                         \
            __u64 _current = __sync_fetch_and_add(&_rv->state, 0);                    \
            __u32 _start_tick = (__u32)(_current >> 32);                              \
            __u32 _old_count = (__u32)(_current & RATE_STATE_COUNT_MASK);             \
            __u32 _next_tick = _now_tick;                                            \
            __u32 _next_count;                                                       \
            if ((__u32)(_now_tick - _start_tick) >= _window_ticks) {                 \
                _next_count = _inc;                                                   \
            } else {                                                                  \
                if (_old_count > _limit || _inc > _limit - _old_count)               \
                    return XDP_DROP;                                                  \
                _next_count = _old_count + _inc;                                      \
                _next_tick = _start_tick;                                             \
            }                                                                         \
            __u64 _next = rate_state_pack(_next_tick, _next_count);                   \
            if (__sync_val_compare_and_swap(&_rv->state, _current, _next) == _current) \
                return XDP_PASS;                                                      \
        }                                                                             \
        return XDP_DROP;                                                              \
    } while (0)

static __always_inline int syn_rate_check(struct flow_key *key, __u64 now,
                                          __u32 dest_port, __u32 rate_max,
                                          __u32 prefix_v4, __u32 prefix_v6,
                                          struct xdp_runtime_cfg *cfg)
{
    if (rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = cfg_rate_window_ns(cfg);

    if (key->family == CT_FAMILY_IPV4) {
        void *inner = bpf_map_lookup_elem(&syn4, &dest_port);
        if (!inner)
            return XDP_PASS; /* no per-port map yet: pass, syncer will create it */
        struct syn_rate_key_v4 rkey;
        fill_source_rate_key_v4(&rkey, key, prefix_v4);
        WINDOW_RATE_CHECK(inner, rkey, struct syn_rate_val, now, window_ns, 1U, rate_max);
    }

    {
        void *inner = bpf_map_lookup_elem(&syn6, &dest_port);
        if (!inner)
            return XDP_PASS;
        struct syn_rate_key_v6 rkey;
        fill_source_rate_key_v6(&rkey, key, prefix_v6);
        WINDOW_RATE_CHECK(inner, rkey, struct syn_rate_val, now, window_ns, 1U, rate_max);
    }
}

static __always_inline int syn_agg_rate_check(struct flow_key *key, __u64 now,
                                              __u32 dest_port, __u32 rate_max,
                                              __u32 prefix_v4, __u32 prefix_v6,
                                              struct xdp_runtime_cfg *cfg)
{
    if (rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = cfg_rate_window_ns(cfg);

    if (key->family == CT_FAMILY_IPV4) {
        struct prefix_rate_key_v4 rkey;
        fill_prefix_rate_key_v4(&rkey, key, dest_port, prefix_v4);
        WINDOW_RATE_CHECK(&synag4, rkey, struct prefix_rate_val, now, window_ns, 1ULL, rate_max);
    }

    struct prefix_rate_key_v6 rkey;
    fill_prefix_rate_key_v6(&rkey, key, dest_port, prefix_v6);
    WINDOW_RATE_CHECK(&synag6, rkey, struct prefix_rate_val, now, window_ns, 1ULL, rate_max);
}

static __always_inline int udp_rate_check(struct flow_key *key, __u64 now,
                                          __u32 dest_port, __u32 rate_max,
                                          __u32 prefix_v4, __u32 prefix_v6,
                                          struct xdp_runtime_cfg *cfg)
{
    if (rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = cfg_rate_window_ns(cfg);

    if (key->family == CT_FAMILY_IPV4) {
        void *inner = bpf_map_lookup_elem(&udprt4, &dest_port);
        if (!inner)
            return XDP_PASS; /* no per-port map yet: pass, syncer will create it */
        struct syn_rate_key_v4 rkey;
        fill_source_rate_key_v4(&rkey, key, prefix_v4);
        WINDOW_RATE_CHECK(inner, rkey, struct syn_rate_val, now, window_ns, 1U, rate_max);
    }

    {
        void *inner = bpf_map_lookup_elem(&udprt6, &dest_port);
        if (!inner)
            return XDP_PASS;
        struct syn_rate_key_v6 rkey;
        fill_source_rate_key_v6(&rkey, key, prefix_v6);
        WINDOW_RATE_CHECK(inner, rkey, struct syn_rate_val, now, window_ns, 1U, rate_max);
    }
}

static __always_inline int udp_agg_rate_check(struct flow_key *key, __u64 now,
                                              __u32 dest_port, __u64 pkt_bytes,
                                              __u32 rate_max,
                                              __u32 prefix_v4, __u32 prefix_v6,
                                              struct xdp_runtime_cfg *cfg)
{
    if (rate_max == 0)
        return XDP_PASS;

    __u64 window_ns = cfg_rate_window_ns(cfg);

    if (key->family == CT_FAMILY_IPV4) {
        struct prefix_rate_key_v4 rkey;
        fill_prefix_rate_key_v4(&rkey, key, dest_port, prefix_v4);
        WINDOW_RATE_CHECK(&udpag4, rkey, struct prefix_rate_val, now, window_ns, pkt_bytes, (__u64)rate_max);
    }

    struct prefix_rate_key_v6 rkey;
    fill_prefix_rate_key_v6(&rkey, key, dest_port, prefix_v6);
    WINDOW_RATE_CHECK(&udpag6, rkey, struct prefix_rate_val, now, window_ns, pkt_bytes, (__u64)rate_max);
    return XDP_PASS;
}

static __always_inline int precheck_new_tcp_syn(struct flow_key *key, __u32 dest_port,
                                                bool bypass_rate, __u64 now,
                                                struct xdp_runtime_cfg *cfg)
{
    struct tcp_port_policy_cfg *policy = bpf_map_lookup_elem(&tcp_port_policies, &dest_port);
    __u32 syn_rate_max = policy ? policy->syn_rate_max : 0;
    __u32 syn_agg_rate_max = policy ? policy->syn_agg_rate_max : 0;
    __u32 source_prefix_v4 = policy ? policy->source_prefix_v4 : 32;
    __u32 source_prefix_v6 = policy ? policy->source_prefix_v6 : 128;

    if (!bypass_rate) {
        if (syn_rate_check(key, now, dest_port, syn_rate_max, source_prefix_v4, source_prefix_v6, cfg) == XDP_DROP) {
            count(CNT_SYN_RATE_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_SYN_RATE_DROP, now);
            return XDP_DROP;
        }

        if (syn_agg_rate_check(key, now, dest_port, syn_agg_rate_max, source_prefix_v4, source_prefix_v6, cfg) == XDP_DROP) {
            count(CNT_SYN_AGG_RATE_DROP);
            count(CNT_TCP_DROP);
            emit_drop(IPPROTO_TCP, key->family, key->saddr, key->daddr,
                      key->sport, key->dport, (__u8)CNT_SYN_AGG_RATE_DROP, now);
            return XDP_DROP;
        }
    }

    return XDP_PASS;
}

// Two-level global UDP rate limiter with blocked_until_ns fast path.
//
// Problem with the naive PERCPU_ARRAY approach: each CPU independently enforces
// byte_rate_max, so the effective global limit is byte_rate_max × N_CPUs.
//
// This design separates accumulation (per-CPU, lock-free) from enforcement
// (single shared state, spinlock-protected):
//
//   Fast path (per packet, no lock):
//     If local->blocked_until_ns is set and unexpired, drop immediately and
//     clear local_bytes to prevent a burst on unblock.
//     Otherwise accumulate pkt_bytes; pass if batch threshold not yet reached.
//
//   Slow path (every UDP_GLOBAL_BATCH_BYTES per CPU, one spinlock acquisition):
//     Check g->blocked_until_ns (under lock): if the global block is active,
//     save the deadline, propagate it to local->blocked_until_ns, and drop.
//     If the block just expired, reset the sliding-window state for a clean
//     slate.  Otherwise run the two-bucket sliding window; if the rate is
//     exceeded, set g->blocked_until_ns = now + window_ns and drop.
//
// Overshoot at any instant is bounded by N_CPUs × UDP_GLOBAL_BATCH_BYTES.
// For 32 CPUs and a 64 KiB batch that is 2 MiB — acceptable for a DDoS limiter.
// Lock contention is proportional to (global_rate / BATCH) × N_CPUs, not per packet.
//
// Avoids integer division using scaled comparisons:
//   prev*(W-elapsed) + curr*W  vs  byte_rate_max*W

#define UDP_GLOBAL_BATCH_BYTES (65536ULL)

// Per-CPU fast path of the global UDP block: returns XDP_DROP while a block
// verdict is active, clearing it once expired. Shared by the early pre-checks
// in the UDP handlers and by udp_global_rate_check().
static __always_inline int udp_global_block_fast_path(struct udp_percpu_local *local,
                                                      __u64 now)
{
    if (local->blocked_until_ns != 0) {
        if (now < local->blocked_until_ns) {
            local->local_bytes = 0;
            return XDP_DROP;
        }
        local->blocked_until_ns = 0;
    }
    return XDP_PASS;
}

static __always_inline int udp_global_rate_check(__u64 now, __u64 pkt_bytes,
                                                 struct xdp_runtime_cfg *cfg)
{
    __u32 key = 0;

    struct udp_global_state *g = bpf_map_lookup_elem(&udp_global_rl, &key);
    if (!g || g->byte_rate_max == 0)
        return XDP_PASS;

    struct udp_percpu_local *local = bpf_map_lookup_elem(&udp_percpu_acc, &key);
    if (!local)
        return XDP_PASS;

    // Per-CPU fast path: check block verdict without any spinlock.
    if (udp_global_block_fast_path(local, now) == XDP_DROP)
        return XDP_DROP;

    local->local_bytes += pkt_bytes;
    if (local->local_bytes < UDP_GLOBAL_BATCH_BYTES)
        return XDP_PASS;

    __u64 to_flush = local->local_bytes;
    local->local_bytes = 0;

    __u64 window_ns = cfg_udp_global_window_ns(cfg);
    __u64 block_until = 0;
    int ret = XDP_PASS;

    bpf_spin_lock(&g->lock);

    if (g->blocked_until_ns != 0) {
        if (now < g->blocked_until_ns) {
            // Global block still active: save deadline for propagation after unlock.
            block_until = g->blocked_until_ns;
        } else {
            // Block expired: reset sliding-window state for a clean slate.
            g->blocked_until_ns = 0;
            g->window_start_ns = 0;
            g->prev_bytes = 0;
            g->curr_bytes = 0;
        }
    }

    if (block_until == 0) {
        if (g->window_start_ns == 0) {
            g->window_start_ns = now;
            g->prev_bytes = 0;
            g->curr_bytes = to_flush;
        } else {
            __u64 elapsed = now - g->window_start_ns;

            if (elapsed >= 2 * window_ns) {
                g->window_start_ns = now;
                g->prev_bytes = 0;
                g->curr_bytes = to_flush;
            } else {
                if (elapsed >= window_ns) {
                    g->prev_bytes = g->curr_bytes;
                    g->curr_bytes = 0;
                    g->window_start_ns += window_ns;
                    elapsed -= window_ns;
                }
                __u64 weighted = g->prev_bytes * (window_ns - elapsed)
                               + g->curr_bytes * window_ns;
                __u64 threshold = (__u64)g->byte_rate_max * window_ns;
                if (weighted + to_flush * window_ns > threshold) {
                    block_until = now + window_ns;
                    g->blocked_until_ns = block_until;
                    ret = XDP_DROP;
                } else {
                    g->curr_bytes += to_flush;
                }
            }
        }
    }

    bpf_spin_unlock(&g->lock);

    if (block_until != 0) {
        local->blocked_until_ns = block_until;
        ret = XDP_DROP;
    }

    return ret;
}
