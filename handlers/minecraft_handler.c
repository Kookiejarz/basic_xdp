// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/types.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_slot_ctx.h"
#include "map_sizes.h"

#define CT_FAMILY_IPV4 2
#define CT_FAMILY_IPV6 10

#define MC_TIMEOUT_NS (15ULL * 1000000000ULL)
#define MC_BLOCK_NS   (300ULL * 1000000000ULL)
#define MC_MAX_OUT_OF_ORDER 4
#define MC_FLOW_MAX RATE_MAP_MAX_ENTRIES_V4

#define MC_STATUS_RATE_WINDOW_NS (10ULL * 1000000000ULL)
#define MC_STATUS_RATE_MAX       30   /* ~3/sec per /24 or /64 */

#define MC_LOGIN_RATE_WINDOW_NS  (60ULL * 1000000000ULL)
#define MC_LOGIN_RATE_MAX        20   /* per minute per /24 or /64 */

#define MC_AWAIT_ACK            1
#define MC_AWAIT_HANDSHAKE      2
#define MC_AWAIT_STATUS_REQUEST 3
#define MC_AWAIT_LOGIN          4
#define MC_AWAIT_PING           5
#define MC_PING_COMPLETE        6
#define MC_DIRECT_STATUS        7
#define MC_DIRECT_LOGIN         8
#define MC_LEGACY_PING          9

#define MC_MAX_PACKET_ID_BYTES 5
#define MC_MAX_PACKET_LEN_BYTES 3
#define MC_HANDSHAKE_HOST_MAX (255 * 3)
#define MC_LOGIN_NAME_MAX (16 * 3)
#define MC_LOGIN_KEY_MAX 512
#define MC_LOGIN_SIGNATURE_MAX 4096

struct flow_key {
    __u8  family;
    __u8  pad[3];
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
} __attribute__((aligned(8)));

struct syn_rate_key_v4 {
    __be32 addr;
};

struct syn_rate_key_v6 {
    __u32 addr[4];
};

struct mc_rate_key_v4 {
    __be32 prefix;
};

struct mc_rate_key_v6 {
    __u32 prefix[2];
};

struct mc_rate_val {
    __u64 state; /* upper 32 bits: window tick; lower 32 bits: count */
};

struct mc_pending_val {
    __u64 last_seen_ns;
    __u32 expected_seq;
    __s32 protocol_version;
    __u16 state;
    __u16 fails;
};

struct mc_varint {
    __s32 value;
    __u32 bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct flow_key);
    __type(value, struct mc_pending_val);
} pending_mc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MC_FLOW_MAX);
    __type(key, struct flow_key);
    __type(value, __u64);
    /* Ingress packets alone establish and refresh this state. Return-path
     * visibility is deliberately unnecessary for asymmetric deployments. */
} verified_mc SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct syn_rate_key_v4);
    __type(value, __u64);
} hblk4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct syn_rate_key_v6);
    __type(value, __u64);
} hblk6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct mc_rate_key_v4);
    __type(value, struct mc_rate_val);
} mc_status_rate4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct mc_rate_key_v6);
    __type(value, struct mc_rate_val);
} mc_status_rate6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V4);
    __type(key, struct mc_rate_key_v4);
    __type(value, struct mc_rate_val);
} mc_login_rate4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, RATE_MAP_MAX_ENTRIES_V6);
    __type(key, struct mc_rate_key_v6);
    __type(value, struct mc_rate_val);
} mc_login_rate6 SEC(".maps");

static __always_inline void fill_flow_key(struct flow_key *key, const struct xdp_slot_ctx *sc)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = sc->family;
    key->sport = sc->sport;
    key->dport = sc->dport;
    __builtin_memcpy(key->saddr, sc->saddr, sizeof(key->saddr));
    __builtin_memcpy(key->daddr, sc->daddr, sizeof(key->daddr));
}

static __always_inline void fill_block_key_v4(struct syn_rate_key_v4 *key, const struct flow_key *ct)
{
    key->addr = (__be32)ct->saddr[0];
}

static __always_inline void fill_block_key_v6(struct syn_rate_key_v6 *key, const struct flow_key *ct)
{
    __builtin_memcpy(key->addr, ct->saddr, sizeof(key->addr));
}

static __always_inline void fill_rate_key_v4(struct mc_rate_key_v4 *key, const struct flow_key *ct)
{
    key->prefix = (__be32)ct->saddr[0] & bpf_htonl(0xFFFFFF00u);
}

static __always_inline void fill_rate_key_v6(struct mc_rate_key_v6 *key, const struct flow_key *ct)
{
    key->prefix[0] = ct->saddr[0];
    key->prefix[1] = ct->saddr[1];
}

#define MC_RATE_TICK_NS 1000000ULL
#define MC_RATE_RETRIES 64

#define MC_RATE_CHECK(map, key, now, window_ns, max_count, over_limit)               \
    do {                                                                             \
        (over_limit) = true;                                                         \
        __u32 _now_tick = (__u32)((now) / MC_RATE_TICK_NS);                         \
        __u64 _ticks64 = (window_ns) / MC_RATE_TICK_NS;                            \
        if ((window_ns) % MC_RATE_TICK_NS)                                          \
            _ticks64++;                                                             \
        __u32 _window_ticks = _ticks64 > 0x7FFFFFFFULL ? 0x7FFFFFFFU                \
                                                       : (__u32)_ticks64;            \
        if (_window_ticks == 0)                                                      \
            _window_ticks = 1;                                                      \
        for (int _attempt = 0; _attempt < MC_RATE_RETRIES; _attempt++) {             \
            struct mc_rate_val *_v = bpf_map_lookup_elem((map), (key));             \
            if (!_v) {                                                               \
                struct mc_rate_val _init = {                                         \
                    .state = ((__u64)_now_tick << 32) | 1ULL,                        \
                };                                                                   \
                if (bpf_map_update_elem((map), (key), &_init, BPF_NOEXIST) == 0) {  \
                    (over_limit) = false;                                            \
                    break;                                                           \
                }                                                                    \
                continue;                                                            \
            }                                                                        \
            __u64 _current = __sync_fetch_and_add(&_v->state, 0);                   \
            __u32 _start_tick = (__u32)(_current >> 32);                            \
            __u32 _count = (__u32)_current;                                          \
            __u32 _next_tick = _now_tick;                                            \
            __u32 _next_count;                                                       \
            if ((__u32)(_now_tick - _start_tick) >= _window_ticks) {                \
                _next_count = 1;                                                     \
            } else {                                                                 \
                if (_count >= (__u32)(max_count))                                    \
                    break;                                                           \
                _next_count = _count + 1;                                            \
                _next_tick = _start_tick;                                            \
            }                                                                        \
            __u64 _next = ((__u64)_next_tick << 32) | _next_count;                  \
            if (__sync_val_compare_and_swap(&_v->state, _current, _next) == _current) { \
                (over_limit) = false;                                                \
                break;                                                               \
            }                                                                        \
        }                                                                            \
    } while (0)

static __always_inline bool mc_handshake_rate_exceeded(
    const struct flow_key *ct, __u64 now,
    void *rate4, void *rate6, __u64 window_ns, __u32 max_count)
{
    bool over_limit;

    if (ct->family == CT_FAMILY_IPV4) {
        struct mc_rate_key_v4 rkey;

        fill_rate_key_v4(&rkey, ct);
        MC_RATE_CHECK(rate4, &rkey, now, window_ns, max_count, over_limit);
    } else {
        struct mc_rate_key_v6 rkey;

        fill_rate_key_v6(&rkey, ct);
        MC_RATE_CHECK(rate6, &rkey, now, window_ns, max_count, over_limit);
    }

    return over_limit;
}

static __always_inline void cleanup_pending(const struct flow_key *ct)
{
    bpf_map_delete_elem(&pending_mc, ct);
}

static __always_inline int restore_and_return(struct xdp_md *ctx, __u16 inner_off, int action)
{
    if (inner_off && action != XDP_DROP && bpf_xdp_adjust_head(ctx, -(int)inner_off))
        return XDP_DROP;
    return action;
}

static __always_inline int drop_with_cleanup(struct xdp_md *ctx, __u16 inner_off, const struct flow_key *ct)
{
    cleanup_pending(ct);
    return restore_and_return(ctx, inner_off, XDP_DROP);
}

static __always_inline int penalize_and_drop(
    struct xdp_md *ctx, __u16 inner_off, const struct flow_key *ct, __u64 now)
{
    __u64 blocked_until = now + MC_BLOCK_NS;
    if (ct->family == CT_FAMILY_IPV4) {
        struct syn_rate_key_v4 blocked_key;
        fill_block_key_v4(&blocked_key, ct);
        bpf_map_update_elem(&hblk4, &blocked_key, &blocked_until, BPF_ANY);
    } else {
        struct syn_rate_key_v6 blocked_key;
        fill_block_key_v6(&blocked_key, ct);
        bpf_map_update_elem(&hblk6, &blocked_key, &blocked_until, BPF_ANY);
    }
    cleanup_pending(ct);
    return restore_and_return(ctx, inner_off, XDP_DROP);
}

static __always_inline int reject_payload(
    struct xdp_md *ctx, __u16 inner_off, const struct flow_key *ct,
    struct mc_pending_val *pending, __u64 now)
{
    if (pending->fails < 0xFFFF)
        pending->fails++;
    pending->last_seen_ns = now;
    if (pending->fails >= MC_MAX_OUT_OF_ORDER)
        return penalize_and_drop(ctx, inner_off, ct, now);
    return restore_and_return(ctx, inner_off, XDP_DROP);
}

static __always_inline int verify_and_pass(
    struct xdp_md *ctx, __u16 inner_off, const struct flow_key *ct, __u64 now)
{
    bpf_map_update_elem(&verified_mc, ct, &now, BPF_ANY);
    cleanup_pending(ct);
    return restore_and_return(ctx, inner_off, XDP_PASS);
}

static __always_inline struct mc_varint mc_varint_fail(void)
{
    struct mc_varint v = { .value = 0, .bytes = 0 };
    return v;
}

#define MC_VARINT_BYTE(ptr, pend, dend, max, idx, shift, result)              \
    do {                                                                      \
        if ((max) < (idx))                                                    \
            goto mc_varint_error;                                            \
        if ((const void *)(ptr) >= (const void *)(dend))                     \
            goto mc_varint_error;                                            \
        barrier_var(ptr);                                                     \
        if ((const void *)(ptr) >= (const void *)(pend))                     \
            goto mc_varint_error;                                            \
        barrier_var(ptr);                                                     \
        __u8 _b = *(ptr)++;                                                   \
        (result) |= ((__s32)(_b & 0x7F) << (shift));                         \
        if (!(_b & 0x80))                                                     \
            return (struct mc_varint){ .value = (result), .bytes = (idx) };  \
    } while (0)

static __always_inline struct mc_varint read_varint(
    __u8 *ptr, const __u8 *end, __u8 max_bytes, const void *data_end)
{
    __s32 result = 0;

    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 1, 0, result);
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 2, 7, result);
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 3, 14, result);
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 4, 21, result);
    MC_VARINT_BYTE(ptr, end, data_end, max_bytes, 5, 28, result);

mc_varint_error:
    return mc_varint_fail();
}

static __always_inline bool read_byte(__u8 **ptr, const __u8 *end, const void *data_end, __u8 *out)
{
    __u8 *p = *ptr;

    if ((const void *)p >= data_end)
        return false;
    barrier_var(p);
    if (p >= end)
        return false;
    barrier_var(p);
    *out = *p;
    *ptr = p + 1;
    return true;
}

static __always_inline bool consume_bytes(__u8 **ptr, const __u8 *end, __u32 n, const void *data_end)
{
    __u8 *p = *ptr;

    n &= 0x1FFF;
    barrier_var(n);
    if ((const void *)(p + n) > data_end)
        return false;
    barrier_var(p);
    if (p + n > end)
        return false;
    barrier_var(p);
    *ptr = p + n;
    return true;
}

static __always_inline bool inspect_status_request(__u8 *start, const __u8 *end, const void *data_end)
{
    struct mc_varint v;

    v = read_varint(start, end, 1, data_end);
    if (!v.bytes || v.value != 1)
        return false;
    start += v.bytes;

    v = read_varint(start, end, 1, data_end);
    if (!v.bytes || v.value != 0)
        return false;
    start += v.bytes;

    return start == end;
}

static __always_inline bool inspect_ping_request(__u8 *start, const __u8 *end, const void *data_end)
{
    struct mc_varint v;

    v = read_varint(start, end, 1, data_end);
    if (!v.bytes || v.value != 9)
        return false;
    start += v.bytes;

    v = read_varint(start, end, 1, data_end);
    if (!v.bytes || v.value != 1)
        return false;
    start += v.bytes;

    if (!consume_bytes(&start, end, 8, data_end))
        return false;

    return start == end;
}

static __always_inline bool inspect_login_packet(
    __u8 *start, const __u8 *end, __s32 protocol_version, const void *data_end)
{
    struct mc_varint v;
    const __u8 *packet_end;
    __u32 packet_len;

    v = read_varint(start, end, MC_MAX_PACKET_LEN_BYTES, data_end);
    if (!v.bytes || v.value < 2 || v.value > (MC_MAX_PACKET_ID_BYTES + MC_LOGIN_NAME_MAX + 4096))
        return false;
    start += v.bytes;
    packet_len = (__u32)v.value;
    barrier_var(packet_len);
    packet_end = start + packet_len;
    if ((const void *)packet_end > data_end || packet_end != end)
        return false;

    v = read_varint(start, packet_end, 1, data_end);
    if (!v.bytes || v.value != 0)
        return false;
    start += v.bytes;

    v = read_varint(start, packet_end, MC_MAX_PACKET_ID_BYTES, data_end);
    if (!v.bytes || v.value < 1 || v.value > MC_LOGIN_NAME_MAX)
        return false;
    start += v.bytes;
    {
        __u32 name_len = (__u32)v.value;

        /* Logically redundant with the v.value check above, but the verifier
         * needs an explicit bound on this register before the variable-length
         * consume_bytes(); barrier_var keeps clang from optimizing it away. */
        if (name_len > MC_LOGIN_NAME_MAX)
            return false;
        barrier_var(name_len);
        if (!consume_bytes(&start, packet_end, name_len, data_end))
            return false;
    }

    if (protocol_version >= 759 && protocol_version < 761) {
        __u8 has_public_key;

        if (!read_byte(&start, packet_end, data_end, &has_public_key))
            return false;
        if (has_public_key) {
            if (!consume_bytes(&start, packet_end, 8, data_end))
                return false;

            v = read_varint(start, packet_end, MC_MAX_PACKET_ID_BYTES, data_end);
            if (!v.bytes || v.value < 0 || v.value > MC_LOGIN_KEY_MAX)
                return false;
            start += v.bytes;
            if (!consume_bytes(&start, packet_end, (__u32)v.value, data_end))
                return false;

            v = read_varint(start, packet_end, MC_MAX_PACKET_ID_BYTES, data_end);
            if (!v.bytes || v.value < 0 || v.value > MC_LOGIN_SIGNATURE_MAX)
                return false;
            start += v.bytes;
            if (!consume_bytes(&start, packet_end, (__u32)v.value, data_end))
                return false;
        }
    }

    if (protocol_version >= 760) {
        if (protocol_version >= 764) {
            if (!consume_bytes(&start, packet_end, 16, data_end))
                return false;
        } else {
            __u8 has_uuid;

            if (!read_byte(&start, packet_end, data_end, &has_uuid))
                return false;
            if (has_uuid && !consume_bytes(&start, packet_end, 16, data_end))
                return false;
        }
    }

    return start == packet_end;
}

static __always_inline __s32 inspect_handshake(
    __u8 *start, const __u8 *end, __s32 *protocol_version, __u8 **next_ptr, const void *data_end)
{
    struct mc_varint v;
    const __u8 *packet_end;
    __u32 packet_len;
    __s32 intention;
    __u8 support_transfer;

    if (start + 1 > end)
        return 0;
    if (start[0] == 0xFE)
        return MC_LEGACY_PING;

    v = read_varint(start, end, MC_MAX_PACKET_LEN_BYTES, data_end);
    if (!v.bytes || v.value < 4 || v.value > (MC_MAX_PACKET_ID_BYTES + MC_HANDSHAKE_HOST_MAX + 16))
        return 0;
    start += v.bytes;
    packet_len = (__u32)v.value;
    barrier_var(packet_len);
    packet_end = start + packet_len;
    if ((const void *)packet_end > data_end || packet_end > end)
        return 0;

    v = read_varint(start, packet_end, 1, data_end);
    if (!v.bytes || v.value != 0)
        return 0;
    start += v.bytes;

    v = read_varint(start, packet_end, MC_MAX_PACKET_ID_BYTES, data_end);
    if (!v.bytes)
        return 0;
    *protocol_version = v.value;
    start += v.bytes;

    v = read_varint(start, packet_end, MC_MAX_PACKET_ID_BYTES, data_end);
    if (!v.bytes || v.value < 0 || v.value > MC_HANDSHAKE_HOST_MAX)
        return 0;
    start += v.bytes;
    if (!consume_bytes(&start, packet_end, (__u32)v.value, data_end))
        return 0;

    if (!consume_bytes(&start, packet_end, 2, data_end))
        return 0;

    v = read_varint(start, packet_end, 1, data_end);
    if (!v.bytes)
        return 0;
    intention = v.value;
    support_transfer = *protocol_version >= 766;

    if (!(intention == 1 || intention == 2 || (support_transfer && intention == 3)))
        return 0;
    start += v.bytes;
    if (start != packet_end)
        return 0;

    if (packet_end == end)
        return intention == 1 ? MC_AWAIT_STATUS_REQUEST : MC_AWAIT_LOGIN;

    *next_ptr = (__u8 *)packet_end;
    return intention == 1 ? MC_DIRECT_STATUS : MC_DIRECT_LOGIN;
}

SEC("xdp/minecraft")
int xdp_minecraft_handler(struct xdp_md *ctx)
{
    struct xdp_slot_ctx *sc = get_slot_ctx(ctx);
    struct flow_key key;
    struct tcphdr *tcp;
    struct mc_pending_val *pending;
    void *data;
    void *data_end;
    __u16 inner_off;
    __u8 family;
    __u64 now;
    __u8 *payload;
    const __u8 *payload_end;
    __u32 payload_len;
    __u32 tcp_hdr_len;
    __u32 l4_and_payload_len;
    __u32 l3_off;
    __u32 inner_off_u32;

    if (!sc || sc->ip_proto != IPPROTO_TCP)
        return XDP_PASS;

    l3_off = (__u32)sc->l3_offset;
    inner_off_u32 = (__u32)sc->inner_offset;
    if (l3_off > 255 || inner_off_u32 > 255)
        return XDP_DROP;

    inner_off = (__u16)inner_off_u32;
    family = sc->family;
    fill_flow_key(&key, sc);

    if (family != CT_FAMILY_IPV4 && family != CT_FAMILY_IPV6)
        return XDP_PASS;
    if (family == CT_FAMILY_IPV4 && inner_off_u32 < l3_off + 20u)
        return XDP_PASS;
    if (family == CT_FAMILY_IPV6 && inner_off_u32 < l3_off + 40u)
        return XDP_PASS;

    /* Compute actual L4+payload length from the IP header *before* adjust_head.
     * data_end points to the physical Ethernet frame end, which may include
     * padding bytes added to meet the 64-byte minimum frame size.  Using
     * data_end directly would inflate payload_len and corrupt expected_seq. */
    {
        void *pre_data = (void *)(long)ctx->data;
        void *pre_data_end = (void *)(long)ctx->data_end;
        if (family == CT_FAMILY_IPV4) {
            struct iphdr *iph = (struct iphdr *)((char *)pre_data + l3_off);
            if ((void *)(iph + 1) > pre_data_end)
                return XDP_PASS;
            __u32 ip_tot    = (__u32)bpf_ntohs(iph->tot_len);
            __u32 ip_l4_off = inner_off_u32 - l3_off;
            l4_and_payload_len = ip_tot > ip_l4_off ? ip_tot - ip_l4_off : 0;
        } else {
            struct ipv6hdr *ip6h = (struct ipv6hdr *)((char *)pre_data + l3_off);
            if ((void *)(ip6h + 1) > pre_data_end)
                return XDP_PASS;
            __u32 ip6_hdr_and_ext = inner_off_u32 - l3_off;
            if (ip6_hdr_and_ext < 40u)
                return XDP_PASS;
            __u32 ip6_plen = (__u32)bpf_ntohs(ip6h->payload_len);
            __u32 ip6_ext  = ip6_hdr_and_ext - 40u;
            l4_and_payload_len = ip6_plen > ip6_ext ? ip6_plen - ip6_ext : 0;
        }
    }

    if (bpf_xdp_adjust_head(ctx, (int)inner_off))
        return XDP_PASS;

    data = (void *)(long)ctx->data;
    data_end = (void *)(long)ctx->data_end;
    tcp = data;

    if ((void *)(tcp + 1) > data_end)
        return restore_and_return(ctx, inner_off, XDP_DROP);
    if (tcp->doff < 5)
        return restore_and_return(ctx, inner_off, XDP_DROP);

    tcp_hdr_len = (__u32)tcp->doff * 4;
    if ((void *)tcp + tcp_hdr_len > data_end)
        return restore_and_return(ctx, inner_off, XDP_DROP);

    now = bpf_ktime_get_ns();

    if (tcp->syn && !tcp->ack) {
        struct mc_pending_val new_pending = {
            .last_seen_ns = now,
            .expected_seq = bpf_ntohl(tcp->seq) + 1,
            .protocol_version = 0,
            .state = MC_AWAIT_ACK,
            .fails = 0,
        };

        bpf_map_delete_elem(&verified_mc, &key);
        bpf_map_update_elem(&pending_mc, &key, &new_pending, BPF_ANY);
        return restore_and_return(ctx, inner_off, XDP_PASS);
    }

    {
        __u64 *verified_at = bpf_map_lookup_elem(&verified_mc, &key);

        if (verified_at) {
            if (tcp->fin || tcp->rst)
                bpf_map_delete_elem(&verified_mc, &key);
            else
                *verified_at = now;
            return restore_and_return(ctx, inner_off, XDP_PASS);
        }
    }

    pending = bpf_map_lookup_elem(&pending_mc, &key);
    if (!pending)
        return restore_and_return(ctx, inner_off, XDP_DROP);

    if (now - pending->last_seen_ns > MC_TIMEOUT_NS)
        return drop_with_cleanup(ctx, inner_off, &key);

    payload = (__u8 *)tcp + tcp_hdr_len;
    if (l4_and_payload_len < tcp_hdr_len)
        return restore_and_return(ctx, inner_off, XDP_DROP);
    payload_len = l4_and_payload_len - tcp_hdr_len;
    payload_end = payload + payload_len;
    if ((void *)payload_end > data_end)
        return restore_and_return(ctx, inner_off, XDP_DROP);

    if (pending->state == MC_AWAIT_ACK) {
        if (!tcp->ack || pending->expected_seq != bpf_ntohl(tcp->seq)) {
            pending->last_seen_ns = now;
            return restore_and_return(ctx, inner_off, XDP_DROP);
        }

        pending->state = MC_AWAIT_HANDSHAKE;
        pending->last_seen_ns = now;

        if (payload_len == 0)
            return restore_and_return(ctx, inner_off, XDP_PASS);
    }

    if (payload_len > 0) {
        __u8 *cursor = payload;

        /* Unreachable given the payload_end check above, but this is the
         * direct ptr-vs-data_end form the verifier tracks; keep it so cursor
         * reads below stay provably in bounds. */
        if ((void *)(cursor + 1) > data_end)
            return restore_and_return(ctx, inner_off, XDP_DROP);

        if (!tcp->ack)
            return penalize_and_drop(ctx, inner_off, &key, now);

        if (pending->expected_seq != bpf_ntohl(tcp->seq)) {
            return reject_payload(ctx, inner_off, &key, pending, now);
        }

        if (pending->state == MC_AWAIT_HANDSHAKE) {
            if ((void *)(cursor + MC_MAX_PACKET_LEN_BYTES) > data_end) {
                pending->last_seen_ns = now;
                return restore_and_return(ctx, inner_off, XDP_DROP);
            }
            __s32 next_state = inspect_handshake(cursor, payload_end, &pending->protocol_version, &cursor, data_end);

            if (!next_state) {
                return reject_payload(ctx, inner_off, &key, pending, now);
            }
            if (next_state == MC_LEGACY_PING)
                return drop_with_cleanup(ctx, inner_off, &key);
            if (next_state == MC_DIRECT_STATUS)
                pending->state = MC_AWAIT_STATUS_REQUEST;
            else if (next_state == MC_DIRECT_LOGIN)
                pending->state = MC_AWAIT_LOGIN;
            else {
                pending->state = (__u16)next_state;
                pending->expected_seq += payload_len;
                pending->fails = 0;
                pending->last_seen_ns = now;
                return restore_and_return(ctx, inner_off, XDP_PASS);
            }
        }

        if (pending->state == MC_AWAIT_STATUS_REQUEST) {
            if (!inspect_status_request(cursor, payload_end, data_end)) {
                return reject_payload(ctx, inner_off, &key, pending, now);
            }
            if (mc_handshake_rate_exceeded(&key, now, &mc_status_rate4, &mc_status_rate6,
                                            MC_STATUS_RATE_WINDOW_NS, MC_STATUS_RATE_MAX))
                return penalize_and_drop(ctx, inner_off, &key, now);
            pending->state = MC_AWAIT_PING;
            pending->expected_seq += payload_len;
            pending->fails = 0;
            pending->last_seen_ns = now;
            return restore_and_return(ctx, inner_off, XDP_PASS);
        }

        if (pending->state == MC_AWAIT_PING) {
            if (!inspect_ping_request(cursor, payload_end, data_end)) {
                return reject_payload(ctx, inner_off, &key, pending, now);
            }
            pending->state = MC_PING_COMPLETE;
            pending->expected_seq += payload_len;
            pending->fails = 0;
            pending->last_seen_ns = now;
            return restore_and_return(ctx, inner_off, XDP_PASS);
        }

        if (pending->state == MC_AWAIT_LOGIN) {
            if (!inspect_login_packet(cursor, payload_end, pending->protocol_version, data_end)) {
                return reject_payload(ctx, inner_off, &key, pending, now);
            }
            if (mc_handshake_rate_exceeded(&key, now, &mc_login_rate4, &mc_login_rate6,
                                            MC_LOGIN_RATE_WINDOW_NS, MC_LOGIN_RATE_MAX))
                return penalize_and_drop(ctx, inner_off, &key, now);
            return verify_and_pass(ctx, inner_off, &key, now);
        }

        if (pending->state == MC_PING_COMPLETE)
            return drop_with_cleanup(ctx, inner_off, &key);

        pending->expected_seq += payload_len;
        pending->fails = 0;
        pending->last_seen_ns = now;
        return restore_and_return(ctx, inner_off, XDP_PASS);
    }

    if (pending->state == MC_AWAIT_HANDSHAKE) {
        pending->last_seen_ns = now;
        return restore_and_return(ctx, inner_off, XDP_PASS);
    }

    pending->last_seen_ns = now;
    return restore_and_return(ctx, inner_off, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
