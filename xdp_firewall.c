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
#define VLAN_MAX_DEPTH 4
#define CT_FAMILY_IPV4 2
#define CT_FAMILY_IPV6 10

// Conntrack timeouts and refresh intervals (in nanoseconds)
#define TCP_TIMEOUT_NS       (300ULL * 1000000000ULL) // 5 minutes
#define UDP_TIMEOUT_NS       (60ULL * 1000000000ULL)  // 1 minute
#define CT_REFRESH_INTERVAL  (30ULL * 1000000000ULL)  // 30 seconds

// ICMP token-bucket rate limiter
#define ICMP_TOKEN_RATE    100ULL  // tokens (packets) replenished per second
#define ICMP_TOKEN_MAX     100ULL  // burst capacity: bucket depth
#define ICMP_NS_PER_TOKEN  (1000000000ULL / ICMP_TOKEN_RATE)

// Global UDP sliding-window rate limiter
#define UDP_GLOBAL_WINDOW_NS     (1000000000ULL) // 1-second window
#define UDP_GLOBAL_DEFAULT_RATE  10000U           // default 10,000 pps; 0 = disabled

// Per-IP SYN rate limiter (anti-brute-force)
// Rate limits per port are configured at runtime via the syn_rate_ports map.
#define SYN_RATE_WINDOW_NS  (1000000000ULL)  // 1-second fixed window per source IP

// BPF Maps: hot-updatable TCP/UDP port whitelists (ARRAY implementation)
// The ARRAY map uses the port number (host byte order) as the array index (__u32 key).
// max_entries = 65536 covers all valid ports.
// Usage: bpftool map update pinned /sys/fs/bpf/xdp_fw/tcp_whitelist \
//          key 0x50 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00



// Counter map: per-CPU array for lock-free packet accounting
// Read with: bpftool map dump pinned /sys/fs/bpf/xdp_fw/pkt_counters

enum xdp_counter_idx {
    CNT_TCP_NEW_ALLOW   = 0,  // TCP pure SYN packets allowed by tcp_whitelist
    CNT_TCP_ESTABLISHED = 1,  // TCP established/reply packets allowed by conntrack
    CNT_TCP_DROP        = 2,  // TCP packets dropped (not in whitelist / no conntrack)
    CNT_UDP_PASS        = 3,  // UDP packets allowed
    CNT_UDP_DROP        = 4,  // UDP packets dropped
    CNT_IPV4_OTHER      = 5,  // IPv4 non-TCP/UDP (ICMP, etc.) passed
    CNT_IPV6_OTHER      = 6,  // IPv6 non-TCP/UDP (ICMPv6, etc.) passed
    CNT_FRAG_DROP       = 7,  // Fragmented packets dropped
    CNT_NON_IP          = 8,  // Non-IP traffic (ARP, etc.) passed
    CNT_TCP_CT_MISS     = 9,  // TCP ACK packets dropped due to missing conntrack state
    CNT_ICMP_DROP       = 10, // ICMP/ICMPv6 echo packets dropped by token-bucket rate limiter
    CNT_SYN_RATE_DROP   = 11, // TCP SYN dropped by per-IP rate limiter (anti-brute-force)
    CNT_UDP_RATE_DROP        = 12, // UDP dropped by per-source-IP rate limiter
    CNT_UDP_GLOBAL_RATE_DROP = 13, // UDP dropped by global sliding-window rate limiter
    CNT_TCP_MALFORM_NULL     = 14, // TCP NULL scan (all flags zero)
    CNT_TCP_MALFORM_XMAS     = 15, // TCP XMAS scan (FIN+URG+PSH)
    CNT_TCP_MALFORM_SYN_FIN  = 16, // TCP SYN+FIN contradictory flags
    CNT_TCP_MALFORM_SYN_RST  = 17, // TCP SYN+RST contradictory flags
    CNT_TCP_MALFORM_RST_FIN  = 18, // TCP RST+FIN contradictory flags
    CNT_TCP_MALFORM_DOFF     = 19, // TCP invalid data offset (doff < 5 or > 15 or truncated)
    CNT_TCP_MALFORM_PORT0    = 20, // TCP src or dst port is 0
    CNT_VLAN_DROP            = 21, // packet dropped: VLAN nesting exceeds VLAN_MAX_DEPTH
    CNT_MAX                  = 22,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CNT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} pkt_counters SEC(".maps");

static __always_inline void count(enum xdp_counter_idx idx) {
    __u32 key = (__u32)idx;
    __u64 *val = bpf_map_lookup_elem(&pkt_counters, &key);
    if (val)
        (*val)++;
}

struct ct_key {
    __u8 family;
    __u8 pad[3];
    __be16 sport;
    __be16 dport;
    __u32 saddr[4];
    __u32 daddr[4];
} __attribute__((aligned(8)));

struct trusted_v4_key {
    __u32 prefixlen;
    __be32 addr;
};

struct trusted_v6_key {
    __u32 prefixlen;
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct ct_key);
    __type(value, __u64); // ktime_ns at insert for future timeout handling
} tcp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct trusted_v4_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} trusted_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __type(key, struct trusted_v6_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} trusted_ipv6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 262144);
    __type(key, struct ct_key);
    __type(value, __u64); // ktime_ns of the most recent outbound UDP packet
} udp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // port number (host byte order) as array index
    __type(value, __u32); // 1 = allow
} tcp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // port number (host byte order) as array index
    __type(value, __u32); // 1 = allow
} udp_whitelist SEC(".maps");

// Global ICMP token-bucket state (single entry, protected by spin lock)
struct icmp_token_bucket {
    struct bpf_spin_lock lock;
    __u64 tokens;
    __u64 last_refill_ns; // ktime_ns of last refill; 0 = uninitialized
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct icmp_token_bucket);
} icmp_tb SEC(".maps");

// Global UDP two-bucket sliding-window rate limiter state.
// rate_max is runtime-configurable via bpftool; set to 0 to disable.
struct udp_global_tb {
    struct bpf_spin_lock lock;
    __u32 rate_max;          // max packets per 1-second window; 0 = disabled
    __u32 _pad;
    __u64 window_start_ns;   // ktime_ns of current bucket's start; 0 = uninit
    __u64 prev_count;        // packet count in the previous 1-second bucket
    __u64 curr_count;        // packet count in the current 1-second bucket
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct udp_global_tb);
} udp_global_rl SEC(".maps");

// Per-port SYN rate limit config, populated at runtime by xdp_port_sync.
// Key: dest port (host byte order). Value: rate_max SYNs/window (0 = disabled).
// Ports absent from this map are NOT rate-limited (e.g. HTTP/HTTPS).
struct syn_rate_port_cfg {
    __u32 rate_max; // max SYNs per source IP per SYN_RATE_WINDOW_NS; 0 = skip
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct syn_rate_port_cfg);
} syn_rate_ports SEC(".maps");

// Per-IP SYN rate limiter state
struct syn_rate_key {
    __u8  family;
    __u8  pad[3];
    __u32 addr[4]; // IPv4: addr[0] only; IPv6: all 4 words
} __attribute__((aligned(8)));

struct syn_rate_val {
    __u64 window_start_ns;
    __u32 count;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536); // tracks up to 64K concurrent source IPs
    __type(key, struct syn_rate_key);
    __type(value, struct syn_rate_val);
} syn_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // dest port (host byte order)
    __type(value, struct syn_rate_port_cfg);
} udp_rate_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct syn_rate_key);
    __type(value, struct syn_rate_val);
} udp_rate_map SEC(".maps");

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

// Per-IP SYN rate limiter: returns XDP_PASS or XDP_DROP.
// Looks up per-port config from syn_rate_ports; skips limiting entirely if
// the port is absent (e.g. HTTP/HTTPS). Races on multi-core are tolerated —
// a few extra SYNs slipping through is acceptable; spin locking every SYN
// would be far too costly.
static __always_inline int syn_rate_check(struct ct_key *key, __u64 now,
                                           __u32 dest_port)
{
    // Per-port config: rate_max=0 or missing entry → no rate limit for this port.
    struct syn_rate_port_cfg *cfg = bpf_map_lookup_elem(&syn_rate_ports, &dest_port);
    if (!cfg || cfg->rate_max == 0)
        return XDP_PASS;

    __u32 rate_max = cfg->rate_max;

    struct syn_rate_key rkey;
    __builtin_memset(&rkey, 0, sizeof(rkey));
    rkey.family   = key->family;
    rkey.addr[0]  = key->saddr[0];
    rkey.addr[1]  = key->saddr[1];
    rkey.addr[2]  = key->saddr[2];
    rkey.addr[3]  = key->saddr[3];

    struct syn_rate_val *rv = bpf_map_lookup_elem(&syn_rate_map, &rkey);
    if (!rv) {
        // First SYN from this source IP — create a fresh entry.
        struct syn_rate_val new_rv;
        __builtin_memset(&new_rv, 0, sizeof(new_rv));
        new_rv.window_start_ns = now;
        new_rv.count = 1;
        bpf_map_update_elem(&syn_rate_map, &rkey, &new_rv, BPF_ANY);
        return XDP_PASS;
    }

    if (now - rv->window_start_ns >= SYN_RATE_WINDOW_NS) {
        // Window has elapsed — start a fresh one.
        rv->window_start_ns = now;
        rv->count = 1;
        return XDP_PASS;
    }

    if (rv->count >= rate_max)
        return XDP_DROP;

    rv->count++;
    return XDP_PASS;
}

static __always_inline int udp_rate_check(struct ct_key *key, __u64 now,
                                           __u32 dest_port)
{
    struct syn_rate_port_cfg *cfg = bpf_map_lookup_elem(&udp_rate_ports, &dest_port);
    if (!cfg || cfg->rate_max == 0)
        return XDP_PASS;

    __u32 rate_max = cfg->rate_max;

    struct syn_rate_key rkey;
    __builtin_memset(&rkey, 0, sizeof(rkey));
    rkey.family  = key->family;
    rkey.addr[0] = key->saddr[0];
    rkey.addr[1] = key->saddr[1];
    rkey.addr[2] = key->saddr[2];
    rkey.addr[3] = key->saddr[3];

    struct syn_rate_val *rv = bpf_map_lookup_elem(&udp_rate_map, &rkey);
    if (!rv) {
        struct syn_rate_val new_rv;
        __builtin_memset(&new_rv, 0, sizeof(new_rv));
        new_rv.window_start_ns = now;
        new_rv.count = 1;
        bpf_map_update_elem(&udp_rate_map, &rkey, &new_rv, BPF_ANY);
        return XDP_PASS;
    }

    if (now - rv->window_start_ns >= SYN_RATE_WINDOW_NS) {
        rv->window_start_ns = now;
        rv->count = 1;
        return XDP_PASS;
    }

    if (rv->count >= rate_max)
        return XDP_DROP;

    rv->count++;
    return XDP_PASS;
}

// Global UDP sliding-window rate limiter.
// Uses a two-bucket approximation: maintains current and previous 1-second
// buckets and computes a weighted estimate of the last 1 second's packet count.
// Avoids integer division by comparing scaled values:
//   prev*(WINDOW-elapsed) + curr*WINDOW  vs  rate_max*WINDOW
static __always_inline int udp_global_rate_check(__u64 now)
{
    __u32 key = 0;
    struct udp_global_tb *tb = bpf_map_lookup_elem(&udp_global_rl, &key);
    if (!tb)
        return XDP_PASS;

    bpf_spin_lock(&tb->lock);

    if (tb->rate_max == 0) {
        bpf_spin_unlock(&tb->lock);
        return XDP_PASS;
    }

    if (tb->window_start_ns == 0) {
        tb->window_start_ns = now;
        tb->prev_count = 0;
        tb->curr_count = 1;
        bpf_spin_unlock(&tb->lock);
        return XDP_PASS;
    }

    __u64 elapsed = now - tb->window_start_ns;

    if (elapsed >= 2 * UDP_GLOBAL_WINDOW_NS) {
        // Both buckets expired; start fresh.
        tb->window_start_ns = now;
        tb->prev_count = 0;
        tb->curr_count = 1;
        bpf_spin_unlock(&tb->lock);
        return XDP_PASS;
    }

    if (elapsed >= UDP_GLOBAL_WINDOW_NS) {
        tb->prev_count = tb->curr_count;
        tb->curr_count = 0;
        tb->window_start_ns += UDP_GLOBAL_WINDOW_NS;
        elapsed -= UDP_GLOBAL_WINDOW_NS;
    }

    // Weighted sliding-window estimate (multiplication avoids division):
    //   (prev*(W-elapsed) + curr*W) >= rate_max*W  →  DROP
    __u64 weighted   = tb->prev_count * (UDP_GLOBAL_WINDOW_NS - elapsed)
                     + tb->curr_count * UDP_GLOBAL_WINDOW_NS;
    __u64 threshold  = (__u64)tb->rate_max * UDP_GLOBAL_WINDOW_NS;

    int ret;
    if (weighted >= threshold) {
        ret = XDP_DROP;
    } else {
        tb->curr_count++;
        ret = XDP_PASS;
    }

    bpf_spin_unlock(&tb->lock);
    return ret;
}

static __always_inline void fill_ct_key_v4(
    struct ct_key *key, __be32 saddr, __be32 daddr,
    __be16 sport, __be16 dport)
{
    // Zero the full key so the verifier never sees uninitialized padding.
    __builtin_memset(key, 0, sizeof(*key));
    key->family = CT_FAMILY_IPV4;
    key->sport = sport;
    key->dport = dport;
    key->saddr[0] = (__u32)saddr;
    key->daddr[0] = (__u32)daddr;
}

static __always_inline void fill_ct_key_v6(
    struct ct_key *key, const struct in6_addr *saddr, const struct in6_addr *daddr,
    __be16 sport, __be16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->family = CT_FAMILY_IPV6;
    key->sport = sport;
    key->dport = dport;
    __builtin_memcpy(key->saddr, saddr, sizeof(*saddr));
    __builtin_memcpy(key->daddr, daddr, sizeof(*daddr));
}

static __always_inline int check_tcp_conntrack(
    struct ct_key *key, __u8 tcp_flags, __u32 dest_port)
{
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;

    // 1. RST: evict conntrack entry, then pass to the kernel.
    // Dropping RST would prevent the kernel from delivering ECONNRESET to
    // the application, leaving the socket open until a read/write timeout.
    if (tcp_flags & 0x04) {
        bpf_map_delete_elem(&tcp_conntrack, key);
        count(CNT_TCP_ESTABLISHED);
        return XDP_PASS;
    }

    // 2. ACK / FIN+ACK / SYN-ACK (established traffic)
    if (tcp_flags & 0x10) {
        last_seen = bpf_map_lookup_elem(&tcp_conntrack, key);
        if (last_seen) {
            // Check logical timeout
            if (now - *last_seen > TCP_TIMEOUT_NS) {
                bpf_map_delete_elem(&tcp_conntrack, key);
                count(CNT_TCP_CT_MISS);
                count(CNT_TCP_DROP);
                return XDP_DROP;
            }

            // FIN+ACK: connection is closing — evict immediately so the map
            // slot is available for new connections rather than waiting up to
            // TCP_TIMEOUT_NS (5 min).  The remaining FIN/ACK exchange will
            // miss conntrack but those packets are benign on a closing conn.
            if (tcp_flags & 0x01) {
                bpf_map_delete_elem(&tcp_conntrack, key);
                count(CNT_TCP_ESTABLISHED);
                return XDP_PASS;
            }

            // Periodic refresh for long-lived connections
            if (now - *last_seen > CT_REFRESH_INTERVAL) {
                bpf_map_update_elem(&tcp_conntrack, key, &now, BPF_EXIST);
            }

            count(CNT_TCP_ESTABLISHED);
            return XDP_PASS;
        }

        count(CNT_TCP_CT_MISS);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    // 2b. Standalone FIN (no ACK, rare but valid per RFC 793 §3.5)
    if (tcp_flags & 0x01) {
        last_seen = bpf_map_lookup_elem(&tcp_conntrack, key);
        if (last_seen) {
            bpf_map_delete_elem(&tcp_conntrack, key);
            count(CNT_TCP_ESTABLISHED);
            return XDP_PASS;
        }
        goto drop;
    }

    // 3. SYN (new inbound connection)
    // TC egress only fires on outbound, so any inbound SYN on a new tuple
    // will always miss conntrack — no pre-check needed or useful here.
    // Use (flags & SYN) && !(flags & ACK) instead of == 0x02 so that
    // ECN-negotiating SYNs (SYN+ECE=0x42, SYN+ECE+CWR=0xC2) are accepted.
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10)) {
        // Whitelist check: port not open → DROP, one map lookup and done.
        __u32 *allow = bpf_map_lookup_elem(&tcp_whitelist, &dest_port);
        if (!allow || !*allow)
            goto drop;

        // Port is open; apply per-IP SYN rate limiting for protected services.
        if (syn_rate_check(key, now, dest_port) == XDP_DROP) {
            count(CNT_SYN_RATE_DROP);
            count(CNT_TCP_DROP);
            return XDP_DROP;
        }

        bpf_map_update_elem(&tcp_conntrack, key, &now, BPF_ANY);
        count(CNT_TCP_NEW_ALLOW);
        return XDP_PASS;
    }

drop:

    count(CNT_TCP_DROP);
    return XDP_DROP;
}

// TCP malformed packet check. Called after the basic 20-byte bounds check,
// before conntrack. Returns XDP_DROP (and increments the appropriate counter)
// for any packet that violates RFC 793 structural invariants.
static __always_inline int tcp_malformed_drop(struct tcphdr *tcp, void *data_end)
{
    // doff must be 5–15 (20–60 bytes); values outside this range are impossible
    // on any conforming implementation and indicate a crafted/corrupt packet.
    __u8 doff = tcp->doff;
    if (doff < 5 || doff > 15) {
        count(CNT_TCP_MALFORM_DOFF);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }
    // Verify the full options area declared by doff is within the packet.
    if ((void *)tcp + ((__u32)doff * 4) > data_end) {
        count(CNT_TCP_MALFORM_DOFF);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    // Port 0 is reserved and never used by real traffic.
    if (tcp->source == 0 || tcp->dest == 0) {
        count(CNT_TCP_MALFORM_PORT0);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    __u8 flags = ((__u8 *)tcp)[13];

    // NULL scan: no control bits set — useless for real traffic, used by scanners.
    if (flags == 0) {
        count(CNT_TCP_MALFORM_NULL);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    // SYN+FIN: open and close simultaneously — never valid per RFC 793.
    if ((flags & 0x03) == 0x03) {
        count(CNT_TCP_MALFORM_SYN_FIN);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    // SYN+RST: initiate and abort simultaneously — never valid per RFC 793.
    if ((flags & 0x06) == 0x06) {
        count(CNT_TCP_MALFORM_SYN_RST);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    // RST+FIN: abort and close simultaneously — never valid. Note: RST+ACK is
    // legitimate (normal half-close acknowledgement) and must not be caught here.
    if ((flags & 0x05) == 0x05) {
        count(CNT_TCP_MALFORM_RST_FIN);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    // XMAS scan: FIN(0x01)+URG(0x20)+PSH(0x08) all set — nmap -sX signature.
    if ((flags & 0x29) == 0x29) {
        count(CNT_TCP_MALFORM_XMAS);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline int check_tcp_ipv4(
    struct iphdr *ip, void *trans_data, void *data_end)
{
    struct tcphdr *tcp = trans_data;
    struct ct_key key;

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp_malformed_drop(tcp, data_end) == XDP_DROP)
        return XDP_DROP;

    __u8  tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);
    fill_ct_key_v4(&key, ip->saddr, ip->daddr, tcp->source, tcp->dest);

    // Trusted source: bypass whitelist + SYN rate limit for new connections.
    // Malformed-packet check already ran above; fragments dropped before we arrive.
    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10) && is_trusted_v4(ip->saddr)) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&tcp_conntrack, &key, &now, BPF_ANY);
        count(CNT_TCP_NEW_ALLOW);
        return XDP_PASS;
    }

    return check_tcp_conntrack(&key, tcp_flags, dest_port);
}

static __always_inline int check_tcp_ipv6(
    struct ipv6hdr *ipv6, void *trans_data, void *data_end)
{
    struct tcphdr *tcp = trans_data;
    struct ct_key key;

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    if (tcp_malformed_drop(tcp, data_end) == XDP_DROP)
        return XDP_DROP;

    __u8 tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);
    fill_ct_key_v6(&key, &ipv6->saddr, &ipv6->daddr, tcp->source, tcp->dest);

    if ((tcp_flags & 0x02) && !(tcp_flags & 0x10) && is_trusted_v6(&ipv6->saddr)) {
        __u64 now = bpf_ktime_get_ns();
        bpf_map_update_elem(&tcp_conntrack, &key, &now, BPF_ANY);
        count(CNT_TCP_NEW_ALLOW);
        return XDP_PASS;
    }

    return check_tcp_conntrack(&key, tcp_flags, dest_port);
}

static __always_inline int check_udp_ipv4(
    struct iphdr *ip, void *trans_data, void *data_end)
{
    struct udphdr *udp = trans_data;
    struct ct_key key;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);

    // UDP replies are stateful now: tc egress records outbound packets as the
    // reverse tuple, and XDP ingress looks up the current inbound tuple here.
    fill_ct_key_v4(&key, ip->saddr, ip->daddr, udp->source, udp->dest);
    last_seen = bpf_map_lookup_elem(&udp_conntrack, &key);
    if (last_seen) {
        // Check logical timeout
        if (now - *last_seen > UDP_TIMEOUT_NS) {
            bpf_map_delete_elem(&udp_conntrack, &key);
        } else {
            // Periodic refresh
            if (now - *last_seen > CT_REFRESH_INTERVAL) {
                bpf_map_update_elem(&udp_conntrack, &key, &now, BPF_EXIST);
            }
            count(CNT_UDP_PASS);
            return XDP_PASS;
        }
    }

    if (is_trusted_v4(ip->saddr)) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    __u32 *allow = bpf_map_lookup_elem(&udp_whitelist, &dest_port);
    if (allow && *allow) {
        if (udp_rate_check(&key, now, dest_port) == XDP_DROP) {
            count(CNT_UDP_RATE_DROP);
            count(CNT_UDP_DROP);
            return XDP_DROP;
        }
        if (udp_global_rate_check(now) == XDP_DROP) {
            count(CNT_UDP_GLOBAL_RATE_DROP);
            count(CNT_UDP_DROP);
            return XDP_DROP;
        }
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    count(CNT_UDP_DROP);
    return XDP_DROP;
}

static __always_inline int check_udp_ipv6(
    struct ipv6hdr *ipv6, void *trans_data, void *data_end)
{
    struct udphdr *udp = trans_data;
    struct ct_key key;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;

    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);

    // IPv6 UDP replies are matched by the same shared conntrack map shape.
    fill_ct_key_v6(&key, &ipv6->saddr, &ipv6->daddr, udp->source, udp->dest);
    last_seen = bpf_map_lookup_elem(&udp_conntrack, &key);
    if (last_seen) {
        // Check logical timeout
        if (now - *last_seen > UDP_TIMEOUT_NS) {
            bpf_map_delete_elem(&udp_conntrack, &key);
        } else {
            // Periodic refresh
            if (now - *last_seen > CT_REFRESH_INTERVAL) {
                bpf_map_update_elem(&udp_conntrack, &key, &now, BPF_EXIST);
            }
            count(CNT_UDP_PASS);
            return XDP_PASS;
        }
    }

    if (is_trusted_v6(&ipv6->saddr)) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    __u32 *allow = bpf_map_lookup_elem(&udp_whitelist, &dest_port);
    if (allow && *allow) {
        if (udp_rate_check(&key, now, dest_port) == XDP_DROP) {
            count(CNT_UDP_RATE_DROP);
            count(CNT_UDP_DROP);
            return XDP_DROP;
        }
        if (udp_global_rate_check(now) == XDP_DROP) {
            count(CNT_UDP_GLOBAL_RATE_DROP);
            count(CNT_UDP_DROP);
            return XDP_DROP;
        }
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    count(CNT_UDP_DROP);
    return XDP_DROP;
}

// ICMP token-bucket rate limiter: returns XDP_PASS or XDP_DROP.
// Tokens refill at ICMP_TOKEN_RATE per second up to ICMP_TOKEN_MAX.
static __always_inline int icmp_rate_limit(void)
{
    __u32 key = 0;
    struct icmp_token_bucket *tb = bpf_map_lookup_elem(&icmp_tb, &key);
    if (!tb)
        return XDP_PASS; // fail-open: never block because of a map miss

    __u64 now = bpf_ktime_get_ns();
    int ret;

    bpf_spin_lock(&tb->lock);

    if (tb->last_refill_ns == 0) {
        // First ICMP packet ever: start with a full bucket.
        tb->tokens = ICMP_TOKEN_MAX;
        tb->last_refill_ns = now;
    } else {
        // Add whole tokens for elapsed time; advance the refill clock by the
        // consumed intervals only (prevents credit accumulation across idle gaps).
        __u64 elapsed = now - tb->last_refill_ns;
        __u64 new_tokens = elapsed / ICMP_NS_PER_TOKEN;
        if (new_tokens > 0) {
            tb->tokens += new_tokens;
            if (tb->tokens > ICMP_TOKEN_MAX)
                tb->tokens = ICMP_TOKEN_MAX;
            tb->last_refill_ns += new_tokens * ICMP_NS_PER_TOKEN;
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

// IPv6 extension header traversal to prevent bypassing port checks

static __always_inline __u8 skip_ipv6_exthdr(
    void **trans_data, void *data_end, __u8 nexthdr)
{
    // Traverse at most 6 extension headers; treat more as anomalous and pass
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        switch (nexthdr) {
        case IPPROTO_HOPOPTS:  // 0  Hop-by-Hop options
        case IPPROTO_ROUTING:  // 43 Routing header
        case IPPROTO_DSTOPTS:  // 60 Destination options
        {
            __u8 *hdr = *trans_data;
            if ((void *)(hdr + 2) > data_end)
                return IPPROTO_NONE;
            nexthdr = hdr[0];
            __u32 hdrlen = (((__u32)hdr[1] + 1) * 8);
            *trans_data += hdrlen;
            if (*trans_data > data_end)
                return IPPROTO_NONE;
            break;
        }
        case IPPROTO_FRAGMENT: // 44 Fragment header (fixed 8 bytes)
        {
            __u8 *hdr = *trans_data;
            __u16 frag_off_flags;
            if ((void *)(hdr + 8) > data_end)
                return IPPROTO_NONE;
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
    return nexthdr;
}

// Strip up to VLAN_MAX_DEPTH 802.1Q/802.1AD tags from the Ethernet frame.
// Returns false if the packet is truncated mid-tag (caller should XDP_PASS).
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
            return false; // truncated: let the kernel handle it
        *eth_proto = vlan->h_vlan_encapsulated_proto;
        *l3_data   = (void *)(vlan + 1);
    }
    return true; // loop exhausted; caller checks whether eth_proto is still VLAN
}

// Main XDP program

SEC("xdp")
int xdp_port_whitelist(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // --- 1. Parse Ethernet layer ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Strip 802.1Q / QinQ VLAN tags so firewall rules apply to the inner
    // EtherType.  Without this, VLAN-tagged IP packets arrive with
    // h_proto=0x8100 and bypass all port/conntrack checks via CNT_NON_IP.
    __be16 eth_proto = eth->h_proto;
    void  *l3_data   = (void *)(eth + 1);

    if (!strip_vlan_tags(&eth_proto, &l3_data, data_end))
        return XDP_PASS; // truncated VLAN header: let the kernel handle it

    // Drop packets with more VLAN layers than VLAN_MAX_DEPTH — no legitimate
    // traffic uses such deep nesting; deeper tags are a known bypass technique.
    if (eth_proto == bpf_htons(ETH_P_8021Q) ||
        eth_proto == bpf_htons(ETH_P_8021AD)) {
        count(CNT_VLAN_DROP);
        return XDP_DROP;
    }

    // 2. IPv4
    if (eth_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = l3_data;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        // Validate ihl before reading frag_off
        __u32 ip_hlen = ip->ihl * 4;
        if (ip_hlen < sizeof(*ip))
            return XDP_PASS;

        // Drop IPv4 fragmented packets (rarely needed on personal servers, and fragments can bypass port filtering)
        if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET)) {
            count(CNT_FRAG_DROP);
            return XDP_DROP;
        }

        void *trans_data = (void *)ip + ip_hlen;

        if (trans_data >= data_end)
            return XDP_PASS;

        switch (ip->protocol) {
        case IPPROTO_TCP:
            return check_tcp_ipv4(ip, trans_data, data_end);
        case IPPROTO_UDP:
            return check_udp_ipv4(ip, trans_data, data_end);
        case IPPROTO_ICMP: {
            if (!is_trusted_v4(ip->saddr) && icmp_rate_limit() == XDP_DROP) {
                count(CNT_ICMP_DROP);
                return XDP_DROP;
            }
            count(CNT_IPV4_OTHER);
            return XDP_PASS;
        }
        default:
            // Pass other IPv4 protocols (IGMP, GRE, etc.)
            count(CNT_IPV4_OTHER);
            return XDP_PASS;
        }
    }

    // 3. IPv6
    if (eth_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = l3_data;
        if ((void *)(ipv6 + 1) > data_end)
            return XDP_PASS;

        void *trans_data = (void *)(ipv6 + 1);

        __u8 nexthdr = skip_ipv6_exthdr(&trans_data, data_end, ipv6->nexthdr);
        // 0xFF is our dedicated sentinel for non-initial IPv6 fragments.
        if (nexthdr == IPV6_FRAG_DROP_SENTINEL) {
            count(CNT_FRAG_DROP);
            return XDP_DROP;
        }
        if (nexthdr == IPPROTO_NONE)
            return XDP_PASS;

        if (trans_data >= data_end)
            return XDP_PASS;

        switch (nexthdr) {
        case IPPROTO_TCP:
            return check_tcp_ipv6(ipv6, trans_data, data_end);
        case IPPROTO_UDP:
            return check_udp_ipv6(ipv6, trans_data, data_end);
        case IPPROTO_ICMPV6: {
            // NDP (RS/RA/NS/NA/Redirect, types 133-137) must always pass —
            // dropping them breaks IPv6 neighbour discovery and routing.
            // Only echo requests (type 128) go through the shared token bucket.
            struct icmp6hdr *icmp6 = trans_data;
            if ((void *)(icmp6 + 1) > data_end) {
                count(CNT_IPV6_OTHER);
                return XDP_PASS;
            }
            if (icmp6->icmp6_type == ICMPV6_ECHO_REQUEST &&
                !is_trusted_v6(&ipv6->saddr) &&
                icmp_rate_limit() == XDP_DROP) {
                count(CNT_ICMP_DROP);
                return XDP_DROP;
            }
            count(CNT_IPV6_OTHER);
            return XDP_PASS;
        }
        default:
            // Other IPv6 protocols pass freely
            count(CNT_IPV6_OTHER);
            return XDP_PASS;
        }
    }

    // 4. Pass non-IP traffic (ARP, etc.) 
    count(CNT_NON_IP);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
