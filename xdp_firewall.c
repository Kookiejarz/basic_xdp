#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// These two macros are not exposed under the BPF compilation path of <linux/ip.h>, so define them manually
#ifndef IP_MF
#define IP_MF     0x2000  // More Fragments bit
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF  // Fragment offset mask
#endif

#define IPV6_FRAG_DROP_SENTINEL 0xFF

// BPF Maps: hot-updatable TCP/UDP port whitelists (ARRAY implementation)
// The ARRAY map uses the port number (host byte order) as the array index (__u32 key).
// max_entries = 65536 covers all valid ports.
// Usage: bpftool map update pinned /sys/fs/bpf/xdp_fw/tcp_whitelist \
//          key 0x50 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00



// Counter map: per-CPU array for lock-free packet accounting
// Read with: bpftool map dump pinned /sys/fs/bpf/xdp_fw/pkt_counters

enum xdp_counter_idx {
    CNT_TCP_PASS    = 0,  // TCP packets allowed
    CNT_TCP_DROP    = 1,  // TCP packets dropped (not in whitelist)
    CNT_UDP_PASS    = 2,  // UDP packets allowed
    CNT_UDP_DROP    = 3,  // UDP packets dropped (not in whitelist)
    CNT_IPV4_OTHER  = 4,  // IPv4 non-TCP/UDP (ICMP, etc.) passed
    CNT_IPV6_OTHER  = 5,  // IPv6 non-TCP/UDP (ICMPv6, etc.) passed
    CNT_FRAG_DROP   = 6,  // IPv4 fragmented packets dropped
    CNT_NON_IP      = 7,  // Non-IP traffic (ARP, etc.) passed
    CNT_TCP_CT_MISS = 8,  // TCP ACK packets dropped due to missing conntrack state
    CNT_MAX         = 9,
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
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ct_key);
    __type(value, __u64); // ktime_ns at insert for future timeout handling
} tcp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __be32);   // IPv4 source address in network byte order
    __type(value, __u32);  // 1 = trusted
} trusted_src_ips SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
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

static __always_inline void fill_ct_key(
    struct ct_key *key, __be32 saddr, __be32 daddr,
    __be16 sport, __be16 dport)
{
    // Zero the full key so the verifier never sees uninitialized padding.
    __builtin_memset(key, 0, sizeof(*key));
    key->saddr = saddr;
    key->daddr = daddr;
    key->sport = sport;
    key->dport = dport;
}

// TCP port check
static __always_inline int check_tcp_legacy(void *trans_data, void *data_end) {
    struct tcphdr *tcp = trans_data;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u8  tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);

    // Pass reply packets of established connections first (ACK/SYN-ACK/FIN/RST).
    // Their dest_port is a random client port not in the whitelist,
    // so they must be passed before the whitelist check.
    if (tcp_flags & 0x10) { // ACK bit set
        count(CNT_TCP_PASS);
        return XDP_PASS;
    }

    // Only pure SYN (0x02, no ACK) is checked against the whitelist
    __u32 *allow = bpf_map_lookup_elem(&tcp_whitelist, &dest_port);
    if (allow && *allow) {
        count(CNT_TCP_PASS);
        return XDP_PASS;
    }

    count(CNT_TCP_DROP);
    return XDP_DROP;
}

static __always_inline int check_tcp_ipv4(
    struct iphdr *ip, void *trans_data, void *data_end)
{
    struct tcphdr *tcp = trans_data;
    struct ct_key key;
    __u64 now;

    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    __u8  tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);

    if (tcp_flags & 0x10) {
        fill_ct_key(&key, ip->saddr, ip->daddr, tcp->source, tcp->dest);
        if (bpf_map_lookup_elem(&tcp_conntrack, &key)) {
            count(CNT_TCP_PASS);
            return XDP_PASS;
        }

        // Track conntrack misses separately while preserving total TCP drop count.
        count(CNT_TCP_CT_MISS);
        count(CNT_TCP_DROP);
        return XDP_DROP;
    }

    if (tcp_flags == 0x02) {
        __u32 *allow = bpf_map_lookup_elem(&tcp_whitelist, &dest_port);
        if (allow && *allow) {
            now = bpf_ktime_get_ns();
            fill_ct_key(&key, ip->saddr, ip->daddr, tcp->source, tcp->dest);
            bpf_map_update_elem(&tcp_conntrack, &key, &now, BPF_ANY);
            count(CNT_TCP_PASS);
            return XDP_PASS;
        }
    }

    count(CNT_TCP_DROP);
    return XDP_DROP;
}

// UDP port check
static __always_inline int check_udp_legacy(void *trans_data, void *data_end) {
    struct udphdr *udp = trans_data;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Convert byte order once at the start of the function
    __u32 src_port  = (__u32)bpf_ntohs(udp->source);
    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);

    // Pass common UDP responses: DNS(53) / NTP(123) / DHCP(67) / QUIC(443)
    // Their dest_port is a random client port not in the whitelist, so pass them here
    if (src_port == 53  ||
        src_port == 123 ||
        src_port == 67  ||
        src_port == 443) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    __u32 *allow = bpf_map_lookup_elem(&udp_whitelist, &dest_port);
    if (allow && *allow) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    count(CNT_UDP_DROP);
    return XDP_DROP;
}

static __always_inline int check_udp(
    struct iphdr *ip, void *trans_data, void *data_end)
{
    struct udphdr *udp = trans_data;
    struct ct_key key;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Keep source port parsed as __u32 for type consistency with map key usage.
    __u32 src_port  = (__u32)bpf_ntohs(udp->source);
    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);

    // UDP replies are stateful now: tc egress records outbound packets as the
    // reverse tuple, and XDP ingress looks up the current inbound tuple here.
    fill_ct_key(&key, ip->saddr, ip->daddr, udp->source, udp->dest);
    if (bpf_map_lookup_elem(&udp_conntrack, &key)) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    (void)src_port;

    __u32 *allow = bpf_map_lookup_elem(&udp_whitelist, &dest_port);
    if (allow && *allow) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    __u32 *trusted = bpf_map_lookup_elem(&trusted_src_ips, &ip->saddr);
    if (trusted && *trusted) {
        count(CNT_UDP_PASS);
        return XDP_PASS;
    }

    count(CNT_UDP_DROP);
    return XDP_DROP;
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

// Main XDP program

SEC("xdp")
int xdp_port_whitelist(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // --- 1. Parse Ethernet layer ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 2. IPv4
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
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
            return check_udp(ip, trans_data, data_end);
        default:
            // Pass other protocols such as ICMP (keep ping reachable)
            count(CNT_IPV4_OTHER);
            return XDP_PASS;
        }
    }

    // 3. IPv6 
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (void *)(eth + 1);
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
            // TODO: IPv6 conntrack not yet implemented — ACK bypass still present on IPv6 path.
            return check_tcp_legacy(trans_data, data_end);
        case IPPROTO_UDP:
            // TODO: IPv6 UDP conntrack / trusted_src_ips not yet implemented.
            return check_udp_legacy(trans_data, data_end);
        default:
            // ICMPv6 (including NDP neighbor discovery) must be passed, otherwise IPv6 networking breaks
            count(CNT_IPV6_OTHER);
            return XDP_PASS;
        }
    }

    // 4. Pass non-IP traffic (ARP, etc.) 
    count(CNT_NON_IP);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
