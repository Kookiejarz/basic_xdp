#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef IP_MF
#define IP_MF     0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

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
    __type(value, __u64);
} tcp_conntrack SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ct_key);
    __type(value, __u64);
} udp_conntrack SEC(".maps");

static __always_inline void fill_ct_key(
    struct ct_key *key, __be32 saddr, __be32 daddr,
    __be16 sport, __be16 dport)
{
    __builtin_memset(key, 0, sizeof(*key));
    key->saddr = saddr;
    key->daddr = daddr;
    key->sport = sport;
    key->dport = dport;
}

SEC("classifier")
int tc_egress_track(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct ct_key key;
    __u32 ip_hlen;
    __u64 now;
    __u8 tcp_flags;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    ip_hlen = ip->ihl * 4;
    if (ip_hlen < sizeof(*ip))
        return TC_ACT_OK;
    if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
        return TC_ACT_OK;

    switch (ip->protocol) {
    case IPPROTO_TCP:
        tcp = (void *)ip + ip_hlen;
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        tcp_flags = ((__u8 *)tcp)[13];
        if (tcp_flags != 0x02)
            return TC_ACT_OK;

        // Record the reverse tuple so inbound SYN-ACK/ACK packets from
        // host-initiated TCP connections can match conntrack at XDP.
        fill_ct_key(&key, ip->daddr, ip->saddr, tcp->dest, tcp->source);
        now = bpf_ktime_get_ns();
        bpf_map_update_elem(&tcp_conntrack, &key, &now, BPF_ANY);
        return TC_ACT_OK;
    case IPPROTO_UDP:
        udp = (void *)ip + ip_hlen;
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;

        // Record the reverse tuple so inbound UDP replies can be matched at XDP.
        fill_ct_key(&key, ip->daddr, ip->saddr, udp->dest, udp->source);
        now = bpf_ktime_get_ns();
        bpf_map_update_elem(&udp_conntrack, &key, &now, BPF_ANY);
        return TC_ACT_OK;
    default:
        return TC_ACT_OK;
    }
}

char _license[] SEC("license") = "GPL";
