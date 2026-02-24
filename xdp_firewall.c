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

// ============================================================
// BPF Map：运行时可热更新的 TCP/UDP 端口白名单（ARRAY 实现）
// ARRAY Map 以端口号（主机字节序）作为数组下标（__u32 key），
// max_entries = 65536 覆盖全部合法端口。
// 用法：bpftool map update pinned /sys/fs/bpf/tcp_whitelist \
//         key 0x50 0x00 0x00 0x00 value 0x01 0x00 0x00 0x00
// ============================================================
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // 主机字节序端口号作为数组下标
    __type(value, __u32);  // 1 = 放行
} tcp_whitelist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);   // 主机字节序端口号作为数组下标
    __type(value, __u32);
} udp_whitelist SEC(".maps");

// ============================================================
// 修复1：TCP 端口检查改用 map 查询
// ============================================================
static __always_inline int check_tcp(void *trans_data, void *data_end) {
    struct tcphdr *tcp = trans_data;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // 函数开头一次性完成字节序转换，后续逻辑统一使用主机字节序
    __u8  tcp_flags = ((__u8 *)tcp)[13];
    __u32 dest_port = (__u32)bpf_ntohs(tcp->dest);

    // 优先放行已建立连接的回包（ACK/SYN-ACK/FIN/RST）
    //    回包的 dest_port 是客户端随机端口，不在白名单，必须在白名单检查前放行
    if (tcp_flags & 0x10)        // ACK bit 置位
        return XDP_PASS;

    // 只有纯 SYN（0x02，无 ACK）才查白名单
    __u32 *allow = bpf_map_lookup_elem(&tcp_whitelist, &dest_port);
    if (allow && *allow)
        return XDP_PASS;

    return XDP_DROP;
}

// ============================================================
// 修复2：UDP 增加白名单（默认放行 DNS 响应，其余丢弃）
// ============================================================
static __always_inline int check_udp(void *trans_data, void *data_end) {
    struct udphdr *udp = trans_data;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // 函数开头一次性完成字节序转换：
    //   原来 source 侧用 4 次 bpf_htons() 做比较，现在只需 1 次 bpf_ntohs()
    __u16 src_port  = bpf_ntohs(udp->source);
    __u32 dest_port = (__u32)bpf_ntohs(udp->dest);

    // 放行常见 UDP 响应（DNS / NTP / DHCP / QUIC）
    if (src_port == 53  ||
        src_port == 123 ||
        src_port == 67  ||
        src_port == 443)
        return XDP_PASS;

    __u32 *allow = bpf_map_lookup_elem(&udp_whitelist, &dest_port);
    if (allow && *allow)
        return XDP_PASS;

    return XDP_DROP;
}

// ============================================================
// 修复3：IPv6 扩展头遍历，防止扩展头绕过端口检查
// ============================================================
static __always_inline __u8 skip_ipv6_exthdr(
    void **trans_data, void *data_end, __u8 nexthdr)
{
    // 最多遍历 6 层扩展头，超出则视为异常放行
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        switch (nexthdr) {
        case IPPROTO_HOPOPTS:   // 0  逐跳选项
        case IPPROTO_ROUTING:   // 43 路由头
        case IPPROTO_DSTOPTS:   // 60 目标选项
        {
            // 扩展头格式：[nexthdr(1B)][hdrlen(1B)][data...]
            // 总长度 = (hdrlen + 1) * 8 字节
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
        case IPPROTO_FRAGMENT:  // 44 分片头（固定 8 字节）
        {
            __u8 *hdr = *trans_data;
            if ((void *)(hdr + 8) > data_end)
                return IPPROTO_NONE;
            nexthdr = hdr[0];
            *trans_data += 8;
            break;
        }
        default:
            // TCP / UDP / ICMPv6 / 其他：停止遍历
            return nexthdr;
        }
    }
    return nexthdr;
}

// ============================================================
// 主 XDP 程序
// ============================================================
SEC("xdp")
int xdp_port_whitelist(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // --- 1. 解析以太网层 ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // --- 2. IPv4 ---
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        __u32 ip_hlen = ip->ihl * 4;
        if (ip_hlen < sizeof(*ip))
            return XDP_PASS;

        void *trans_data = (void *)ip + ip_hlen;

        // 修复4：检查传输层起始地址合法性
        if (trans_data >= data_end)
            return XDP_PASS;

        switch (ip->protocol) {
        case IPPROTO_TCP:
            return check_tcp(trans_data, data_end);
        case IPPROTO_UDP:
            return check_udp(trans_data, data_end);
        default:
            // ICMP 等其他协议放行（保持 Ping 可达）
            return XDP_PASS;
        }
    }

    // --- 3. IPv6 ---
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end)
            return XDP_PASS;

        void *trans_data = (void *)(ipv6 + 1);

        // 修复3：跳过扩展头，找到真正的传输层协议
        __u8 nexthdr = skip_ipv6_exthdr(&trans_data, data_end, ipv6->nexthdr);
        if (nexthdr == IPPROTO_NONE)
            return XDP_PASS;

        if (trans_data >= data_end)
            return XDP_PASS;

        switch (nexthdr) {
        case IPPROTO_TCP:
            return check_tcp(trans_data, data_end);
        case IPPROTO_UDP:
            return check_udp(trans_data, data_end);
        default:
            // ICMPv6（包括 NDP 邻居发现）必须放行，否则 IPv6 网络瘫痪
            return XDP_PASS;
        }
    }

    // --- 4. 非 IP 流量放行（ARP 等）---
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
