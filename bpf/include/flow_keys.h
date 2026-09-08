#pragma once
#include <linux/types.h>

#define CT_FAMILY_IPV4 2
#define CT_FAMILY_IPV6 10

/* Shared map/key ABI used by the base program and protection handlers. */
struct flow_key {
    __u8 family;
    __u8 pad[3];
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
