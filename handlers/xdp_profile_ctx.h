#pragma once
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define XDP_PROFILE_MINECRAFT 1

struct xdp_profile_ctx {
    __u64 policy_generation;
    __u64 profile_generation;
    __u32 profile_id;
    __u32 _pad;
};

/* Written by the admission program immediately before profile dispatch. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_profile_ctx);
} profile_ctx_map SEC(".maps");

static __always_inline struct xdp_profile_ctx *get_profile_ctx(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&profile_ctx_map, &key);
}
