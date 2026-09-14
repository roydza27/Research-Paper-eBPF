#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} state SEC(".maps");

static __always_inline __u32 classify(__u32 x)
{
    if (x & 1)
        return 1;
    if (x & 2)
        return 2;
    if (x & 4)
        return 3;
    return 0;
}

SEC("xdp")
int xdp_branching_maps(struct xdp_md *ctx)
{
    __u32 key = classify(ctx->ingress_ifindex);
    __u64 *value = bpf_map_lookup_elem(&state, &key);
    if (!value)
        return XDP_ABORTED;
    if (*value > 100)
        return XDP_DROP;
    if (*value > 50)
        return XDP_TX;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
