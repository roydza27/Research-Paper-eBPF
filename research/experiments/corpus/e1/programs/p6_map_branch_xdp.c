#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} e1_state SEC(".maps");

SEC("xdp")
int e1_p6(struct xdp_md *ctx)
{
    __u32 key = ctx->ingress_ifindex & 3;
    __u64 *value = bpf_map_lookup_elem(&e1_state, &key);
    if (!value)
        return XDP_ABORTED;
    if (*value > 100)
        return XDP_DROP;
    if (*value > 50)
        return XDP_TX;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
