#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} state SEC(".maps");

SEC("xdp")
int xdp_map_value_compare(struct xdp_md *ctx)
{
    __u32 key = 0;
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
