#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} e1_map SEC(".maps");

SEC("xdp")
int e1_p5(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&e1_map, &key);
    if (value)
        return XDP_PASS;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
