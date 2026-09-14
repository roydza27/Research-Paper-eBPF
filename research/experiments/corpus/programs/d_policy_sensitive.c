#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} policy_state SEC(".maps");

SEC("xdp")
int xdp_policy_sensitive(struct xdp_md *ctx)
{
    __u32 key = 0;
    __u64 *state = bpf_map_lookup_elem(&policy_state, &key);
    if (!state)
        return XDP_ABORTED;

    if (ctx->data_end - ctx->data > 64) {
        __u64 now = bpf_ktime_get_ns();
        *state = now;
        return XDP_PASS;
    }

    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
