#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_adversarial_helper(struct xdp_md *ctx)
{
    /* Synthetic policy-violation case: this helper can be forbidden by policy. */
    __u64 now = bpf_ktime_get_ns();
    if (now == 0)
        return XDP_ABORTED;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
