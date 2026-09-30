#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_ktime_branch_constant_return(struct xdp_md *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    volatile __u64 marker;

    if (now == 0)
        marker = 1;
    else
        marker = 2;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
