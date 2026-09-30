#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int e1_p3(struct xdp_md *ctx)
{
    __u32 x = ctx->ingress_ifindex;
    if (x & 1)
        return XDP_PASS;
    if (x & 2)
        return XDP_DROP;
    if (x & 4)
        return XDP_TX;
    if (x & 8)
        return XDP_ABORTED;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
