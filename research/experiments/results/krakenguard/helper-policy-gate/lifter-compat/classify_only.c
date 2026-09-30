#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

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
int xdp_classify_only(struct xdp_md *ctx)
{
    __u32 key = classify(ctx->ingress_ifindex);
    if (key == 1)
        return XDP_PASS;
    if (key == 2)
        return XDP_DROP;
    if (key == 3)
        return XDP_TX;
    return XDP_ABORTED;
}

char LICENSE[] SEC("license") = "GPL";
