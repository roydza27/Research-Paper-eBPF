#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int e1_p2(struct xdp_md *ctx)
{
    __u32 x = ctx->ingress_ifindex;
    if (x & 1)
        return XDP_PASS;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
