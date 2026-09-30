#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int e1_p1(struct xdp_md *ctx)
{
    __u32 x = ctx->ingress_ifindex;
    __u32 y = x * 3 + 7;
    return y == 0 ? XDP_ABORTED : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
