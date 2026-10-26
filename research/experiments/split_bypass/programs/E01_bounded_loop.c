#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int E01_bounded_loop(struct xdp_md *ctx)
{
    volatile __u32 acc = ctx->ingress_ifindex;
    __u32 i = 0;
#pragma clang loop unroll(disable)
    for (i = 0; i < 8; i++)
        acc = (acc * 3) ^ i;
    return acc & 1 ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
