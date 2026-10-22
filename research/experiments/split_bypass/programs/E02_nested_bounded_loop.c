#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int E02_nested_bounded_loop(struct xdp_md *ctx)
{
    volatile __u32 acc = ctx->ingress_ifindex;
    __u32 i = 0;
    __u32 j = 0;
#pragma clang loop unroll(disable)
    for (i = 0; i < 3; i++) {
#pragma clang loop unroll(disable)
        for (j = 0; j < 4; j++)
            acc = (acc + i) ^ j;
    }
    return acc & 1 ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
