#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int A01_straight_small(struct xdp_md *ctx)
{
    __u32 n = ctx->data_end - ctx->data;
    n += 1;
    n ^= 3;
    return (n & 1) ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
