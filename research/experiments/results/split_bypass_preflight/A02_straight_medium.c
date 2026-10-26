#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int A02_straight_medium(struct xdp_md *ctx)
{
    volatile __u32 n = ctx->data_end - ctx->data;
    n = (n * 3) + 1;
    n = (n * 4) + 2;
    n = (n * 5) + 3;
    n = (n * 6) + 4;
    n = (n * 2) + 5;
    n = (n * 3) + 6;
    n = (n * 4) + 0;
    n = (n * 5) + 1;
    n = (n * 6) + 2;
    n = (n * 2) + 3;
    n = (n * 3) + 4;
    n = (n * 4) + 5;
    n = (n * 5) + 6;
    n = (n * 6) + 0;
    n = (n * 2) + 1;
    n = (n * 3) + 2;
    n = (n * 4) + 3;
    n = (n * 5) + 4;
    n = (n * 6) + 5;
    n = (n * 2) + 6;
    n = (n * 3) + 0;
    n = (n * 4) + 1;
    n = (n * 5) + 2;
    n = (n * 6) + 3;
    return n & 1 ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
