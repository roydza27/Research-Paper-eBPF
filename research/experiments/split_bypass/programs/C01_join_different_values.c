#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int C01_join_different_values(struct xdp_md *ctx)
{
    volatile __u32 joined;
    if ((ctx->data_end - ctx->data) & 1)
        joined = 1;
    else
        joined = 2;
    if (joined == 1)
        return XDP_PASS;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
