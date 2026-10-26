#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int B01_branch_safe(struct xdp_md *ctx)
{
    __u32 len = ctx->data_end - ctx->data;
    if (len & 1)
        return XDP_PASS;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
