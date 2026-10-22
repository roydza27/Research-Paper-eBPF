#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int B03_branch_depth(struct xdp_md *ctx)
{
    __u32 len = ctx->data_end - ctx->data;
    if (ctx->ingress_ifindex & 1) {
        if (len & 1)
            return XDP_PASS;
        return XDP_PASS;
    }
    if (len > 128)
        return XDP_PASS;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
