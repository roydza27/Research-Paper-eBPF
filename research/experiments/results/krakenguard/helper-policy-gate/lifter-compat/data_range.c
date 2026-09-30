#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_data_range(struct xdp_md *ctx)
{
    if (ctx->data_end - ctx->data > 64)
        return XDP_PASS;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
