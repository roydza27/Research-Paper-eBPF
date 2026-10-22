#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int B03_branch_depth(struct xdp_md *ctx)
{
    __u32 len = ctx->data_end - ctx->data;
    volatile __u64 stamp = 0;
    if (ctx->ingress_ifindex & 1) {
        stamp = bpf_ktime_get_ns();
        if (len & 1)
            stamp ^= bpf_ktime_get_ns();
    } else if (len > 128) {
        stamp = bpf_ktime_get_ns();
    }
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
