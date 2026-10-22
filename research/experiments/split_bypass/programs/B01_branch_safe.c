#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int B01_branch_safe(struct xdp_md *ctx)
{
    __u32 len = ctx->data_end - ctx->data;
    volatile __u64 stamp = 0;
    if (len & 1)
        stamp = bpf_ktime_get_ns();
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
