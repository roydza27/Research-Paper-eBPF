#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int A03_helper_clock(struct xdp_md *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    __u32 len = ctx->data_end - ctx->data;
    return ((now ^ len) & 1) ? XDP_PASS : XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
