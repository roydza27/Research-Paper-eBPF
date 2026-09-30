#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c2(struct xdp_md *ctx)
{
    __u32 x = ctx->data_end - ctx->data;
    x = (x * 3) + 7;
    static const char fmt[] = "c2_violation\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
