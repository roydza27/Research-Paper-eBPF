#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c1(struct xdp_md *ctx)
{
    static const char fmt[] = "c1_violation\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
