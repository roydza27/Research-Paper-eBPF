#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c4(struct xdp_md *ctx)
{
    __u64 t = bpf_ktime_get_ns();
    (void)t;
    static const char fmt[] = "c4_violation\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
