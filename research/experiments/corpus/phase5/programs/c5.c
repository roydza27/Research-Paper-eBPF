#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c5(struct xdp_md *ctx)
{
    __u64 t1 = bpf_ktime_get_ns();
    __u64 t2 = bpf_ktime_get_ns();
    volatile __u64 acc = t2 - t1;
    (void)acc;
    static const char fmt[] = "c5_violation\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
