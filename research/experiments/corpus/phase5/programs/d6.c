#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int d6(struct xdp_md *ctx)
{
    __u64 t = bpf_ktime_get_ns();
    if ((t & 31) == 31) {
        static const char fmt[] = "d6_violation\n";
        bpf_trace_printk(fmt, sizeof(fmt));
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
