#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int d5(struct xdp_md *ctx)
{
    __u64 t = bpf_ktime_get_ns();
    if ((t & 15) == 15) {
        static const char fmt[] = "d5_violation\n";
        bpf_trace_printk(fmt, sizeof(fmt));
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
