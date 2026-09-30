#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a5(struct xdp_md *ctx)
{
    __u64 t1 = bpf_ktime_get_ns();
    __u64 t2 = bpf_ktime_get_ns();
    __u64 t3 = bpf_ktime_get_ns();
    __u64 t4 = bpf_ktime_get_ns();
    volatile __u64 acc = (t2 - t1) + (t4 - t3);
    (void)acc;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
