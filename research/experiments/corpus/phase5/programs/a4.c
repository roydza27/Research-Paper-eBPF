#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a4(struct xdp_md *ctx)
{
    __u64 t1 = bpf_ktime_get_ns();
    __u64 t2 = bpf_ktime_get_ns();
    volatile __u64 diff = t2 - t1;
    (void)diff;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
