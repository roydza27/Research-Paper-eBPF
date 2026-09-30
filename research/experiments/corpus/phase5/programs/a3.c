#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a3(struct xdp_md *ctx)
{
    volatile __u64 t = bpf_ktime_get_ns();
    (void)t;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
