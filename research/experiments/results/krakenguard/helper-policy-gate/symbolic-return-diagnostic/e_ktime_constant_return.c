#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_ktime_constant_return(struct xdp_md *ctx)
{
    volatile __u64 now = bpf_ktime_get_ns();
    (void)now;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
