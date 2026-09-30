#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_ktime_symbolic_return(struct xdp_md *ctx)
{
    __u64 now = bpf_ktime_get_ns();

    if (now == 0)
        return XDP_ABORTED;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
