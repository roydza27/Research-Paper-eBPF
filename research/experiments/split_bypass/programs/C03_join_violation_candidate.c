#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int C03_join_violation_candidate(struct xdp_md *ctx)
{
    volatile __u32 joined;
    if (ctx->ingress_ifindex & 1)
        joined = 0;
    else
        joined = 1;
    if (joined == 1)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
