#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int C02_join_policy_sensitive(struct xdp_md *ctx)
{
    volatile __u32 joined;
    if (ctx->ingress_ifindex & 1)
        joined = 0;
    else
        joined = 1;
    if (joined)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
