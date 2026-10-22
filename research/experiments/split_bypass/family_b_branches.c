#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int split_bypass_family_b(struct xdp_md *ctx)
{
    if (ctx->ingress_ifindex & 1)
        return XDP_PASS;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
