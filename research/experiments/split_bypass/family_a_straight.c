#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int split_bypass_family_a(struct xdp_md *ctx)
{
    __u32 value = ctx->ingress_ifindex;
    value += 3;
    value ^= 1;
    value &= 0xffff;
    return value == 0xffffffff ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
