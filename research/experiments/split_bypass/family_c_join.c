#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int split_bypass_family_c(struct xdp_md *ctx)
{
    __u32 value;
    if (ctx->ingress_ifindex & 1)
        value = 1;
    else
        value = 2;

    /* The value reaches a shared join and affects the terminal result. */
    if (value == 1)
        return XDP_PASS;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
