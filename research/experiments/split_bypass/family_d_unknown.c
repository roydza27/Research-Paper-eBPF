#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int split_bypass_family_d(struct xdp_md *ctx)
{
    /* The branch condition is input-derived; analyzer behavior must be measured. */
    __u32 ingress = ctx->ingress_ifindex;
    if (ingress > 7)
        return XDP_PASS;
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
