#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int split_bypass_family_e(struct xdp_md *ctx)
{
    volatile __u32 limit = ctx->ingress_ifindex & 3;
    __u32 count = 0;

#pragma clang loop unroll(disable)
    for (int i = 0; i < 4; i++) {
        count += 1;
        if (count >= limit)
            break;
    }

    return count == 0xffffffff ? XDP_DROP : XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
