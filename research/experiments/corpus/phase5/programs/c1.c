#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c1(struct xdp_md *ctx)
{
    __u32 r = bpf_get_prandom_u32();
    (void)r;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
