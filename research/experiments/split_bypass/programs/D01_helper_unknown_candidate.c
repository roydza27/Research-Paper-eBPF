#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int D01_helper_unknown_candidate(struct xdp_md *ctx)
{
    __u32 value = bpf_get_prandom_u32();
    if (value == 0x13579)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
