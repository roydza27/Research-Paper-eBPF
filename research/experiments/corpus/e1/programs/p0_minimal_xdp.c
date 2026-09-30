#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int e1_p0(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
