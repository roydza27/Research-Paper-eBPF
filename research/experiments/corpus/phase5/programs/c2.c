#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c2(struct xdp_md *ctx)
{
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
