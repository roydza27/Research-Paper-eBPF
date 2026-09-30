#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_atomic_stack(struct xdp_md *ctx)
{
    __u64 counter = 0;
    __sync_fetch_and_add(&counter, 1);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
