#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int B02_branch_policy_sensitive(struct xdp_md *ctx)
{
    __u64 now = bpf_ktime_get_ns();
    if (now & 1)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
