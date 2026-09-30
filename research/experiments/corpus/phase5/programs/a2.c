#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a2(struct xdp_md *ctx)
{
    __u32 x = ctx->data_end - ctx->data;
    x = (x * 3) + 7;
    if (x == 0) {
        // Dead code path that never executes for positive length
        return XDP_PASS;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
