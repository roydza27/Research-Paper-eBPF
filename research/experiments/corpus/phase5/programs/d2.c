#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int d2(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 1)) {
        *p ^= 2;
        bpf_get_prandom_u32();
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
