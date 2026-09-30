#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int b1(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & 1) {
        *p ^= 1;
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
