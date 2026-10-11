#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int dpath_p016(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    volatile __u8 *p = (volatile __u8 *)data;
    if (t & (1ULL << 0)) {
        *p ^= (__u8)1;
        bpf_trace_printk("scaling", 7);
    }
    if (t & (1ULL << 1)) {
        *p ^= (__u8)2;
    }
    if (t & (1ULL << 2)) {
        *p ^= (__u8)4;
    }
    if (t & (1ULL << 3)) {
        *p ^= (__u8)8;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
