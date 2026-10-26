#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int D02_packet_memory_candidate(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;
    volatile unsigned char value = *(unsigned char *)data;
    if (value == 0x7f)
        return XDP_DROP;
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "GPL";
