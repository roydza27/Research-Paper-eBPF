#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int asize_0000(struct xdp_md *ctx)
{
    /*
     * Keep one small volatile scalar on the BPF stack. Each generated
     * update must survive -O2, while the stack footprint stays constant.
     * This gives us straight-line instruction growth without introducing
     * extra symbolic branches, packet-data loads, or helper calls.
     */
    /*
     * Seed the volatile stack slot from a context field so initialization is
     * represented as a normal register-to-stack store. The accumulator is
     * intentionally independent of the final return value: size scaling must
     * increase straight-line verifier work without turning the fast-path
     * verdict into UNKNOWN merely because stack contents are not abstractly
     * value-precise.
     */
    volatile __u64 x = 0;

    (void)x;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
