#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int asize_0032(struct xdp_md *ctx)
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

    x ^= (__u64)1;
    x ^= (__u64)2;
    x ^= (__u64)3;
    x ^= (__u64)4;
    x ^= (__u64)5;
    x ^= (__u64)6;
    x ^= (__u64)7;
    x ^= (__u64)8;
    x ^= (__u64)9;
    x ^= (__u64)10;
    x ^= (__u64)11;
    x ^= (__u64)12;
    x ^= (__u64)13;
    x ^= (__u64)14;
    x ^= (__u64)15;
    x ^= (__u64)16;
    x ^= (__u64)17;
    x ^= (__u64)18;
    x ^= (__u64)19;
    x ^= (__u64)20;
    x ^= (__u64)21;
    x ^= (__u64)22;
    x ^= (__u64)23;
    x ^= (__u64)24;
    x ^= (__u64)25;
    x ^= (__u64)26;
    x ^= (__u64)27;
    x ^= (__u64)28;
    x ^= (__u64)29;
    x ^= (__u64)30;
    x ^= (__u64)31;
    x ^= (__u64)32;
    (void)x;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
