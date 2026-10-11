#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int csize_0064(struct xdp_md *ctx)
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
    x ^= (__u64)33;
    x ^= (__u64)34;
    x ^= (__u64)35;
    x ^= (__u64)36;
    x ^= (__u64)37;
    x ^= (__u64)38;
    x ^= (__u64)39;
    x ^= (__u64)40;
    x ^= (__u64)41;
    x ^= (__u64)42;
    x ^= (__u64)43;
    x ^= (__u64)44;
    x ^= (__u64)45;
    x ^= (__u64)46;
    x ^= (__u64)47;
    x ^= (__u64)48;
    x ^= (__u64)49;
    x ^= (__u64)50;
    x ^= (__u64)51;
    x ^= (__u64)52;
    x ^= (__u64)53;
    x ^= (__u64)54;
    x ^= (__u64)55;
    x ^= (__u64)56;
    x ^= (__u64)57;
    x ^= (__u64)58;
    x ^= (__u64)59;
    x ^= (__u64)60;
    x ^= (__u64)61;
    x ^= (__u64)62;
    x ^= (__u64)63;
    x ^= (__u64)64;
    bpf_trace_printk("scaling", 7);
    (void)x;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
