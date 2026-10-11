#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int asize_0128(struct xdp_md *ctx)
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
    x ^= (__u64)65;
    x ^= (__u64)66;
    x ^= (__u64)67;
    x ^= (__u64)68;
    x ^= (__u64)69;
    x ^= (__u64)70;
    x ^= (__u64)71;
    x ^= (__u64)72;
    x ^= (__u64)73;
    x ^= (__u64)74;
    x ^= (__u64)75;
    x ^= (__u64)76;
    x ^= (__u64)77;
    x ^= (__u64)78;
    x ^= (__u64)79;
    x ^= (__u64)80;
    x ^= (__u64)81;
    x ^= (__u64)82;
    x ^= (__u64)83;
    x ^= (__u64)84;
    x ^= (__u64)85;
    x ^= (__u64)86;
    x ^= (__u64)87;
    x ^= (__u64)88;
    x ^= (__u64)89;
    x ^= (__u64)90;
    x ^= (__u64)91;
    x ^= (__u64)92;
    x ^= (__u64)93;
    x ^= (__u64)94;
    x ^= (__u64)95;
    x ^= (__u64)96;
    x ^= (__u64)97;
    x ^= (__u64)98;
    x ^= (__u64)99;
    x ^= (__u64)100;
    x ^= (__u64)101;
    x ^= (__u64)102;
    x ^= (__u64)103;
    x ^= (__u64)104;
    x ^= (__u64)105;
    x ^= (__u64)106;
    x ^= (__u64)107;
    x ^= (__u64)108;
    x ^= (__u64)109;
    x ^= (__u64)110;
    x ^= (__u64)111;
    x ^= (__u64)112;
    x ^= (__u64)113;
    x ^= (__u64)114;
    x ^= (__u64)115;
    x ^= (__u64)116;
    x ^= (__u64)117;
    x ^= (__u64)118;
    x ^= (__u64)119;
    x ^= (__u64)120;
    x ^= (__u64)121;
    x ^= (__u64)122;
    x ^= (__u64)123;
    x ^= (__u64)124;
    x ^= (__u64)125;
    x ^= (__u64)126;
    x ^= (__u64)127;
    x ^= (__u64)128;
    (void)x;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
