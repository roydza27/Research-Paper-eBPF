#!/usr/bin/env python3
"""
Phase 5 Corpus Generator
Authors the 24 eBPF validation programs across Categories A, B, C, D:
- Category A (A1-A6): Abstractly Provable Compliant (Target paths: 1, 1, 1, 4, 16, 64)
- Category B (B1-B6): Abstractly Uncertain, Symbolically Compliant (Target paths: 2, 2, 4, 8, 16, 32)
- Category C (C1-C6): Abstractly Provable Violation (Target paths: 1, 1, 2, 8, 16, 32)
- Category D (D1-D6): Symbolically Discovered Violation (Target paths: 2, 2, 4, 8, 16, 32)
"""

from pathlib import Path

PROGRAMS_DIR = Path(__file__).resolve().parents[1] / "corpus" / "phase5" / "programs"
PROGRAMS_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------
# Category A: Abstractly Provable Compliant (A1-A6)
# ---------------------------------------------------------

# A1: Minimal XDP, 1 path, returns XDP_PASS
A1_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a1(struct xdp_md *ctx)
{
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# A2: Register arithmetic, 1 path, returns XDP_PASS
A2_SRC = """#include <linux/bpf.h>
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
"""

# A3: Permitted helper bpf_ktime_get_ns(), 1 path, returns XDP_PASS
A3_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a3(struct xdp_md *ctx)
{
    volatile __u64 t = bpf_ktime_get_ns();
    (void)t;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# A4: Permitted helper with 2 orthogonal bit branches (4 paths), returns XDP_PASS
A4_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# A5: Permitted helper with 4 orthogonal bit branches (16 paths), returns XDP_PASS
A5_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a5(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if (t & (1ULL << 3))
        *p ^= 8;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# A6: Permitted helper with 6 orthogonal bit branches (64 paths), returns XDP_PASS
A6_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int a6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if (t & (1ULL << 3))
        *p ^= 8;

    if (t & (1ULL << 4))
        *p ^= 16;

    if (t & (1ULL << 5))
        *p ^= 32;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# ---------------------------------------------------------
# Category B: Abstractly Uncertain, Symbolically Compliant (B1-B6)
# Returns 1 (XDP_DROP) or 2 (XDP_PASS) based on unresolved conditions
# ---------------------------------------------------------

# B1: 2 paths, returns XDP_DROP or XDP_PASS based on t & 1
B1_SRC = """#include <linux/bpf.h>
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
"""

# B2: 2 paths, packet payload check returning XDP_DROP or XDP_PASS
B2_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int b2(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 1)) {
        *p ^= 2;
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# B3: 4 paths, 2 orthogonal branches returning XDP_DROP or XDP_PASS
B3_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int b3(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if ((t & 3) == 3)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# B4: 8 paths, 3 orthogonal branches returning XDP_DROP or XDP_PASS
B4_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int b4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if ((t & 7) == 7)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# B5: 16 paths, 4 orthogonal branches returning XDP_DROP or XDP_PASS
B5_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int b5(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if (t & (1ULL << 3))
        *p ^= 8;

    if ((t & 15) == 15)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# B6: 32 paths, 5 orthogonal branches returning XDP_DROP or XDP_PASS
B6_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int b6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if (t & (1ULL << 3))
        *p ^= 8;

    if (t & (1ULL << 4))
        *p ^= 16;

    if ((t & 31) == 31)
        return XDP_DROP;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# ---------------------------------------------------------
# Category C: Abstractly Provable Violation (C1-C6)
# Unconditionally calls forbidden helper or returns forbidden code
# ---------------------------------------------------------

# C1: 1 path, unconditionally calls forbidden helper bpf_get_prandom_u32()
C1_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c1(struct xdp_md *ctx)
{
    __u32 r = bpf_get_prandom_u32();
    (void)r;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# C2: 1 path, unconditionally returns forbidden code XDP_TX (3)
C2_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c2(struct xdp_md *ctx)
{
    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
"""

# C3: 2 paths, calls forbidden helper bpf_trace_printk unconditionally on all paths
C3_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c3(struct xdp_md *ctx)
{
    static const char fmt[] = "violation\\n";
    bpf_trace_printk(fmt, sizeof(fmt));
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# C4: 8 paths, all paths call forbidden helper bpf_get_prandom_u32()
C4_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c4(struct xdp_md *ctx)
{
    __u32 r = bpf_get_prandom_u32();
    (void)r;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# C5: 16 paths, all paths call forbidden helper bpf_trace_printk()
C5_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c5(struct xdp_md *ctx)
{
    static const char fmt[] = "c5_log\\n";
    bpf_trace_printk(fmt, sizeof(fmt));

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if (t & (1ULL << 3))
        *p ^= 8;

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# C6: 32 paths, all paths unconditionally return forbidden code XDP_TX (3)
C6_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int c6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_TX;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if (t & (1ULL << 3))
        *p ^= 8;

    if (t & (1ULL << 4))
        *p ^= 16;

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
"""

# ---------------------------------------------------------
# Category D: Symbolically Discovered Violation (D1-D6)
# Violation reachable only along a conditional branch
# ---------------------------------------------------------

# D1: 2 paths, conditional return XDP_TX (3) on t & 1
D1_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int d1(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & 1) {
        *p ^= 1;
        return XDP_TX;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# D2: 2 paths, conditional call to forbidden helper bpf_get_prandom_u32()
D2_SRC = """#include <linux/bpf.h>
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
"""

# D3: 4 paths, conditional return XDP_TX (3) on (t & 3) == 3
D3_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int d3(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if ((t & 3) == 3) {
        *p ^= 4;
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# D4: 8 paths, conditional call to forbidden helper on (t & 7) == 7
D4_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int d4(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if ((t & 7) == 7)
        bpf_get_prandom_u32();

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# D5: 16 paths, conditional return XDP_TX (3) on (t & 15) == 15
D5_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int d5(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if (t & (1ULL << 3))
        *p ^= 8;

    if ((t & 15) == 15) {
        *p ^= 16;
        return XDP_TX;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

# D6: 32 paths, conditional call to forbidden helper on (t & 31) == 31
D6_SRC = """#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int d6(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    if (t & (1ULL << 0))
        *p ^= 1;

    if (t & (1ULL << 1))
        *p ^= 2;

    if (t & (1ULL << 2))
        *p ^= 4;

    if (t & (1ULL << 3))
        *p ^= 8;

    if (t & (1ULL << 4))
        *p ^= 16;

    if ((t & 31) == 31)
        bpf_get_prandom_u32();

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
"""

PROGRAMS = {
    "a1": A1_SRC,
    "a2": A2_SRC,
    "a3": A3_SRC,
    "a4": A4_SRC,
    "a5": A5_SRC,
    "a6": A6_SRC,
    "b1": B1_SRC,
    "b2": B2_SRC,
    "b3": B3_SRC,
    "b4": B4_SRC,
    "b5": B5_SRC,
    "b6": B6_SRC,
    "c1": C1_SRC,
    "c2": C2_SRC,
    "c3": C3_SRC,
    "c4": C4_SRC,
    "c5": C5_SRC,
    "c6": C6_SRC,
    "d1": D1_SRC,
    "d2": D2_SRC,
    "d3": D3_SRC,
    "d4": D4_SRC,
    "d5": D5_SRC,
    "d6": D6_SRC,
}


def main():
    print(f"Generating 24 Phase 5 validation programs in {PROGRAMS_DIR}...")
    for prog_id, src in sorted(PROGRAMS.items()):
        file_path = PROGRAMS_DIR / f"{prog_id}.c"
        with open(file_path, "w") as f:
            f.write(src)
        print(f"  Written: {file_path.name}")
    print(f"Successfully generated all {len(PROGRAMS)} programs.")


if __name__ == "__main__":
    main()
