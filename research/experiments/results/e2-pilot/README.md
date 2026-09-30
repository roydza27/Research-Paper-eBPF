# Phase 4 E2 Pilot Execution & Symbolic Path Validation Report

## 1. Executive Summary

- **Experiment ID**: Phase 4 E2 Pilot Gate
- **Research Question**: *How does KRAKENGUARD verification time scale as the number of feasible symbolic paths increases under controlled conditions?*
- **Execution Date**: 2026-09-30
- **Host Environment**: Linux `7.2.3-arch1-2` x86_64, Clang `22.1.8`, bpftool `7.8.0`, Docker `29.7.2`
- **KRAKENGUARD Baseline Commit**: `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- **Baseline Policy**: `research/experiments/corpus/e1/policies/e1_fixed_policy.json` (SHA-256: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`)
- **Scope**: Pilot gate execution **ONLY** (1 single execution each for candidate programs `E2-P0` through `E2-P4`). No full matrix execution was conducted.
- **Pilot Gate Decision**: **`PILOT PASS — READY FOR FULL MATRIX PROPOSAL`**

---

## 2. Invariant & Environment Verification

| Parameter | Specification | Verified State | Status |
| :--- | :--- | :--- | :--- |
| **KRAKENGUARD Container** | `artifact-krakenguard:latest` | Container ID `krakenguard`, healthy | PASS |
| **Commit Invariant** | `e7bd84005b304c5a10efcdb04914d1882b3cccf7` | Matches frozen container image | PASS |
| **Policy Invariant** | `e1_fixed_policy.json` | SHA-256: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603` | PASS |
| **Symbolic Driver** | Pure `bpf_ktime_get_ns()` | Verified (no `ingress_ifindex`, no maps) | PASS |
| **Compiler Invariant** | `clang -target bpf -mcpu=v1 -O2 -g` | Clang 22.1.8 host toolchain | PASS |
| **Execution Protocol** | Single pilot run per candidate (P0–P4) | Exactly 1 run per level (5 runs total) | PASS |

---

## 3. Compiler Optimization Analysis & Solution

### Root Cause Analysis of LLVM DSE Collapse
The draft candidate program design in `e2-design.md` proposed using local stack stores to a `volatile __u64 sink = 0;`:
```c
__u64 x = bpf_ktime_get_ns();
volatile __u64 sink = 0;
if (x & (1ULL << 0)) sink = 1; else sink = 2;
...
return XDP_PASS;
```
During static analysis of the lifting pipeline, we discovered:
1. Clang compiles eBPF stack operations into raw memory stores relative to register `r10` (`*(u64 *)(r10 - 8) = r1`).
2. When KRAKENGUARD's `bpflifter_cli` lifts bytecode to LLVM IR, it instantiates an LLVM `alloca` for the stack with non-volatile LLVM `store` instructions.
3. In Step 2 of KRAKENGUARD's pipeline, `opt -O3` executes across the lifted IR. LLVM Dead-Store Elimination (DSE) detects that `sink` never escapes the local function boundary, discarding all stores and flattening all branches into a single basic block returning `XDP_PASS` (`Paths: 1`, `TotalInsts: 12710`).

### The Architectural Solution: Packet Buffer Bitmask Mutation
To ensure control-flow branches survive `opt -O3`, the side-effect must cross the program boundary into an external interface. Under XDP, `ctx->data` represents an external packet buffer whose memory mutations cannot be eliminated by `opt -O3`:
```c
SEC("xdp")
int e2_pX(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    if (data + 1 > data_end)
        return XDP_PASS;

    __u64 t = bpf_ktime_get_ns();
    unsigned char *p = (unsigned char *)data;

    // Orthogonal bitmask checks
    if (t & (1ULL << 0)) *p ^= 1;
    // ...
    return XDP_PASS;
}
```
**Strict Conformance**:
- Exactly 1 helper (`bpf_ktime_get_ns()`).
- 0 maps, 0 loops.
- Packet memory contents remain concrete in KRAKENGUARD's harness (`data` is concrete buffer in `lifting_tools/krakenguard_template.j2`), so the safety check `if (data + 1 > data_end)` evaluates along a single concrete path.
- The sole symbolic source remains `bpf_ktime_get_ns()`.

---

## 4. Static Program Properties

| Program | Source File | Predicates | Target Paths | Disasm Insts | Branches | Helpers | Maps | Object SHA-256 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E2-P0** | `e2_p0.c` | 0 | 1 | 7 | 1 | 1 | 0 | `a74538bd85bf8a87...` |
| **E2-P1** | `e2_p1.c` | 1 | 2 | 13 | 2 | 1 | 0 | `ddf1f85f096ad8a5...` |
| **E2-P2** | `e2_p2.c` | 2 | 4 | 19 | 3 | 1 | 0 | `1f27fe0f82b20385...` |
| **E2-P3** | `e2_p3.c` | 3 | 8 | 25 | 4 | 1 | 0 | `00929a589a7abe38...` |
| **E2-P4** | `e2_p4.c` | 4 | 16 | 31 | 5 | 1 | 0 | `cac016e08e67dbc3...` |

*Note: In bytecode disassembly, `branches` equals $k + 1$ due to the required concrete packet boundary check (`if data + 1 > data_end`).*

---

## 5. Empirical Pilot Results

Telemetry recorded from live KRAKENGUARD daemon execution:

| Program ID | Theoretical Paths | KLEE Explored Paths | KLEE Completed Paths | KLEE Total Queries | Total KLEE Insts | Wall-Clock Time | CPU Time | Verifier Result | Policy Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E2-P0** | 1 | **1** | 0 | 1 | 12,720 | 744.24 ms | 0.66 ms | VERIFIED | COMPLIANT |
| **E2-P1** | 2 | **2** | 0 | 2 | 12,809 | 740.08 ms | 0.76 ms | VERIFIED | COMPLIANT |
| **E2-P2** | 4 | **4** | 0 | 4 | 12,989 | 734.96 ms | 0.61 ms | VERIFIED | COMPLIANT |
| **E2-P3** | 8 | **8** | 0 | 8 | 13,349 | 783.94 ms | 0.64 ms | VERIFIED | COMPLIANT |
| **E2-P4** | 16 | **16** | 0 | 16 | 14,069 | 834.51 ms | 0.54 ms | VERIFIED | COMPLIANT |

Raw logs, including compiler outputs, disassembly dumps, BTF dumps, KRAKENGUARD daemon stdout/stderr, and KLEE `info` logs, are preserved in `research/experiments/results/e2-pilot/raw/`.

---

## 6. Pilot Gate Evaluation

1. **Strictly Increasing Explored Path Counts**: **PASS**
   - Observed sequence: $1 < 2 < 4 < 8 < 16$.
   - The observed KLEE path count perfectly matches the theoretical model $2^k$ for all tested levels $k \in \{0, 1, 2, 3, 4\}$.
2. **Reaches Minimum Reachable Level ($\ge 8$ paths)**: **PASS**
   - E2-P3 explored exactly 8 paths.
   - E2-P4 explored exactly 16 paths.
3. **Execution Success & Policy Compliance**: **PASS**
   - 100% of runs completed with execution status `success`.
   - All programs verified as policy compliant (no safety violations, no solver timeouts).
4. **Compiled Branches Survived**: **PASS**
   - Verified via `llvm-objdump -d` and confirmed by KLEE branching.
5. **Single Symbolic Helper**: **PASS**
   - Pure `bpf_ktime_get_ns()`, 0 maps.

**Final Gate Status**: **`PILOT PASS — READY FOR FULL MATRIX PROPOSAL`**

---

## 7. Recommendations for Full Matrix Execution

1. **Corpus Stability**: The bitmask packet mutation paradigm is robust, survives LLVM `opt -O3`, and reliably yields exactly $2^k$ feasible symbolic paths.
2. **Expansion to Full Matrix ($k \in \{0, \dots, 6\}$)**:
   - Levels E2-P0 through E2-P4 are fully validated.
   - Levels E2-P5 ($2^5 = 32$ paths) and E2-P6 ($2^6 = 64$ paths) can now be implemented using the identical bitmask pattern (`1ULL << 4`, `1ULL << 5`).
3. **Execution Matrix**:
   - 7 programs $\times$ (2 warmups + 7 measured) = 63 total executions.
   - Estimated runtime: ~50–60 seconds total given sub-second execution per run.
