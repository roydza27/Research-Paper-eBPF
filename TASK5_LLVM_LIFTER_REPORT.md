# Task 5 LLVM Lifter ALU32 Pointer Mismatch Remediation Report

> **Research Topic:** Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification  
> **Date:** 2026-10-22  
> **Branch:** `main` | **HEAD Commit:** `ce2cebe`  
> **Artifacts Produced:**  
> - Standalone Sanitizer: [`research/experiments/split_bypass/scripts/sanitize_lifted_ir.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/sanitize_lifted_ir.py)  
> - Semantics & Regression Tests: [`research/experiments/tests/test_lifter_alu32_semantics.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/tests/test_lifter_alu32_semantics.py) (6 passed)  
> - Patched C++ Lifter Source: [`research/baselines/krakenguard/artifact/bpf_lifter/src/instr_utils.cpp`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/baselines/krakenguard/artifact/bpf_lifter/src/instr_utils.cpp)  
> - Patched Pipeline Script: [`research/baselines/krakenguard/artifact/lifting_tools/generateIR.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/baselines/krakenguard/artifact/lifting_tools/generateIR.py)  
> - Updated Memory: [`MEMORY.md`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/MEMORY.md)

---

## 1. Executive Summary

Task 5 investigated, reproduced, and remediated the LLVM 13 typed pointer mismatch in the KRAKENGUARD LLVM lifter (`bpflifter_cli` + `generateIR.py`). During Task 3, this issue prevented symbolic fallback execution on five corpus fixtures (`A02_straight_medium`, `C01_join_different_values`, `C02_join_policy_sensitive`, `D02_packet_memory_candidate`, and `E01_bounded_loop`), forcing the orchestrator to fail closed as `unresolved`.

### Outcomes:
1. **Root Cause Isolated:** Identified that `emitLoadALUDest` (lines 56–64) and `emitJmpLoadSrcAndDstAndZero` (lines 195–224) in `instr_utils.cpp` directly loaded `i32` from 64-bit register alloca pointers (`i64*`), generating invalid LLVM IR: `load i32, i64* %rX`.
2. **Minimal Source-Level Fix:** Corrected `instr_utils.cpp` to emit `load i64` followed by `trunc i64 to i32` (matching `emitLoadALUSource`), directly producing natively typed LLVM IR.
3. **Defense-in-Depth Sanitization:** Implemented a strictly validated post-processing sanitizer in `sanitize_lifted_ir.py` and integrated it into `generateIR.py`.
4. **Submodule Patch Preservation:** Confirmed that the pre-existing 41-line synthetic map ID patch in `generateIR.py` remains 100% intact.
5. **Empirical Verification:**
   - Locally validated: 6 unit tests in `test_lifter_alu32_semantics.py` passing; 79 total repository tests passing across 5 suites.
   - Container verified: Recompiled `bpflifter_cli` in the KRAKENGUARD container and verified that `generateIR.py` succeeds with exit code 0 across all five previously failing fixtures. `A02_straight_medium` proved `SAFE` via live daemon fallback.

---

## 2. Technical Root Cause & Source Evidence

### A. Register Allocation Model
In `research/baselines/krakenguard/artifact/bpf_lifter/src/Decompiler.cpp:325-330`:
```cpp
for (int i = 0; i <= 10; i++) {
    regs.push_back(builder.CreateAlloca(
        builder.getInt64Ty(),  // Allocates i64* (pointer to i64)
        nullptr,
        "r" + std::to_string(i)));
}
```
All eBPF registers `%r0`..`%r10` are allocated as 64-bit integer slots (`i64*`).

### B. Flawed Destination Read Implementation
In `research/baselines/krakenguard/artifact/bpf_lifter/src/instr_utils.cpp:56-64`:
```cpp
llvm::Value *emitLoadALUDest(const bpf_insn &inst, llvm::Value **regs,
                             llvm::IRBuilder<> &builder, bool dstAlways64)
{
    if (((inst.code & 0x07) == EBPF_CLS_ALU64) || dstAlways64) {
        return builder.CreateLoad(builder.getInt64Ty(), regs[inst.dst_reg]);
    } else {
        // BUG: regs[inst.dst_reg] is i64*, but CreateLoad requests i32Ty
        return builder.CreateLoad(builder.getInt32Ty(), regs[inst.dst_reg]);
    }
}
```
When handling ALU32 instructions, this emitted:
```llvm
  %13 = load i32, i64* %r1, align 4
```
In LLVM 13 typed IR, `load T, Ptr` strictly requires `Ptr` to be of type `T*`. LLVM's `opt -O3` rejected this with:
`error: explicit pointee type doesn't match operand's pointee type (i32 vs i64)`.

The exact same bug existed in `emitJmpLoadSrcAndDstAndZero` (`instr_utils.cpp:202-212`) for conditional JMP32 comparisons.

### C. Why ALU64, ALU32 MOV, and Memory Loads Were Not Affected
- **ALU64:** Explicitly used `builder.getInt64Ty()`, emitting valid `load i64, i64* %rX`.
- **ALU32 MOV (`wX = wY` / `wX = imm`):** Only reads the source register and overwrites the destination. It never calls `emitLoadALUDest`.
- **Memory Loads (`LDX`):** Packet and stack pointers are converted to typed memory pointers (e.g. `i32*`) via `inttoptr` and `bitcast`, emitting valid `load i32, i32* %ptr`.

Thus, `load i32, i64* %rX` is uniquely confined to ALU32 destination reads and JMP32 operand reads.

---

## 3. Minimal Reproduction & Observed Diagnostics

We reproduced the failure on `A02_straight_medium.o` in the container before patching:

### Raw LLVM IR Emitted Before Fix:
```llvm
  %11 = load i32, i32* %10, align 4
  %12 = zext i32 %11 to i64
  store i64 %12, i64* %r1, align 4
  %13 = load i32, i64* %r1, align 4        ; <-- INVALID OPERAND POINTEE TYPE
  %14 = load i64, i64* %r2, align 4
  %15 = trunc i64 %14 to i32
  %16 = sub i32 %13, %15
  %17 = zext i32 %16 to i64
  store i64 %17, i64* %r1, align 4
```

### Compiler Diagnostic on Raw IR:
```
opt -O3 -S raw.ll -o opt.ll
opt: raw.ll:57:14: error: explicit pointee type doesn't match operand's pointee type (i32 vs i64)
  %13 = load i32, i64* %r1, align 4
             ^
```

---

## 4. Applied Corrections

### A. Source-Level Lifter Correction (`bpf_lifter/src/instr_utils.cpp`)
We updated `emitLoadALUDest` (lines 61–65) to load the 64-bit register and truncate to 32 bits:
```cpp
	if (((inst.code & 0x07) == EBPF_CLS_ALU64) || dstAlways64) {
		return builder.CreateLoad(builder.getInt64Ty(), regs[inst.dst_reg]);
	} else {
		return builder.CreateTrunc(
			builder.CreateLoad(builder.getInt64Ty(), regs[inst.dst_reg]),
			builder.getInt32Ty());
	}
```
And updated JMP32 in `emitJmpLoadSrcAndDstAndZero` (lines 204–215):
```cpp
	if ((inst.code & 0x07) == 0x06) {
		// JMP32
		if (regSrc) {
			src = builder.CreateTrunc(
				builder.CreateLoad(builder.getInt64Ty(), regs[inst.src_reg]),
				builder.getInt32Ty());
		} else {
			src = builder.getInt32(inst.imm);
		}
		dst = builder.CreateTrunc(
			builder.CreateLoad(builder.getInt64Ty(), regs[inst.dst_reg]),
			builder.getInt32Ty());
		zero = builder.getInt32(0);
	} else {
```

### B. Defense-in-Depth Module (`sanitize_lifted_ir.py`)
Created [`research/experiments/split_bypass/scripts/sanitize_lifted_ir.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/sanitize_lifted_ir.py) and integrated it into `lifting_tools/generateIR.py`:
- Matches only valid eBPF register slots `%r0`..`%r10`.
- Normalizes to:
  ```llvm
  %alu32_load_{var} = load i64, i64* %{reg}{rest}
  %{var} = trunc i64 %alu32_load_{var} to i32
  ```
- Preserves valid SSA syntax, instruction ordering, and debug metadata.

---

## 5. Semantic Validation

eBPF ALU32 semantics were rigorously verified:
1. **32-Bit Arithmetic Wrapping:** 32-bit operations wrap modulo $2^{32}$.
2. **Zero-Extension Invariant:** In eBPF, all ALU32 operations zero-extend their 32-bit result into the 64-bit destination register. `emitStoreALUResult` implements this via `builder.CreateZExt(result, builder.getInt64Ty())`, ensuring upper 32 bits are cleared.
3. **ALU64 Invariance:** 64-bit operations remain untouched and operate over `i64`.
4. **Pointer Memory Integrity:** Packet and stack memory pointers remain typed pointers (`i8*`, `i32*`, `i64*`).

---

## 6. Empirical Validation Results

### A. Local Unit Test Suite (79/79 Passed, 100% Green):
1. `python3 -m unittest research/experiments/tests/test_lifter_alu32_semantics.py -v` $\to$ **6 PASSED**
2. `python3 -m unittest discover -s research/experiments/split_bypass/tests -p 'test_*.py' -v` $\to$ **22 PASSED**
3. `python3 -m unittest discover -s research/experiments/tests -p 'test_split_bypass_corpus.py' -v` $\to$ **11 PASSED**
4. `python3 -m unittest discover -s research/experiments/tests -p 'test_split_analyze_bypass.py' -v` $\to$ **18 PASSED**
5. `PYTHONPATH=. pytest -v research/tests/` $\to$ **22 PASSED**
- **Total: 79 PASSED, 0 FAILED (Exit Code 0).**

### B. Container Deployment & Execution Verification
After deploying the patched source and rebuilding `bpflifter_cli` with LLVM 13 inside the container:

| Fixture | Command Executed | Lifter Status | Linker Output | Final Status |
|---|---|:---:|:---:|:---:|
| **A02_straight_medium.o** | `generateIR.py A02_straight_medium.o` | **PASS (0)** | `final_linked_ir.bc` | **RESOLVED** |
| **C01_join_different_values.o** | `generateIR.py C01_join_different_values.o` | **PASS (0)** | `final_linked_ir.bc` | **RESOLVED** |
| **C02_join_policy_sensitive.o** | `generateIR.py C02_join_policy_sensitive.o` | **PASS (0)** | `final_linked_ir.bc` | **RESOLVED** |
| **D02_packet_memory_candidate.o**| `generateIR.py D02_packet_memory_candidate.o`| **PASS (0)** | `final_linked_ir.bc` | **RESOLVED** |
| **E01_bounded_loop.o** | `generateIR.py E01_bounded_loop.o` | **PASS (0)** | `final_linked_ir.bc` | **RESOLVED** |

### Live Daemon Verification:
We executed `split_analyze_bypass.py` on `A02_straight_medium.o` against the live KRAKENGUARD daemon:
```json
{
  "output": "/tmp/test_a02_after.json",
  "overall_status": "symbolic_pass",
  "overall_verdict": "SAFE"
}
```
`A02_straight_medium`, which previously yielded `unresolved` / `UNKNOWN` due to the lifter crash, now successfully passes symbolic verification.

---

## 7. Submodule & Repository Integrity Audit

- **Submodule (`research/baselines/krakenguard/artifact`):**
  - `lifting_tools/generateIR.py`: Pre-existing 41-line synthetic map ID patch **strictly preserved**. Added 26 lines of defense-in-depth sanitization under Step 1.
  - `bpf_lifter/src/instr_utils.cpp`: Clean +9/-4 line source diff in `emitLoadALUDest` and `emitJmpLoadSrcAndDstAndZero`.
- **Historical Datasets:** All historical datasets (`work/results/runs.csv`, E1–E5, Phase 5) remain untouched.
- **Git State:** On branch `main` at commit `ce2cebe`. No unapproved Git commits, rebases, or pushes were performed.

---

## 8. Next Research Milestone

With the LLVM lifter compatibility blocker resolved and validated:
- **Task 6 (Region Abstract Analyzer Implementation):** Refactor `AbstractPolicyAnalyzer` to implement `analyze_region(program, region, incoming_state, policy, path_constraints)` and sound CFG state propagation using the Task 4 API contract.
