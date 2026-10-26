# Task 8: Stack Memory Modeling and Ground-Truth Oracle Assignment Report

**Date:** 2026-10-22  
**Commit Baseline:** `ce2cebe`  
**Repository:** `Research-Paper-eBPF`  
**Branch:** `main`

---

## 1. Executive Summary

Task 8 eliminates the two critical blockers identified during the Task 7 architecture audit:
1. **Stack Memory Modeling:** Implemented width-aware, bound-checked eBPF stack frame modeling in `region_analyzer.py`. Fixed the conflation between private BPF stack spills on `r10` and network packet writes on `r1..r9`.
2. **Ground-Truth Reference Oracle Assignment:** Formally assigned and documented independent reference verdicts (`SAFE` or `VIOLATION`) for all 10 compiled corpus fixtures (`A01` through `E01`) in `corpus-manifest.json` under the authoritative frozen E1 policy (`policy-c0f0ac4d1a5e.json`).

Prior to Task 8, fixtures with `volatile` variables spilled to `*(u32*)(r10 - 4)`, triggering false `UNKNOWN` outcomes under `policy-c0f0ac4d1a5e.json`. With Task 8:
- All 9 acyclic compliant fixtures (`A01`–`D02`) are discharged as **`SAFE`** by `region_analyzer.py`.
- `E01_bounded_loop` has stack stores and reloads modeled without error, but is conservatively flagged **`UNKNOWN`** due to CFG back-edge cycle detection, correctly preserving the fail-closed fallback boundary.
- All 116 tests across the repository pass cleanly (84 pytest items, 20 subtests, 12 Phase 5 soundness tests).

---

## 2. Root Cause Analysis and Implementation Details

### 2.1 The Stack Memory Gap
In `region_analyzer.py` (as written in Task 6), memory stores were matched by a generic regex:
```python
if re.match(r"^\*\([^)]*\)\([rw](?:10|[0-9])(?:\s*[+-]\s*(?:0x[0-9A-Fa-f]+|\d+))?\)\s*=", ins.text):
    if program._memory_policy_constrained():
        return RegionResult(verdict=RegionVerdict.UNKNOWN, reason="Memory store requires policy-aware proof...")
```
Because `policy-c0f0ac4d1a5e.json` defines `"write-access": ["x"]` (no packet writes), `program._memory_policy_constrained()` returned `True`. The analyzer did not differentiate the eBPF frame pointer `r10` from packet buffer pointers (`r1`), treating private stack spills as potentially violating packet writes.

### 2.2 Mathematical & Architectural Stack Model
1. **Base Register Distinction:**
   - Stack access: Base register is strictly `r10` (or `w10`).
   - Packet/map access: Base register is `r1`–`r9`. Packet stores under `"write-access": ["x"]` emit `RegionVerdict.VIOLATION`.
2. **Frame Bounds:**
   - Exactly 512 bytes: `offset < 0`, `offset >= -512`, and `(offset + width) <= 0`.
   - Accesses violating these bounds emit fail-closed `RegionVerdict.UNKNOWN` (`"Invalid stack access: out of bounds"`).
3. **Width-Aware Slot Tracking:**
   - Supports `u8` (1 byte), `u16` (2 bytes), `u32` (4 bytes), and `u64` (8 bytes).
   - `stack_slots: dict[int, tuple[int, AbstractValue]]` maps negative byte offsets to `(width, value)`.
   - Overlapping writes automatically invalidate intersected slots to prevent stale reads.
   - Reads from unwritten or width-mismatched slots conservatively yield `AbstractValue.unknown()` (never fabricating safe constants).
4. **CFG Predecessor Join:**
   - Converging paths join stack slots across incoming states:
     $\text{joined\_stack}[k] = (w, v_1 \sqcup v_2)$ for common offsets $k$ with equal width $w$.

---

## 3. Fixture-by-Fixture Before/After Behavior

Tested under the canonical policy `policy-c0f0ac4d1a5e.json`:

| Fixture ID | Task 7 Behavior (Before) | Task 8 Behavior (After) | Change Description |
|:---|:---:|:---:|:---|
| `A01_straight_small` | `SAFE` | `SAFE` | Unaltered (straight-line registers). |
| `A02_straight_medium` | `UNKNOWN` (Memory store pc 3) | **`SAFE`** | 24 ALU32 operations with stack spills on `r10-4` now discharge cleanly. |
| `A03_helper_clock` | `SAFE` | `SAFE` | Unaltered (helper 5 allowed by `*`). |
| `B01_branch_safe` | `SAFE` | `SAFE` | Unaltered (both branches return XDP_PASS). |
| `B02_branch_policy_sensitive` | `SAFE` | `SAFE` | Unaltered (DROP and PASS permitted by policy). |
| `C01_join_different_values` | `UNKNOWN` (Memory store pc 6) | **`SAFE`** | Stack spill at `r10-4` joins values 1 and 2; discharges cleanly. |
| `C02_join_policy_sensitive` | `UNKNOWN` (Memory store pc 3) | **`SAFE`** | Stack spill at `r10-4` joins values 0 and 1; discharges cleanly. |
| `D01_helper_unknown_candidate` | `SAFE` | `SAFE` | Unaltered (helper 7 allowed by `*`). |
| `D02_packet_memory_candidate` | `UNKNOWN` (Memory store pc 7) | **`SAFE`** | Guarded packet read into `r10-1` stack slot discharges cleanly. |
| `E01_bounded_loop` | `UNKNOWN` (Memory store pc 1) | **`UNKNOWN`** (CFG back-edge cycle) | Stack stores pass cleanly; correctly halts on CFG cycle at loop header `bb_4`. |

---

## 4. Ground-Truth Reference Oracle Table

Formally updated in [`corpus-manifest.json`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/manifests/corpus-manifest.json):

| Fixture ID | Reference Verdict | Abstract Expected | Semantic Justification | Evidence Source |
|:---|:---:|:---:|:---|:---|
| `A01_straight_small` | **`SAFE`** | `SAFE` | Context length computation; no memory writes; legal `XDP_PASS` (2) return. | eBPF ISA & E1 policy |
| `A02_straight_medium` | **`SAFE`** | `SAFE` | 24 ALU32 operations on `volatile n`; spills within 512B stack frame; returns `XDP_PASS` (2). | Clang disassembly & E1 policy |
| `A03_helper_clock` | **`SAFE`** | `SAFE` | Calls `bpf_ktime_get_ns()` (helper 5); allowed by `helper_access: ["*"]`; returns `XDP_PASS` (2). | Clang disassembly & E1 policy |
| `B01_branch_safe` | **`SAFE`** | `SAFE` | Conditional branch on packet length parity; both branches return `XDP_PASS` (2). | Clang disassembly & E1 policy |
| `B02_branch_policy_sensitive` | **`SAFE`** | `SAFE` | Calls helper 5 (allowed); branches return `XDP_DROP` (1) or `XDP_PASS` (2); policy lacks return rule. | Clang disassembly & E1 policy |
| `C01_join_different_values` | **`SAFE`** | `SAFE` | Two branches join values 1 and 2 on stack; downstream branch returns `XDP_PASS` (2). | Clang disassembly & E1 policy |
| `C02_join_policy_sensitive` | **`SAFE`** | `SAFE` | Branches join values 0 and 1 on stack; returns `XDP_DROP` or `PASS`; policy lacks return rule. | Clang disassembly & E1 policy |
| `D01_helper_unknown_candidate` | **`SAFE`** | `SAFE` | Calls helper 7 (`bpf_get_prandom_u32()`, allowed); returns `XDP_DROP` or `PASS`. | Clang disassembly & E1 policy |
| `D02_packet_memory_candidate` | **`SAFE`** | `SAFE` | Bound-checked packet read `data + 1 <= data_end`; offset 0 in `[0-54]`; local stack spill. | Clang disassembly & E1 policy |
| `E01_bounded_loop` | **`SAFE`** | **`UNKNOWN`** | Bounded 8-iteration loop; stack spills valid; returns `XDP_PASS` (2). Abstract analyzer conservatively yields `UNKNOWN` due to CFG back-edge cycle. | Clang disassembly & E1 policy |

---

## 5. Test Commands & Verification Results

### Targeted Stack Memory Tests:
8 new test cases added in `test_region_analyzer.py:StackMemoryModelTests`:
- `test_stack_spill_and_reload_roundtrip`: PASSED
- `test_stack_uninitialized_read_yields_unknown`: PASSED
- `test_stack_width_mismatch_yields_unknown`: PASSED
- `test_stack_overlapping_stores_invalidate`: PASSED
- `test_stack_out_of_bounds_store_yields_unknown`: PASSED
- `test_stack_out_of_bounds_load_yields_unknown`: PASSED
- `test_packet_memory_write_under_policy_yields_violation`: PASSED
- `test_multiblock_stack_join`: PASSED

### Full Test Suite Execution:
```bash
# Split-bypass and experiment tests
pytest research/experiments/split_bypass/tests/ research/experiments/tests/ -v
# Result: 84 passed, 20 subtests passed (104 test items) in 0.25s (Exit code: 0)

# Phase 5 Soundness tests
PYTHONPATH=. pytest research/tests/test_phase5_abstract_soundness.py -v
# Result: 12 passed in 0.07s (Exit code: 0)
```
**Total Passing Tests:** **116 / 116 tests passing (100% green)**.

---

## 6. Readiness Assessment for Task 9

- **Stack Memory Modeling:** Resolved and verified with zero false `UNKNOWN`s on compliant local variables.
- **Corpus Ground Truth:** Fully documented and assigned in `corpus-manifest.json`.
- **Readiness for Task 9:** **YES, READY.** The repository is now prepared for **Task 9: Tri-Mode Runner Integration and Telemetry Instrumentation**.
