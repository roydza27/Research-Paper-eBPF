# Task 6: Region-Level Abstract Interpretation and Sound CFG State Propagation Report

**Date:** 2026-10-22  
**Commit Baseline:** `ce2cebe`  
**Repository:** `Research-Paper-eBPF`  
**Branch:** `main`

---

## 1. Executive Summary

Task 6 implements the first genuine region-level abstract interpretation capability and sound CFG abstract state propagation for the eBPF hybrid verification research initiative:

```
Compiled eBPF → CFG Extraction → Region Abstract Interpretation → Sound State Propagation & Join → Verdict Composition
```

Prior to Task 6, abstract interpretation was whole-program only (starting rigidly from entry PC 0 with default blank registers). Task 6 delivers:
1. `analyze_region(program, region, incoming_state, policy, path_constraints)` operating strictly under an explicit, non-optional incoming abstract state.
2. Abstract transfer functions for 64-bit and 32-bit registers (`[rw]0`–`[rw]10`), ALU operations (+, -, *, &, |, ^, <<, >>), helper calls, map lookups, memory references, and return values.
3. Sound CFG state propagation across reachable regions, implementing mathematical least-upper-bound state joins (`AbstractRegisterState.join()`) at multi-predecessor merge points.
4. Conservative CFG cycle / back-edge detection using 3-color DFS to guarantee termination and enforce fail-closed `UNKNOWN` outcomes on unbounded loops.
5. Direct integration with `ProgramVerdictComposer` to assemble whole-program verdicts from region results.
6. Rigorous backend classification: whole-program fallback (KRAKENGUARD) remains strictly typed as `WHOLE_PROGRAM` and is prohibited from being mislabeled as region-scoped.

---

## 2. Theoretical and Mathematical Properties

### 2.1 Abstract State & Semantics
- **Registers:** Formally represented as `AbstractRegisterState` containing an immutable mapping of registers `r0`–`r10` to `AbstractValue`.
- **Subregisters:** ALU32 operations (`w0`–`w9`) write directly to the 64-bit registers with zero-extension (`val & 0xFFFFFFFF`) matching eBPF ISA specifications.
- **Join Semantics ($\sqcup$):**
  - $\text{Const}(c_1) \sqcup \text{Const}(c_2) = \text{Const}(c_1)$ if $c_1 = c_2$, else $\text{Interval}(\min(c_1, c_2), \max(c_1, c_2))$.
  - $\text{Interval}(l_1, h_1) \sqcup \text{Const}(c) = \text{Interval}(\min(l_1, c), \max(h_1, c))$.
  - $\text{Interval}(l_1, h_1) \sqcup \text{Interval}(l_2, h_2) = \text{Interval}(\min(l_1, l_2), \max(h_1, h_2))$.
  - Any join with $\text{Unknown}$ yields $\text{Unknown}$.

### 2.2 Safety & Fail-Closed Boundaries
- **Missing or Implicit States:** Non-explicit incoming states immediately raise `ValueError` and never default to `SAFE`.
- **Policy Checking:**
  - Forbidden helper calls immediately emit `VIOLATION` with violating instruction evidence.
  - Allowed helper calls symbolically mark `r0` and clobber caller-saved registers `r1`–`r5` to `Unknown`.
  - Unmodeled opcodes or unknown helper IDs yield `UNKNOWN`.
  - Exits under active return rules require proof of allowed return constants; indeterminate returns yield `UNKNOWN`.
  - Memory stores under memory-constrained policies yield `UNKNOWN` without formal memory bounds proofs.

### 2.3 Cycle & Back-Edge Detection
- CFG cycles and loops are identified using 3-color DFS (`WHITE`, `GRAY`, `BLACK`).
- Any edge entering an active ancestor node (`GRAY`) or pointing to itself is recorded as a back-edge.
- Regions targeted by back-edges emit `RegionVerdict.UNKNOWN` (`"CFG cycle / back-edge detected entering region '...'"`).
- Forward propagation along back-edges is halted, guaranteeing termination while soundly failing closed.

---

## 3. Implementation Details

### Files Authored / Modified:
1. `research/experiments/split_bypass/scripts/region_analyzer.py` [NEW]:
   - `BpfInstruction`, `BpfBasicBlock`, `BpfProgramContext`
   - `partition_basic_blocks(context)`
   - `find_cfg_backedges(context)`
   - `analyze_region(...)`
   - `propagate_and_analyze_program(...)`
2. `research/experiments/split_bypass/tests/test_region_analyzer.py` [NEW]:
   - 19 unit and integration test cases covering:
     - Missing incoming state rejection
     - ALU constant and unknown transfer functions
     - Allowed, forbidden, and unmodeled helper policies
     - Map access authorization
     - Exit and return value policy compliance
     - Sequential block state propagation
     - Deterministic branch condition evaluation vs. indeterminate path splitting
     - Multi-path state joins at merge points
     - Cycle / back-edge loop detection
     - Reachable violation composition
     - Real corpus fixture integration (`A01_straight_small`, `A03_helper_clock`, `E01_bounded_loop`)
     - Backend executor scope mislabeling prevention

---

## 4. Verification and Test Results

All test suites across the repository were executed:

```bash
# Split-bypass and experiment tests
pytest research/experiments/split_bypass/tests/ research/experiments/tests/ -v
# Result: 76 passed, 20 subtests passed (96 total test items) in 0.28s

# Phase 5 Abstract Soundness tests
PYTHONPATH=. pytest research/tests/test_phase5_abstract_soundness.py -v
# Result: 12 passed in 0.06s
```

**Total Passing Tests:** **108 / 108 tests passing (100%)**.

---

## 5. Architectural Integrity and Limitations

1. **Explicit Backend Classification:**
   Whole-program symbolic fallback (KRAKENGUARD) remains explicitly labeled `WHOLE_PROGRAM`. `region_analyzer.py` and `region_contract.py` enforce that no whole-program verifier output can masquerade as a region-level verdict.
2. **Abstract Domain Bounds:**
   Constant propagation and bounded intervals are supported. Symbolic path constraints are recorded along branch decisions. Relational abstract domains (e.g., Octagons or Polyhedra) are deferred to future optimizations.
3. **Loop Handling:**
   Unrolled loops evaluate straight-line instructions; loops containing back-edges soundly fail closed as `UNKNOWN`.
