# Task 12: Region-Scoped Symbolic Fallback Validation Report

**Document:** `REGION_SCOPED_FALLBACK_REPORT.md`  
**Phase:** Phase 3 (Validate and Report)  
**Date:** 2026-10-25  
**Authoritative Baseline:** Commit `ce2cebe` on branch `main`  
**Repository Working Directory:** `/home/cy3pher/Documents/WorkSpace-Research/eBPF`  

---

## 1. Executive Status & Verdict

**Overall Task 12 Status:** `PARTIAL` *(Prototype Region-Scoped Symbolic Fallback Verified; External KRAKENGUARD Backend Bounded to Whole-Program)*

### Summary Assessment:
1. **Direct Region-Scoped Symbolic Fallback (`VERIFIED PASS`):**
   - The in-memory state-aware symbolic executor (`DirectRegionSymbolicExecutor`) genuinely analyzes isolated basic blocks and linear region slices under explicit incoming abstract states (`IncomingAbstractState`).
   - Models 32-bit zero-extension (`wX` into `rX`), bounded stack frame loads and stores within `[-512, 0)`, relational pointer provenance (`packet` vs `map_val` vs `stack` vs `scalar`), and branch conditions.
   - Propagates resolved exit states to successor regions across the CFG worklist and integrates soundly with `ProgramVerdictComposer`.
   - Verified across 16 focused unit and integration tests (100% green).
2. **KRAKENGUARD Lifter Boundary (`CONFIRMED LIMITATION / WHOLE-PROGRAM`):**
   - Baseline KRAKENGUARD (`bpflifter_cli` $\to$ `generateIR.py` $\to$ `krakenguard_template.j2` $\to$ KLEE) cannot ingest isolated instruction slices or raw basic blocks; it strictly requires a full compiled eBPF ELF binary with section headers and symbol tables.
   - Telemetry enforces scientific veracity: KRAKENGUARD fallback is strictly recorded as `fallback_scope: "whole_program"`. Any attempt to label full-program execution as `region_scoped` raises a contract violation error.
3. **Scientific Status Classification:** Because genuine region-level symbolic verification is achieved via `DirectRegionSymbolicExecutor`, but the external baseline KRAKENGUARD verifier remains structurally bound to whole-program fallback, the overall architecture is classified as **`PARTIAL`**. Success is not overstated.

---

## 2. Actual Fallback Scope & Runtime Evidence

### 2.1 Scope Telemetry and Verification Rules
The typed API contract enforces that scope cannot be fabricated:
- **`ScopeLevel.BASIC_BLOCK` / `ScopeLevel.MULTI_BLOCK_REGION`:** Permitted **only** when `DirectRegionSymbolicExecutor` executes an isolated slice.
- **`ScopeLevel.WHOLE_PROGRAM`:** Enforced whenever KRAKENGUARD or full-ELF binaries are executed.

```python
# region_contract.py:238-243
if self.is_genuinely_region_scoped and self.backend_executor_scope == ScopeLevel.WHOLE_PROGRAM:
    raise ValueError(
        "Scope veracity violation: is_genuinely_region_scoped cannot be True "
        "when backend_executor_scope is WHOLE_PROGRAM"
    )
```

### 2.2 Direct Region Execution Evidence
In `region_analyzer.py:988–1035`, when a basic block evaluates to `RegionVerdict.UNKNOWN`, the fallback gate constructs a `RegionSymbolicRequest`:
- `instructions`: Contains strictly the instructions belonging to that basic block (`program.basic_blocks[bid].instructions`).
- `incoming_state`: Carries the exact abstract state at the block's entry point.
- `backend_executor_scope`: Returns `ScopeLevel.BASIC_BLOCK`.

### 2.3 KRAKENGUARD Whole-Program Fallback Evidence
In `split_analyze_bypass.py:311–320`:
```python
row["symbolic_invoked"] = True
row["fallback_invoked"] = True
row["fallback_scope"] = "whole_program"
```
The client calls `KrakenGuardClient.verify(object_file=args.object)` with the full `.o` binary file. The telemetry truthfully reflects whole-program execution.

---

## 3. Supported Semantics & Fail-Closed Safeguards

### 3.1 Supported Instruction Semantics in `DirectRegionSymbolicExecutor`

| Category | Instruction Formats | Modeled Semantics | Soundness Boundary |
| :--- | :--- | :--- | :--- |
| **ALU32 Operations** | `wX = imm`, `wX = wY`, `wX <op>= imm`, `wX <op>= wY` | Evaluated with integer interval arithmetic; masked with `& 0xFFFFFFFF` to ensure high 32 bits of `rX` are cleared. | Zero-extension strictly enforced. |
| **ALU64 Operations** | `rX = imm`, `rX = rY`, `rX <op>= imm`, `rX <op>= rY` | Evaluated over 64-bit integer intervals and constants. Supported: `+`, `-`, `*`, `&`, `\|`, `^`, `<<`, `>>`. | Arithmetic overflow tracked. |
| **Stack Memory** | `*(uX *)(r10 - off) = src`, `dst = *(uX *)(r10 - off)` | Width-aware tracking (`u8`, `u16`, `u32`, `u64`) within bounds `[-512, 0)`. Overlapping stores invalidate prior sub-slots. | Offsets $< -512$ or $\ge 0$ fail closed as `UNKNOWN`. |
| **Helper Functions** | `call 1` (`map_lookup`), `call 2` (`map_update`), `call 5` (`ktime`), `call 7` (`prandom`) | Sets return register `r0` and assigns relational provenance; clobbers caller-saved registers `r1..r5` to `unknown`. | Unmodeled helper IDs fail closed as `UNKNOWN`. Forbidden helpers emit `VIOLATION`. |
| **Pointer Provenance** | Tracking `stack`, `map_val`, `packet`, and `scalar` | Differentiates pointer targets. Stores through `map_val` and `stack` are permitted; stores through `packet` violate write-prohibited policies. | Ambiguous pointer provenance fails closed as `UNKNOWN`. |
| **Return Values** | `r0 = imm; exit` | Evaluates return value against policy `return_values` allowlist. | Known compliant return emits `SAFE`; non-compliant emits `VIOLATION`; indeterminate emits `UNKNOWN`. |

### 3.2 Fail-Closed Soundness Invariants (Verdict Criteria)

The executor cannot emit `SAFE` on heuristics or unmodeled instructions:
1. **`VIOLATION` (Definitive Counterexample Found):**
   - Memory store through a pointer with `packet` provenance under `"write-access": ["x"]`.
   - Helper function call whose ID matches `forbidden_helpers`.
   - `exit` instruction where `r0` is a known constant not permitted by policy.
   - *Requirement:* Must provide an explicit `witness_trace`.
2. **`SAFE` (Mathematical Compliance Proof):**
   - All instructions in the region are modeled.
   - All memory stores target proven `stack` or `map_val` memory.
   - All helper calls are permitted and caller-saved registers are clobbered.
   - Return value complies with policy.
   - Valid outgoing `exit_states` are generated.
3. **`UNKNOWN` (Inconclusive Fail-Closed):**
   - Any unsupported instruction opcode (e.g., custom accelerators, SIMD).
   - Any unmodeled helper call ID.
   - Any memory store through an ambiguous or unproven pointer.
   - Any out-of-bounds stack access ($< -512$ or $\ge 0$).
   - Any indeterminate return value under an active return policy.
   - Any CFG back-edge cycle or loop.
   - Any execution exception or timeout.
   - *Requirement:* Must provide an explicit `unresolved_reason`.

---

## 4. Test Evidence & Pass Counts

All repository regression and soundness suites were executed synchronously. **Zero failures were observed.**

### 4.1 Test Execution Summary

| Test Suite | File Path | Tests Executed | Passed | Failed | Execution Time |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Region Fallback & Provenance** | `split_bypass/tests/test_region_scoped_fallback.py` | 16 | 16 | 0 | 0.07s |
| **Region Analyzer & Stack Model** | `split_bypass/tests/test_region_analyzer.py` | 27 | 27 | 0 | 0.19s |
| **Region Contract & Scope Veracity** | `split_bypass/tests/test_region_contract.py` | 11 | 11 | 0 | 0.05s |
| **Tri-Mode Runner & Gate** | `split_bypass/tests/test_tri_mode_runner.py` | 21 | 21 | 0 | 0.05s |
| **Controlled Evaluation & Corpus** | `split_bypass/tests/test_controlled_evaluation.py` | 12 (20 subtests) | 12 | 0 | 0.04s |
| **Split-Bypass Runner & CFG** | `experiments/tests/test_split_analyze_bypass.py` | 18 | 18 | 0 | 0.03s |
| **Lifter ALU32 Semantics** | `experiments/tests/test_lifter_alu32_semantics.py` | 6 | 6 | 0 | 0.02s |
| **Corpus Adapter Suite** | `experiments/tests/test_split_bypass_corpus.py` | 10 | 10 | 0 | 0.03s |
| **Phase 5 Abstract Soundness** | `research/tests/test_phase5_abstract_soundness.py` | 12 | 12 | 0 | 0.05s |
| **TOTAL** | — | **133 tests (+20 subtests)** | **133** | **0** | **~0.48s** |

### 4.2 Exact Verification Commands
```bash
# 1. Focused region fallback suite
PYTHONPATH=research/experiments/split_bypass/scripts pytest research/experiments/split_bypass/tests/test_region_scoped_fallback.py -v

# 2. Complete split_bypass and experiments suites
pytest research/experiments/split_bypass/tests/ research/experiments/tests/ -v

# 3. Phase 5 abstract soundness suite
PYTHONPATH=. pytest -v research/tests/test_phase5_abstract_soundness.py
```

---

## 5. Limitations & Technical Risks

1. **Relational Incompleteness Across Merges:**
   - At multi-predecessor merge points, cross-register relational constraints (e.g., $r_1 \le r_2$) weaken to Cartesian intervals ($r_1 \in [0, 10], r_2 \in [0, 10]$). If a downstream region's safety depends on $r_1 \le r_2$, the region executor soundly returns `UNKNOWN`.
2. **Conservative Loop Abstention:**
   - CFG back-edges strictly fail closed as `UNKNOWN`. While sound, programs with bounded loops require whole-program symbolic execution.
3. **KRAKENGUARD Inelasticity:**
   - KRAKENGUARD's C++ lifter (`bpflifter_cli`) cannot ingest raw instruction buffers, preventing external SMT solvers from verifying isolated slices without synthesizing complex ELF objects.

---

## 6. Changed Files & Working Tree Audit

### Modified Files in Phase 2:
1. [`research/experiments/split_bypass/scripts/region_symbolic_executor.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/region_symbolic_executor.py) — ALU32 zero-extension, stack bounds checking, compound ALU, fail-closed unmodeled opcode/helper guards, and pointer provenance tracking.
2. [`research/experiments/split_bypass/scripts/region_analyzer.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/region_analyzer.py) — Fallback dispatch in `propagate_and_analyze_program`, isolated request generation, successor state propagation, and scope veracity enforcement.
3. [`research/experiments/split_bypass/tests/test_region_scoped_fallback.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/tests/test_region_scoped_fallback.py) — 16 unit and integration tests covering scope veracity, provenance, unmodeled opcodes, unmodeled helpers, and CFG fallback propagation.

### Preserved Artifacts:
- Baseline benchmark results (`research/experiments/results/split_bypass_evaluation/`) are **100% preserved**.
- Katran case-study results (`research/experiments/results/katran_case_study/`) are **100% preserved**.
- Dissertation manuscripts (`results.md`, `docs/manuscript/final_research_summary.md`, docx/pdf exports) are **completely untouched**.

---

## 7. Recommended Next Steps

Having established that Task 12 is verified with a status of **`PARTIAL`**, the next logical milestone is:
1. Obtain user approval on this validation report (`REGION_SCOPED_FALLBACK_REPORT.md`).
2. Proceed to **Task 10 Benchmark Rerun** in an isolated results directory (`research/experiments/results/split_bypass_evaluation_rerun/`) under bounded resource limits.
3. Proceed to **Katran Case Study Rerun** in an isolated directory (`research/experiments/results/katran_case_study_rerun/`).
4. Validate rerun data provenance, append records to `evidence_ledger.csv` (preserving rows 1–28), and generate publication figures.
