# Task 4 Region-Level Verification API Contract Report

> **Research Topic:** Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification  
> **Date:** 2026-10-22  
> **Branch:** `main` | **HEAD Commit:** `ce2cebe`  
> **Artifacts Produced:**  
> - Specification: [`research/experiments/split_bypass/REGION_API_CONTRACT.md`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/REGION_API_CONTRACT.md)  
> - Typed Contract Module: [`research/experiments/split_bypass/scripts/region_contract.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/region_contract.py)  
> - Contract Unit Tests: [`research/experiments/split_bypass/tests/test_region_contract.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/tests/test_region_contract.py) (11 passed)  
> - Updated Memory: [`MEMORY.md`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/MEMORY.md)

---

## 1. Executive Summary

Task 4 formalizes the contract governing the transition from whole-program orchestration to fine-grained, region-level verification. 

While Tasks 1–3 established that abstract early-exit bypasses are fast (~112 ms) and fail-closed handling is sound, the underlying prototype remains limited to whole-program scope. Basic blocks extracted from the CFG have been strictly metadata-only. 

Task 4 bridges this gap by establishing:
1. **Precise Boundary Rules:** Formal definitions for basic blocks, multi-block regions, and functions, preventing structural confusion.
2. **Explicit Incoming State Semantics:** Prohibiting default safe assumptions; requiring explicit register environments, path constraints, and sound multi-predecessor state joins ($\sqcup$).
3. **Truth in Execution Scope:** Prohibiting whole-program execution backends (such as KRAKENGUARD) from being mislabeled as region-scoped verifiers.
4. **Sound Program Verdict Composition:** Formulating composition rules requiring that program `SAFE` demands all reachable regions be proven safe under compatible states, while confirmed reachable violations permit early-exit termination.
5. **Executable Verification:** Typed contract classes in `region_contract.py` accompanied by 11 unit tests in `test_region_contract.py`, bringing total passing tests to 73 across 5 suites.

---

## 2. Working Tree Safety & Provenance

Repository safety safeguards were confirmed before and after task execution:
- **Git Branch:** `main` at `ce2cebe`.
- **Submodule State:** `research/baselines/krakenguard/artifact` (commit `e7bd840`) dirty status verified intact. The 41-line synthetic map ID patch in `lifting_tools/generateIR.py` was strictly preserved (`1 file changed, 41 insertions(+)`).
- **Historical Data:** No historical datasets (`work/results/runs.csv`, E1–E5, Phase 5) or Task 3 smoke records were overwritten or modified.
- **No Unapproved Operations:** No remote pushes, branch switches, rebases, or destructive stashes were executed.

---

## 3. Inspected Codebase Interfaces

| Component | Inspected Location | Key Observations & Structural Reality |
|---|---|---|
| **Abstract Analyzer** | `research/analyzer/abstract_policy_analyzer.py` | `AbstractPolicyAnalyzer.analyze()` starts at PC 0 with default blank registers (`r10=0`, `r0..r9=unknown`). Has no parameter for incoming state or entry block. Loop visits trigger immediate conservative `UNKNOWN`. |
| **CFG Extraction** | `research/experiments/scripts/split_analyze_bypass.py:extract_cfg` | Extracts basic blocks, predecessors, successors, and reverse-postorder. Annotates block verdicts as `metadata_only` because analyzer has no sound independent-block API. |
| **Symbolic Verifier** | `research/experiments/scripts/split_analyze_bypass.py:_symbolic_worker` | Calls frozen KRAKENGUARD daemon client with `(object_file, constraints_file)`. Accepts only whole compiled ELF binaries. |
| **Lifter Backend** | `research/baselines/krakenguard/artifact/lifting_tools/generateIR.py` | `bpflifter_cli` emits LLVM pointer mismatches (`load i32, i64* %r1`) on ALU32 sub-registers, causing `opt` in KRAKENGUARD to crash on medium/join fixtures. |

---

## 4. Summary of the Contract Specification

The complete specification is authored in [`research/experiments/split_bypass/REGION_API_CONTRACT.md`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/REGION_API_CONTRACT.md). Its core pillars are:

### A. Region Boundary Contract
- Every region has a single dominating entry block, a non-empty set of constituent basic blocks, and explicit exit blocks.
- Single basic blocks have `scope: BASIC_BLOCK`. Regions containing more than one block must have `scope: MULTI_BLOCK_REGION`.
- Internal cycles (`has_backedge: True`) require explicit inductive invariants or conservative `UNKNOWN` abstention.

### B. Incoming State & Join Contract
- Interface: `analyze_region(P, R, incoming_state, policy, path_constraints) -> RegionResult`.
- Missing or implicit incoming states are rejected by validation.
- Multiple predecessor execution paths must be combined using the sound least upper bound ($\sqcup$) across the register lattice.
- Default safe states at intermediate basic blocks are strictly prohibited.

### C. Region Result & Truth in Scope
- Every result carries its verdict (`SAFE`, `VIOLATION`, `UNKNOWN`), scope, analysis method, entry assumptions, and unresolved reason (if `UNKNOWN`).
- **Scope Invariant:** If `backend_executor_scope == WHOLE_PROGRAM`, the result scope cannot claim `BASIC_BLOCK` or `MULTI_BLOCK_REGION`. Whole-program fallback is recognized as a temporary compatibility fallback, not a region verification engine.

### D. Composition Rules
- **Overall SAFE:** All reachable regions must be `SAFE` under valid, soundly propagated incoming states.
- **Overall VIOLATION:** Any confirmed reachable violation permits early termination of violation-existence checks without verifying all remaining paths.
- **Overall UNKNOWN:** Any reachable `UNKNOWN`, `TIMEOUT`, or tool failure prevents an overall `SAFE` verdict (fail-closed).

---

## 5. Implementation Readiness Assessment

| Capability | Status | File Citation | Notes / Blocker |
|---|:---:|---|---|
| **CFG Extraction** | `EXISTS` | `split_analyze_bypass.py:extract_cfg` | Functional metadata extraction |
| **Region Boundary Modeling** | `EXISTS` | `region_contract.py:RegionBoundary` | Validated in unit tests |
| **Abstract Register Domain** | `EXISTS` | `abstract_policy_analyzer.py:AbstractValue` | Supports const, symbolic, unknown |
| **Incoming State Modeling** | `EXISTS` | `region_contract.py:IncomingAbstractState` | Validated in unit tests |
| **State Join Operator ($\sqcup$)** | `PARTIAL` | `region_contract.py:AbstractValue.join` | Lattice join implemented in contract module; not yet connected to analyzer |
| **Region Abstract Analysis** | `NOT_IMPLEMENTED` | *None* | `analyze()` is whole-program only |
| **Loop / Invariant Handling** | `NOT_IMPLEMENTED` | `abstract_policy_analyzer.py:278` | Emits conservative UNKNOWN on loop visit |
| **Whole-Program Fallback** | `EXISTS` | `split_analyze_bypass.py:_symbolic_worker` | Active with live Docker daemon |
| **Scoped Region Fallback** | `BLOCKED` | KRAKENGUARD daemon | Daemon accepts only whole ELF binaries |
| **Lifter Type Compatibility** | `BLOCKED` | `generateIR.py` / `bpflifter_cli` | LLVM 13 pointer mismatch on ALU32 registers |
| **Sound Verdict Composition** | `EXISTS` | `region_contract.py:ProgramVerdictComposer` | Validated in unit tests |
| **Provenance Logging** | `EXISTS` | `run_smoke.py` | 16 normalized schema fields recorded |

---

## 6. Contract Test Suite Verification

Contract-level unit tests were implemented in [`research/experiments/split_bypass/tests/test_region_contract.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/tests/test_region_contract.py) covering all 8 prompt-specified behaviors:
1. `test_invalid_region_boundaries_rejected`: Empty block sets, missing entry block, or mismatched blocks raise validation errors.
2. `test_missing_incoming_state_does_not_default_to_safe`: Missing or non-explicit incoming states raise validation errors.
3. `test_unknown_error_timeout_remain_non_safe`: Verifies `UNKNOWN` requires an unresolved reason and cannot be labeled `SAFE`.
4. `test_region_verdict_includes_assumptions_and_scope`: Confirms `RegionResult` records explicit entry assumptions and scope level.
5. `test_whole_program_fallback_cannot_be_mislabeled_as_region_scoped`: Validation prevents setting `scope: BASIC_BLOCK` on whole-program fallback results.
6. `test_multiple_predecessor_states_require_explicit_join_or_unresolved`: Verifies `AbstractRegisterState.join` computes sound intervals and unknown states.
7. `test_unresolved_reachable_path_prevents_program_safe`: If any reachable region is `UNKNOWN`, whole-program verdict is `UNKNOWN`.
8. `test_confirmed_reachable_violation_terminates_early`: Proven violation on a reachable path yields `VIOLATION` with early termination.

### Full Regression Suite Results (73/73 Passed, 100% Green):
1. `python3 -m unittest discover -s research/experiments/split_bypass/tests -p 'test_*.py' -v` $\to$ **22 PASSED** (11 controlled eval + 11 region contract)
2. `python3 -m unittest discover -s research/experiments/tests -p 'test_split_bypass_corpus.py' -v` $\to$ **11 PASSED**
3. `python3 -m unittest discover -s research/experiments/tests -p 'test_split_analyze_bypass.py' -v` $\to$ **18 PASSED**
4. `PYTHONPATH=. pytest -v research/tests/` $\to$ **22 PASSED**
- **Total: 73 PASSED, 0 FAILED (Exit Code 0).**

---

## 7. Next Implementation Milestones

1. **Task 5 (LLVM Lifter Remediation):**
   Investigate patching `bpflifter_cli` or configuring Clang/LLVM flags to eliminate the `load i32, i64* %r1` pointer mismatch on ALU32 sub-registers, unblocking symbolic verification for medium and join fixtures.
2. **Task 6 (Region Abstract Analyzer Implementation):**
   Refactor `AbstractPolicyAnalyzer` to implement `analyze_region(R, incoming_state)` according to the contract, enabling genuine region verification and state propagation.
3. **Task 7 (Controlled Evaluation Visualization Notebook):**
   Construct the Jupyter visualization notebook integrating `corpus-manifest.json` and the validated `summary.json` benchmarks.
