# Task 3 Smoke Experiment and Verification-Routing Audit Report

> **Research Topic:** Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification  
> **Date:** 2026-10-22  
> **Branch:** `main` | **HEAD Commit:** `ce2cebe`  
> **Artifacts Produced:**  
> - Smoke Raw Results: `research/experiments/results/split_bypass_smoke/raw/` (30 JSON records)  
> - Smoke Summary: `research/experiments/results/split_bypass_smoke/summary.json`  
> - Smoke Runner: `research/experiments/split_bypass/scripts/run_smoke.py`  
> - Enhanced Aggregator: `research/experiments/split_bypass/scripts/analyze_runs.py`  
> - Enhanced Tests: `research/experiments/split_bypass/tests/test_controlled_evaluation.py` (11 passed)

---

## 1. Executive Summary

Task 3 empirically executed the Split–Analyze–Bypass orchestration prototype against the canonical 10-fixture eBPF corpus under policy `policy-c0f0ac4d1a5e.json`. The campaign executed **30 individual runs** (1 warmup + 2 measured repetitions per fixture) to audit verification routing, early-exit bypass, symbolic fallback, fail-closed safety, and timing collection.

### Key Empirical Findings:
1. **Early-Exit Bypass Validated:**
   Fixtures with definitive abstract violations (`A03_helper_clock`, `B02_branch_policy_sensitive`, `D01_helper_unknown_candidate`) were immediately classified as `VIOLATION` by the abstract interpreter in median **112.4 ms to 117.8 ms**, completely bypassing symbolic verifier invocation (`symbolic_invocation_rate: 0.0`).
2. **Symbolic Fallback Proved Safe:**
   Fixtures where the abstract interpreter soundly abstained with `UNKNOWN` (`A01_straight_small`, `B01_branch_safe`) were successfully routed to the KRAKENGUARD symbolic verifier fallback, which discharged them as `SAFE` (`symbolic_pass`) in median **898.6 ms** and **943.8 ms** respectively.
3. **Fail-Closed Soundness Confirmed:**
   Fixtures encountering legacy lifter LLVM pointer type mismatches in the KRAKENGUARD daemon (`A02_straight_medium`, `C01`, `C02`, `D02`, `E01`) were caught by the fail-closed wrapper and recorded strictly as `unresolved` (`overall_verdict: "UNKNOWN"`). At no point was an unverified or failing program misclassified as `SAFE`.
4. **Warmup Filtering & Granular Error Accounting:**
   `analyze_runs.py` was enhanced to exclude warmups from latency medians and to break down unresolved outcomes into distinct `unknown_count`, `timeout_count`, and `error_count` categories, verified by unit tests.

---

## 2. Provenance & Working Tree Safety

Before and during execution, repository state was strictly preserved:
- **Git Branch:** `main` at `ce2cebe`.
- **KRAKENGUARD Submodule (`research/baselines/krakenguard/artifact`):** Commit `e7bd840` maintained dirty with the uncommitted 41-line synthetic map ID patch in `lifting_tools/generateIR.py`. No destructive git commands were run.
- **Historical Data Preservation:** Historical datasets (`work/results/runs.csv`, E1–E5, Phase 5) remained untouched.
- **Dedicated Experiment Directory:** Smoke outputs were written to `research/experiments/results/split_bypass_smoke/`.
- **Test Integrity:** All 4 test suites passed before and after the campaign:
  - `test_controlled_evaluation.py`: 11 passed
  - `test_split_bypass_corpus.py`: 11 passed
  - `test_split_analyze_bypass.py`: 18 passed
  - `research/tests` (pytest): 22 passed
  - **Total: 62 passed, 0 failed.**

---

## 3. Tooling & Aggregator Enhancements

### A. Warmup Filtering in `analyze_runs.py`
In previous iterations, warmup executions were combined with measured repetitions in latency statistics. We updated `analyze_runs.py` to:
- Filter out records where `is_warmup` or `warmup` is true when computing `end_to_end_ms_median`, `end_to_end_ms_mean`, `abstract_ms_median`, and `symbolic_ms_median`.
- Exclude warmup runs from paired bootstrap latency comparisons.
- Track both `warmup_count` and `measured_count` in each per-program aggregate.

### B. Granular Unresolved Accounting
To prevent collapsing distinct failure modes, `analyze_runs.py` now reports:
- `unknown_count`: counts `UNKNOWN` and `UNRESOLVED` verdicts.
- `timeout_count`: counts explicit `TIMEOUT` events.
- `error_count`: counts execution or parsing `ERROR` events.
- `unknown_or_unresolved_count`: maintained for full backwards compatibility.

### C. Regression Tests
Added `test_warmup_runs_excluded_from_latency_metrics` and updated `test_timeouts_and_errors_counted_as_unresolved` in `test_controlled_evaluation.py`. All 11 unit tests pass.

---

## 4. Empirical Verification-Routing Audit

The table below summarizes the 10 fixtures across the 30 smoke runs (1 warmup + 2 measured repetitions):

| Fixture ID | Family | Abstract Verdict | Abstract Median (ms) | Fallback Routed? | Symbolic Verdict | Overall Disposition | Overall Verdict | E2E Median (ms) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **A01_straight_small** | A_straight | `UNKNOWN` (ALU32 `w0=0x2`) | 113.2 ms | **Yes** | `SAFE` | `symbolic_pass` | `SAFE` | 898.6 ms |
| **A02_straight_medium** | A_straight | `UNKNOWN` (ALU32 load) | 112.3 ms | **Yes** | `UNKNOWN` (Lifter error) | `unresolved` | `UNKNOWN` | 357.5 ms |
| **A03_helper_clock** | A_straight | `VIOLATION` (Helper 14) | 112.0 ms | **No (Bypassed)** | *None* | `violation` | `VIOLATION` | 112.4 ms |
| **B01_branch_safe** | B_branch | `UNKNOWN` (ALU32/branch) | 119.8 ms | **Yes** | `SAFE` | `symbolic_pass` | `SAFE` | 943.8 ms |
| **B02_branch_policy_sens**| B_branch | `VIOLATION` (Policy limit) | 117.4 ms | **No (Bypassed)** | *None* | `violation` | `VIOLATION` | 117.8 ms |
| **C01_join_diff_values** | C_join | `UNKNOWN` (Join state) | 121.3 ms | **Yes** | `UNKNOWN` (Lifter error) | `unresolved` | `UNKNOWN` | 417.0 ms |
| **C02_join_policy_sens** | C_join | `UNKNOWN` (Join state) | 130.9 ms | **Yes** | `UNKNOWN` (Lifter error) | `unresolved` | `UNKNOWN` | 430.1 ms |
| **D01_helper_unknown** | D_unknown | `VIOLATION` (Helper 9999) | 112.4 ms | **No (Bypassed)** | *None* | `violation` | `VIOLATION` | 112.6 ms |
| **D02_packet_memory** | D_unknown | `UNKNOWN` (Packet memory) | 109.0 ms | **Yes** | `UNKNOWN` (Lifter error) | `unresolved` | `UNKNOWN` | 354.6 ms |
| **E01_bounded_loop** | E_loop | `UNKNOWN` (Backedge) | 108.9 ms | **Yes** | `UNKNOWN` (Lifter error) | `unresolved` | `UNKNOWN` | 360.3 ms |

### Detailed Routing Observations:

1. **Fast-Path Abstract Bypass:**
   - `A03_helper_clock`: Calling helper `bpf_ktime_get_ns` (ID 14), which is absent from the policy helper allowlist (`[1]`), is immediately detected as a violation by the abstract interpreter.
   - `B02_branch_policy_sensitive`: Path condition explores assignment exceeding allowed range, correctly triggering abstract violation.
   - `D01_helper_unknown_candidate`: Nonexistent helper ID 9999 is outside allowlist, correctly flagged as abstract violation.
   - **Timing Impact:** Fast-path violations completed in ~112–118 ms total time, completely eliminating the 800–1500 ms symbolic execution overhead.
2. **Symbolic Fallback Execution:**
   - `A01_straight_small` and `B01_branch_safe`: Successfully lifted and verified by KRAKENGUARD's KLEE backend, proving compliance in 898 ms and 944 ms respectively.
3. **Fail-Closed Unresolved Diagnoses:**
   - `A02_straight_medium`, `C01`, `C02`, `D02`, `E01`: When routed to KRAKENGUARD, the container's legacy `bpflifter_cli` tool failed during LLVM optimization with `explicit pointee type doesn't match operand's pointee type (i32 vs i64)` (e.g. `%13 = load i32, i64* %r1`).
   - The runner caught the processing error cleanly, set `symbolic_verdict: "UNKNOWN"`, and assigned `disposition: "unresolved"`.
   - **Soundness Guarantee:** These fixtures demonstrate that tool errors in the symbolic verifier fail closed without generating false safe verdicts.

---

## 5. Scope Boundary Audit: Whole-Program Orchestration vs. Region-Level Verification

The empirical data highlights the exact architectural distinction between the current prototype and genuine region-level verification:

```
+-----------------------------------------------------------------------------------+
|                           CURRENT PROTOTYPE ARCHITECTURE                          |
|                                                                                   |
|    Compiled ELF Binary                                                            |
|             |                                                                     |
|             v                                                                     |
|    Abstract Interpreter --------[ SAFE / VIOLATION ]--------> Immediate Verdict   |
|             |                                                  (Bypass Symbolic)  |
|         (UNKNOWN)                                                                 |
|             |                                                                     |
|             v                                                                     |
|    Symbolic Verifier ----------[ SAFE / VIOLATION ]---------> Fallback Verdict    |
|    (WHOLE-PROGRAM SCOPE)                |                                         |
|                                      (ERROR)                                      |
|                                         |                                         |
|                                         v                                         |
|                               Fail-Closed UNRESOLVED                              |
+-----------------------------------------------------------------------------------+
```

### What Is Currently Implemented:
- Extraction of CFG basic blocks and reverse-postorder traversal (`split_analyze_bypass.py`).
- Deterministic gating: early-exit on definitive abstract verdicts (`abstract_pass`, `violation`).
- Routing to whole-program symbolic verification when abstract analysis returns `UNKNOWN`.
- Fail-closed exception and error handling across workers.

### What Is NOT Implemented (Genuine Region-Level Verification Gap):
1. **Region Entry Abstract State API:**
   The analyzer operates on `(object, policy)` at entry PC 0 with blank registers. It does not accept `(entry_block_id, incoming_abstract_state, policy)`.
2. **Inter-Block Transfer & Join Functions:**
   The analyzer has no join operator ($\sqcup$) to soundly merge incoming abstract states from multiple CFG predecessors (e.g. at join nodes in `C01` and `C02`).
3. **Block-Level Symbolic Slicing:**
   When a region yields `UNKNOWN`, there is no mechanism to slice that specific basic block or subgraph into an isolated LLVM IR module for symbolic execution with bounded path constraints.
4. **Conclusion:** Claiming region- or basic-block-level verification based solely on the current CFG metadata extraction would be scientifically unsound. The current prototype is strictly an **ELF-level orchestration and gating architecture**.

---

## 6. Next Steps & Recommended Follow-on Tasks

1. **Task 4 (Formalize Region-Level API Contract):**
   Design and specify the interface contract for an abstract interpreter that accepts an explicit `IncomingAbstractState`, `RegionBoundary`, and `PathConstraints`.
2. **Task 5 (Patch / Modernize LLVM Lifter):**
   Address the legacy `bpflifter_cli` LLVM 13 pointer mismatch on ALU32 sub-register instructions (`i32` vs `i64*`) to allow symbolic fallback to successfully lift medium and join fixtures.
3. **Task 6 (Controlled Evaluation Notebook):**
   Construct the Jupyter visualization notebook integrating `corpus-manifest.json` and the validated `summary.json` benchmarks.
