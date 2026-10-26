# Project Memory Log (`MEMORY.md`)

> Durable handoff document for coding agents and researchers working on eBPF hybrid policy verification.
> Last updated: 2026-10-22 | Current HEAD: `ce2cebe` on branch `main`.

---

## 1. Project Purpose

* **Research Objective:** Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification. The goal is to determine whether placing a lightweight three-valued abstract interpreter ahead of a symbolic verifier can reduce end-to-end policy-verification cost without weakening security guarantees.
* **Scope Boundary — Orchestration vs. Region-Level Verification:**
  * **Whole-Program Orchestration (`IMPLEMENTED / VERIFIED`):** The current prototype routes complete compiled eBPF ELF binaries to either an abstract analyzer (fast path) or a frozen KRAKENGUARD symbolic verifier fallback when unresolved.
  * **Region-Level Abstract Interpretation & CFG State Propagation (`IMPLEMENTED in Task 6 / VERIFIED`):** Implemented in `research/experiments/split_bypass/scripts/region_analyzer.py`. Accepts explicit incoming abstract states, transfers 64/32-bit registers and policy constraints across basic blocks/regions, joins multi-predecessor states soundly, detects cycles/loops, and composes verdicts via `ProgramVerdictComposer`.
  * **Region-Scoped Symbolic Fallback (`NOT IMPLEMENTED`):** Symbolic fallback via KRAKENGUARD operates strictly at whole-ELF granularity. There is no region-scoped symbolic fallback backend; KRAKENGUARD remains explicitly classified as `WHOLE_PROGRAM`.

---

## 2. Current Architecture

* **Abstract Analyzer (`research/analyzer/abstract_policy_analyzer.py`):**
  * Git Blob: `ca07c1ad340e4220f227a8051b91a62faa0dce5d` (`VERIFIED`).
  * Evaluates compiled eBPF instructions against JSON-defined policies (allowed memory read/write intervals, helper function allowlists, return value bounds).
  * Three-valued lattice: `SAFE`, `VIOLATION`, or `UNKNOWN`.
  * Returns `UNKNOWN` conservatively on unresolved conditional branches, unmodeled helper IDs, unmodeled packet store instructions, or analysis errors (`VERIFIED`).
* **Symbolic Verifier Baseline (`research/baselines/krakenguard/artifact`):**
  * Submodule at commit `e7bd840` with local uncommitted patch in `lifting_tools/generateIR.py` ensuring unmapped BPF maps receive synthetic IDs.
  * Pipeline: eBPF bytecode $\to$ LLVM IR lifter (`bpflifter_cli`) $\to$ function passes $\to$ KLEE symbolic execution $\to$ conditional policy oracle.
  * Emits `COMPLIANT` or `POLICY VIOLATION`. Fails closed (`UNKNOWN`) on lifter crashes, malformed outputs, or execution timeouts.
* **Orchestration Runner (`research/experiments/scripts/split_analyze_bypass.py` & `work/run_comparison.py`):**
  * `SAFE` $\to$ Discharged immediately as compliant (`abstract_pass`); symbolic execution bypassed.
  * `VIOLATION` $\to$ Discharged immediately as policy violation; symbolic execution bypassed.
  * `UNKNOWN` $\to$ Routed to symbolic fallback (`symbolic_pass` or `violation`).
  * Timeouts, tool errors, or missing verdicts $\to$ Fails closed as `unresolved` / `UNKNOWN` (`VERIFIED`). Never counted as compliant.

---

## 3. Repository Map

```text
├── MEMORY.md                                       # Durable handoff context (this file)
├── results.md                                      # 12-section living dissertation results record
├── evidence_ledger.csv                             # Authoritative 28-row claim-by-claim verification ledger
├── docs/manuscript/
│   ├── docx/
│   │   ├── Paper-Final.docx                        # Preserved baseline user manuscript (10 pages)
│   │   ├── Paper-Final-Audited.docx                # Audited Word manuscript (strictly 11 pages)
│   │   └── Paper-Final-Audited.pdf                 # Reference LibreOffice PDF export (11 pages)
│   └── final_research_summary.md                   # Metric reconciliation table, viva Q&As, Katran forensic analysis
├── research/
│   ├── analyzer/
│   │   └── abstract_policy_analyzer.py             # Three-valued abstract interpreter
│   ├── baselines/krakenguard/artifact/             # Frozen KRAKENGUARD submodule (lifting + KLEE)
│   ├── experiments/
│   │   ├── corpus/phase5/                          # 24-program benchmark corpus (Groups A, B, C, D)
│   │   ├── design/split-analyze-bypass-prototype.md # Split-Analyze-Bypass architecture and limits
│   │   ├── results/
│   │   │   ├── split_bypass_preflight/             # Preflight fixture compilation logs, ELFs, disassemblies
│   │   │   └── split-analyze-bypass/REPORT.md      # Integration status report
│   │   ├── scripts/split_analyze_bypass.py         # CFG extraction and gating runner
│   │   ├── split_bypass/                           # Controlled evaluation suite
│   │   │   ├── manifests/corpus-manifest.json      # Versioned, provenance-tracked corpus manifest (10 fixtures)
│   │   │   ├── policies/                           # Versioned experiment policy copies
│   │   │   ├── programs/                           # 10 compiled fixture sources (.c) and objects (.o)
│   │   │   ├── scripts/
│   │   │   │   ├── prepare_corpus.py               # Corpus manifest and compilation generator
│   │   │   │   └── analyze_runs.py                 # Summary and paired uncertainty analyzer
│   │   │   └── tests/test_controlled_evaluation.py # Evaluator unit tests
│   │   └── tests/
│   │       ├── test_split_analyze_bypass.py        # Runner and CFG tests
│   │       └── test_split_bypass_corpus.py         # Adapter exposing controlled evaluation tests
│   └── tests/                                      # Regression tests (test_analysis_audit.py, test_phase5_e3_e4_e5_audit.py)
└── work/
    ├── analyze_comparison.py                       # 504-row transparent comparative analysis script
    └── results/                                    # 648 raw runs, runs.csv, analysis.json, paired-comparison.csv
```

---

## 4. Experimental History & Dataset Provenance

Datasets must be kept strictly separate. Do not substitute metrics from one dataset into another:

| Dataset / Experiment | Runs & Design | Verified Findings (`VERIFIED`) | Limitations / Status |
| :--- | :--- | :--- | :--- |
| **Baseline E1** | 72 total (56 measured), 8 programs (2–20 insns) | Verification time 672.4–707.6 ms (5.2% variation); instruction count does not drive verification cost | Micro-corpus; only single- and two-path programs (`VERIFIED`) |
| **Baseline E2** | 63 total (49 measured), 1–64 feasible paths | Cost scales near-linearly ($R^2 > 0.999$): $T(P) \approx 740\text{ ms} + 7.6\text{ ms} \cdot P$. Median: 746 ms (1 path) to 1,231 ms (64 paths) | Fixed pipeline overhead accounts for ~730 ms (`VERIFIED`) |
| **Historical Phase 5 (E3–E5)** | 432 total (336 measured across 24 programs) | 50.0% discharge (12/24); paired median saving 45.53%; aggregate reduction 44.93% | `REPORTED BUT NOT REPRODUCED` from historical branch commits due to commit/dataset branch provenance separation |
| **Comparative Workbench** | 648 total (504 measured: 24 programs $\times$ 3 modes $\times$ 7 reps) | **Discharge:** 50.0% (12/24). **Savings:** 46.16% paired median, 45.71% aggregate, 46.05% pooled. **Correctness:** 420 definitive verdicts (100% agreement, 0 false SAFEs, 0 false VIOLATIONs) + 84 conservative UNKNOWN abstentions in `abstract_only` | **Significance:** Two-sided sign test $p = 1.0$ (12 pos, 12 neg); bootstrap 95% CI $[-31.62\text{ ms}, +670.72\text{ ms}]$ spans zero. Overall speedup is **not statistically significant** on balanced 50/50 corpus (`VERIFIED`) |
| **Katran Case Study** | Real-world Meta XDP load balancer (`bpf_balancer.c`) | Clang cleanly compiled 134 KB ELF bytecode (`katran-upstream.o`). Abstract analyzer safely emitted `UNKNOWN`. | **Failed at Lifter:** KRAKENGUARD `bpflifter_cli` crashed on LLVM GEP opaque pointer assertion (`Instructions.h:960`). 0 verdicts. Status: `COMPILED BUT LIFTING FAILED` (`VERIFIED`) |

---

## 5. Current Task & Progress (Task 6: Region-Level Abstract Interpretation & Sound CFG State Propagation)

* **Task 4 Deliverables Confirmed (`VERIFIED`):**
  * Formalized region-level API contract in [`research/experiments/split_bypass/REGION_API_CONTRACT.md`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/REGION_API_CONTRACT.md).
  * Implemented typed contract module [`research/experiments/split_bypass/scripts/region_contract.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/region_contract.py) with 11 contract-level unit tests.
* **Task 5 Deliverables Confirmed (`VERIFIED`):**
  * Remediated `bpflifter_cli` and `generateIR.py` ALU32 pointer mismatch (`load i32, i64* %rX`), added `sanitize_lifted_ir.py` and unit tests in `test_lifter_alu32_semantics.py`. Verified all 5 failing fixtures in container; authored [`TASK5_LLVM_LIFTER_REPORT.md`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/TASK5_LLVM_LIFTER_REPORT.md).
* **Task 8 Stack Memory Modeling & Ground-Truth Oracle Assignment (`VERIFIED`):**
  * **Stack Frame Modeling (`research/experiments/split_bypass/scripts/region_analyzer.py`):**
    * Differentiated the BPF frame pointer `r10` from packet/map registers (`r1..r9`). Enforced 512-byte eBPF stack frame bounds (`[-512, 0)`).
    * Implemented width-aware tracking (`u8`, `u16`, `u32`, `u64`), overlapping slot invalidation, uninitialized read handling, and predecessor stack joins ($\sqcup$).
    * Packet writes (`r1..r9`) under policy `"write-access": ["x"]` continue to trigger `RegionVerdict.VIOLATION`.
  * **Fixture Discharge Behavior:** All 9 acyclic compliant fixtures (`A01`–`D02`) discharge cleanly as `SAFE`. `E01_bounded_loop` has stack stores modeled without error, but correctly halts with `UNKNOWN` on the CFG back-edge cycle.
  * **Reference Oracles Assigned (`corpus-manifest.json`):** Formally assigned and documented independent reference verdicts (`SAFE` under E1 policy `policy-c0f0ac4d1a5e.json`) for all 10 fixtures with ISA and policy justifications.
  * **Automated Test Results (116/116 Tests Passing, 100% Green):**
    1. `pytest research/experiments/split_bypass/tests/test_region_analyzer.py -v` $\to$ **27 PASSED, 0 FAILED** (8 new stack memory tests).
    2. `pytest research/experiments/split_bypass/tests/ research/experiments/tests/ -v` $\to$ **84 PASSED, 20 subtests passed (104 test items)**.
    3. `PYTHONPATH=. pytest -v research/tests/test_phase5_abstract_soundness.py` $\to$ **12 PASSED, 0 FAILED**.
  * **Report:** Authored [`TASK8_STACK_MEMORY_AND_ORACLE_REPORT.md`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/TASK8_STACK_MEMORY_AND_ORACLE_REPORT.md).

---

## 6. Environment & Reproducibility

* **Operating System:** Linux (x86_64)
* **Python Runtime:** Python 3.14.7 (`/usr/bin/python`)
* **C Compiler:** Clang 23.1.1 (`/usr/bin/clang`)
* **Target Architecture:** BPF (`-target bpf -D__TARGET_ARCH_x86 -O2 -g -I/usr/include -c`)
* **BPF Headers:** `/usr/include/linux/bpf.h` (286,467 bytes), `/usr/include/bpf/bpf_helpers.h`
* **Inspection Tool:** LLVM Object Dump 23.1.1 (`/usr/bin/llvm-objdump`)
* **Reference Policy:** `research/experiments/corpus/policies/p1_allow_execution.json` (SHA256: `c0f0ac4d...`)

---

## 7. Known Limitations and Tooling Risks

1. **Analysis Tooling — Warmup Ingestion (`RESOLVED in Task 3`):** `analyze_runs.py` automatically filters out rows marked `"is_warmup": true` when computing latency medians, means, and paired comparisons.
2. **Analysis Tooling — Paired Timing Denominators (`KNOWN LIMITATION`):** Paired latency differences and bootstrap confidence intervals are computed strictly over rows sharing identical `pair_id` attributes. Unpaired records are excluded from paired comparisons.
3. **Region-Level Transfer Functions & Join Propagation (`RESOLVED in Task 6`):** Implemented in `region_analyzer.py` with `analyze_region(...)`, 64/32-bit ALU transfer functions, and lattice joins ($\sqcup$).
4. **Stack Memory Modeling (`RESOLVED in Task 8`):** Width-aware, bound-checked eBPF stack frame modeling (`r10` within 512B) is implemented in `region_analyzer.py`. Fixed the conflation between stack spills and packet writes. Acyclic compliant fixtures (`A01`–`D02`) discharge cleanly as `SAFE`.
5. **Evaluation Pipeline Disconnect (`BLOCKER for Benchmark Execution`):** `split_analyze_bypass.py` and `run_smoke.py` currently invoke only the legacy whole-program `AbstractPolicyAnalyzer`. Upgrading the runner to support Mode C (`region_hybrid`) is scheduled for Task 9.
6. **Ground-Truth Reference Oracles (`RESOLVED in Task 8`):** All 10 fixtures in `corpus-manifest.json` have verified, independently justified reference verdicts (`SAFE` under E1 policy `policy-c0f0ac4d1a5e.json`).
7. **Symbolic Fallback Granularity Boundary (`PRESERVED CONSTRAINT`):** KRAKENGUARD's pipeline operates strictly on full ELF object files. Whole-program fallback is explicitly classified as `WHOLE_PROGRAM` and prohibited from mislabeling as region-scoped.
8. **LLVM Lifter ALU32 Type Crash (`RESOLVED in Task 5`):** Fixed typed pointer load mismatch in `instr_utils.cpp` and `generateIR.py`. Recompiled lifter natively produces valid typed IR; verified on all 5 corpus fixtures in container.

---

## 8. Next Steps Checklist for Subsequent Agents

- [x] **Task 1 (Preflight Compilation & Memory):** Merged experiment commits, compiled 10 fixtures, established CFG preflight summary.
- [x] **Task 2 (Evaluation Tests & Corpus Manifest):** Fixed `test_controlled_evaluation.py:57`, added multi-program isolation tests, generated canonical `corpus-manifest.json`.
- [x] **Task 3 (Controlled Smoke Experiment & Routing Audit):** Enhanced `analyze_runs.py` with warmup filtering and granular error accounting, executed 30-run smoke experiment, verified early-exit bypass, symbolic fallback, and fail-closed handling, authored `TASK3_SMOKE_REPORT.md`.
- [x] **Task 4 (Formalize Region-Level API Contract):** Authored `REGION_API_CONTRACT.md`, implemented typed contract classes and validators in `region_contract.py`, added 11 contract unit tests in `test_region_contract.py`, authored `TASK4_REGION_API_REPORT.md`.
- [x] **Task 5 (LLVM Lifter Remediation):** Remediated `bpflifter_cli` and `generateIR.py` ALU32 pointer mismatch, added `sanitize_lifted_ir.py` and unit tests in `test_lifter_alu32_semantics.py`, verified all 5 failing fixtures in container, authored `TASK5_LLVM_LIFTER_REPORT.md`.
- [x] **Task 6 (Region Abstract Analyzer Implementation):** Implemented `region_analyzer.py` with `analyze_region(...)`, 32/64-bit ALU transfers, CFG state propagation with `join()`, cycle/back-edge detection, and sound composition via `ProgramVerdictComposer`. Authored `TASK6_REGION_ANALYSIS_REPORT.md`.
- [x] **Task 7 (Architecture Progress Audit & Readiness Assessment):** Audited 15 core capabilities, confirmed standalone execution across 10 fixtures, uncovered runner disconnect and stack-spill false UNKNOWNs, defined 3-way evaluation plan, authored `TASK7_PROGRESS_AND_EVALUATION_READINESS.md`.
- [x] **Task 8 (Stack Memory Modeling & Ground-Truth Oracle Assignment):** Modeled safe stack-frame read/writes (`r10` within 512B) in `region_analyzer.py`, added 8 unit tests in `test_region_analyzer.py`, assigned independently justified reference oracles in `corpus-manifest.json`, authored `TASK8_STACK_MEMORY_AND_ORACLE_REPORT.md`.
- [x] **Task 9 (Tri-Mode Runner Integration & Telemetry):** Upgraded `split_analyze_bypass.py` and implemented `run_evaluation.py` to support `--mode [symbolic_only | whole_hybrid | region_hybrid]`. Mode A dispatches directly to KRAKENGUARD, Mode B runs legacy whole-program analyzer with whole-program fallback, and Mode C runs Task 6/8 region analyzer with whole-program fallback. Added 21 validation tests in `test_tri_mode_runner.py` verifying mode dispatch, fail-closed handling, telemetry schema, oracle agreement, and warmup exclusion. Authored `TASK9_RUNNER_INTEGRATION_REPORT.md`.
- [x] **Task 10 (3-Way Comparative Benchmark Execution):** Executed the full 120-run comparative benchmark (10 fixtures $\times$ 3 modes $\times$ [1 warmup + 3 measured] = 120 runs) in 76.36s. Mode C (`region_hybrid`) achieved 119.51ms median latency (6.63× speedup over symbolic-only, 7.52× over legacy hybrid), 10.0% fallback rate, and 100% oracle agreement. Mode A incurred 3 KLEE crashes on D01 (fail-closed ERROR). Paired bootstrap analysis ($N=30$, 5,000 samples) confirmed statistically significant latency reductions ($p < 0.001$, CI $[+485.33, +671.65]$ ms over Mode A). Authored `TASK10_BENCHMARK_REPORT.md`.
- [x] **Task 11A (Katran Real-World Case Study):** Profiled all 4 compiled Katran ELF variants. Isolated lifter crashes to unhandled BPF-to-BPF local calls (`EBPF_OP_CALL | 0x8`) with cross-section relocations to `.text` and typed GEP pointer mismatches. Demonstrated that `katran-upstream-clang13.o` inlined functions and lifted cleanly to LLVM IR (`final_linked_ir.bc`), but timed out in KLEE at 180s due to state explosion across 66 BPF maps. Enforced correctness gate on Mode C: audited PC 18/22 stores as map values (`stats` map pointer in `r0`), diagnosed the raw violation as spurious due to lack of pointer provenance, and assigned authoritative oracle as `INCONCLUSIVE`. Authored `KATRAN_CASE_STUDY_REPORT.md`.
- [x] **Task 12 (Region-Scoped Symbolic Fallback Audit & Interface Implementation):** Audited end-to-end CFG data flow, merge joins, and KRAKENGUARD/KLEE interface boundaries. Implemented `RegionSymbolicRequest`/`RegionSymbolicResponse` contracts and `DirectRegionSymbolicExecutor` with relational pointer provenance (`packet` vs `map_val` vs `stack`). Developed 9-scenario correctness test suite in `test_region_scoped_fallback.py` (126/126 total repository tests passing). Verified that baseline KRAKENGUARD cannot ingest non-ELF slices, necessitating whole-program fallback while truthfully reporting `backend_executor_scope`. Authored `REGION_SCOPED_FALLBACK_REPORT.md`.
- [ ] **Task 11B (Analysis, Visualizations, & Manuscript Update):** Construct Jupyter visualization notebook, generate latency distribution figures, update `evidence_ledger.csv`, and reconcile manuscript findings.
