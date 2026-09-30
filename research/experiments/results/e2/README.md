# Phase 4 E2 — Full Matrix Execution Results & Statistical Report

## 1. Executive Summary

- **Experiment ID**: Phase 4 E2 Full Matrix Replication
- **Research Question**: *How does KRAKENGUARD verification cost change as feasible symbolic execution path count increases from the validated 1–16 path regime to higher controlled path levels, while the policy, verifier revision, environment, compiler configuration, hook, and program family remain fixed?*
- **Execution Date**: 2026-09-30
- **Host System**: Linux `7.2.3-arch1-2` x86_64, AMD Ryzen 5 5600H (6 cores / 12 threads), 7.1 GiB RAM
- **Toolchain**: Clang `22.1.8`, bpftool `7.8.0`, Docker `29.7.2`
- **KRAKENGUARD Baseline Commit**: `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- **Security Policy**: `research/experiments/corpus/e1/policies/e1_fixed_policy.json` (SHA-256: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`)
- **Execution Scope**: Exactly 63 executions (14 warmups + 49 measured runs) across 7 program levels in Blocked / Interleaved order.
- **Audit Verdict**: **`AUDIT PASS — FULL DATASET VERIFIED`**

---

## 2. Invariant & Environment Provenance

| Parameter | Specification | Live Verified State | Status |
| :--- | :--- | :--- | :--- |
| **Git Branch** | `phase4-e2-full-matrix` | `phase4-e2-full-matrix` (Commit `dfaaa8e`) | **PASS** |
| **Host Kernel** | Linux 7.2.3-arch1-2 | `7.2.3-arch1-2 x86_64` | **PASS** |
| **Compiler** | Clang 22.1.8 | `-target bpf -mcpu=v1 -O2 -g -D__TARGET_ARCH_x86 -I/usr/include` | **PASS** |
| **Verifier Container** | `artifact-krakenguard:latest` | Container `krakenguard` (Up 8 hours, healthy) | **PASS** |
| **Baseline Commit** | `e7bd84005b304c5a10efcdb04914d1882b3cccf7` | Matches container baseline image | **PASS** |
| **Fixed Policy** | `e1_fixed_policy.json` | SHA-256: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603` | **PASS** |
| **Symbolic Helper** | Pure `bpf_ktime_get_ns()` | Helper ID 5, 0 maps, 0 loops | **PASS** |
| **Hook Type** | XDP | `SEC("xdp")` across all 7 programs | **PASS** |

---

## 3. Dataset Integrity Audit Results

Prior to computing statistical conclusions, an independent automated audit was executed on all raw data (`audit.json` / `audit.md`):
- **Planned vs Executed Runs**: Exactly 63 planned runs $\to$ 63 executed runs (14 warmups + 49 measured).
- **Timeouts / Failures**: 0 timeouts, 0 failures. 100% of runs completed with execution status `success` and verifier verdict `VERIFIED`.
- **Observed Path Monotonicity**: Exactly $[1, 2, 4, 8, 16, 32, 64]$. The observed KLEE explored path ladder perfectly matched the theoretical model $2^k$.
- **Completed Paths Verification**: 100% of explored paths completed cleanly (`klee_completed_paths == klee_paths_explored`), confirming the anchored regex parser fix.
- **Raw Log vs Aggregate Agreement**: 100% concordance between raw KLEE `info` logs, raw stdout/stderr logs, `e2-results.csv`, and `e2-results.json`.

---

## 4. Empirical Statistical Summary (49 Measured Observations)

Warmup runs ($n = 2$ per level) are strictly isolated and excluded from descriptive statistics. The table below reports the empirical distribution across the $n = 7$ measured runs per level:

| Program ID | Predicates ($k$) | Target Paths ($2^k$) | Observed Feasible Paths | Z3 Queries | N | Median Wall Time (ms) | Mean Wall Time (ms) | StdDev (ms) | CV | Min Wall Time (ms) | Max Wall Time (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E2-P0** | 0 | 1 | **1** | 1 | 7 | **746.14** | 757.28 | 34.55 | 0.0456 | 728.68 | 833.28 |
| **E2-P1** | 1 | 2 | **2** | 2 | 7 | **749.93** | 752.64 | 18.59 | 0.0247 | 721.32 | 783.98 |
| **E2-P2** | 2 | 4 | **4** | 4 | 7 | **762.77** | 770.22 | 28.96 | 0.0376 | 745.65 | 831.15 |
| **E2-P3** | 3 | 8 | **8** | 8 | 7 | **789.88** | 789.19 | 10.73 | 0.0136 | 772.99 | 802.17 |
| **E2-P4** | 4 | 16 | **16** | 16 | 7 | **853.02** | 854.79 | 11.25 | 0.0132 | 842.36 | 870.63 |
| **E2-P5** | 5 | 32 | **32** | 32 | 7 | **973.44** | 972.45 | 7.97 | 0.0082 | 961.65 | 981.92 |
| **E2-P6** | 6 | 64 | **64** | 64 | 7 | **1231.16** | 1266.86 | 56.61 | 0.0447 | 1213.62 | 1334.89 |

*Note on secondary telemetry: Peak memory and solver time were not exposed by the baseline daemon and are recorded as `NOT_REPORTED`. Client-process CPU time (`time.process_time()`) averaged ~0.6 ms per run and represents client IPC overhead only.*

---

## 5. Primary Analysis: Symbolic Path Scaling vs Verification Cost

### Empirical Scaling Pattern
Plotting median end-to-end verification time against observed feasible KLEE paths reveals:
1. **Low-Path Regime ($1 \to 4$ paths)**: Verification time is dominated by fixed translation and pipeline setup overhead (~740–760 ms), matching the flat regime observed in Experiment E1.
2. **Path Growth Regime ($8 \to 64$ paths)**: As symbolic path counts increase beyond 4, verification cost departs decisively from the flat baseline and exhibits steady, monotonic growth.
3. **Linearity with Respect to Feasible Paths**:
   Across the tested range ($P \in [1, 64]$), end-to-end verification wall-clock time exhibits an almost perfectly linear relationship with respect to the number of explored feasible paths $P$:
   $$T(P) \approx T_{\text{base}} + c \cdot P$$
   where $T_{\text{base}} \approx 740\text{ ms}$ represents lifter/harness initialization, and $c \approx 7.6\text{ ms per path}$ represents the incremental symbolic execution and solver dispatch cost.
4. **Exponential Scaling with Respect to Branch Predicates ($k$)**:
   Because each orthogonal predicate doubles the reachable path count ($P = 2^k$), the end-to-end cost as a function of predicate count scales as:
   $$T(k) \approx 740\text{ ms} + 7.6\text{ ms} \times 2^k$$
   Between $k=0$ (1 path, 746 ms) and $k=6$ (64 paths, 1231 ms), end-to-end verification time increases by **+485 ms (+65.0%)**.

---

## 6. Contrast with Experiment E1

| Dimension | Experiment E1 (Complexity Baseline) | Experiment E2 (Symbolic Path Scaling) |
| :--- | :--- | :--- |
| **Independent Variable** | Micro-program complexity (instructions, maps, helpers) | Feasible symbolic execution paths ($1 \to 64$) |
| **Tested Range** | 2–20 bytecode instructions | 1–64 feasible paths (7–43 bytecode instructions) |
| **Observed Scaling** | Flat (~700–850 ms, dominated by ~95% fixed translation) | Clear transition from flat translation overhead to path-dominated cost |
| **Observed Z3 Queries** | 0 to 3 queries | Exactly $2^k$ queries (1 to 64 queries) |
| **Scaling Boundary** | Not observed in E1 (paths stayed at 1–2) | Observed in E2: path growth adds ~7.6 ms/path, increasing total time by 65% |

---

## 7. Research Interpretation Boundaries

In adherence to scientific integrity guidelines:

### What is Established (Observed Facts)
- In the frozen KRAKENGUARD baseline environment, increasing feasible symbolic paths from 1 to 64 strictly scales the solver query count $1:1$ with paths ($Q = P = 2^k$).
- Verification wall-clock time increases monotonically with path count, rising from 746 ms (1 path) to 1231 ms (64 paths).
- The incremental cost per path is approximately 7.6 ms under the tested hardware and solver configuration.

### What is Inferred (Valid Deductions)
- The flat overhead observed in E1 was an artifact of remaining in the 1–2 path regime; once feasible paths exceed ~8, symbolic exploration cost becomes a measurable fraction of total verification time.
- Hypothesis **H1** is supported: increasing feasible symbolic path counts produces measurable, statistically significant increases in end-to-end verification cost.

### What is NOT Established (Strictly Prohibited Claims)
- We do **not** claim general or asymptotic exponential complexity for arbitrary eBPF programs.
- We do **not** claim memory scaling or state explosion, as memory was unmeasured and all 64 paths completed within 1.3 seconds.
- We do **not** claim superiority or inferiority of the hybrid verifier over KRAKENGUARD, as the hybrid verifier has not yet been benchmarked on this corpus.

---

## 8. Repository Artifact Inventory

- `research/experiments/results/e2/e2-results.csv`: Complete dataset (63 runs with static and runtime metrics).
- `research/experiments/results/e2/e2-results.json`: Full structured JSON dataset with complete provenance.
- `research/experiments/results/e2/audit.md` & `audit.json`: Post-execution data integrity audit report.
- `research/experiments/results/e2/raw/`: Complete raw compiler logs, objdump disassemblies, readelf headers, bpftool BTF dumps, daemon stdout/stderr, and KLEE `info` logs for all 63 executions.
- `research/experiments/scripts/execute-e2-matrix.py`: Audited matrix execution orchestrator.
- `research/experiments/scripts/audit-e2-matrix.py`: Dataset integrity audit script.
