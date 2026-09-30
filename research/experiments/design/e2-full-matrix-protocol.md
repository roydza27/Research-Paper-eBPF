# Phase 4 E2 — Full Matrix Experimental Protocol, Statistical Design & Final Execution Gate

## 1. Research Question

The core research question of the broader project is:
> *Can fine-grained eBPF isolation policies be checked with predictable cost by combining inexpensive abstract analysis with selective symbolic execution?*

While Phase 4 Experiment E1 established the baseline cost of KRAKENGUARD across micro-program complexity dimensions (finding a flat pipeline overhead dominated by lifter and harness translation), E1 never reached meaningful symbolic path growth ($1–2$ paths). 

The specific research question for Phase 4 Experiment E2 is:
> **How does KRAKENGUARD verification cost change as feasible symbolic execution path count increases from the validated 1–16 path regime to higher controlled path levels, while the policy, verifier revision, environment, compiler configuration, hook, and program family remain fixed?**

The objective is to identify whether and where the flat micro-program regime observed in E1 begins to change under actual symbolic path growth.

---

## 2. Hypothesis

> **H1: Increasing feasible symbolic path counts will increase symbolic exploration and solver activity, and at sufficiently high path counts will produce a measurable increase in end-to-end verification cost relative to the low-path baseline.**

In accordance with strict scientific discipline:
- We do not hypothesize or assume exponential scaling a priori.
- The hypothesis is falsifiable: if end-to-end timing remains flat up to 64 paths, H1 is rejected within the tested regime.

---

## 3. Pilot Outcome

The Phase 4 E2 Pilot Gate successfully executed on the research host with 1 execution per level for programs E2-P0 through E2-P4:

| Program ID | Intended Predicates | Compiled Insts | Compiled Branches | Observed KLEE Explored Paths | Solver Queries | Wall-Clock Time | Verifier Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E2-P0** | 0 | 7 | 1 | **1** | 1 | 744.24 ms | VERIFIED |
| **E2-P1** | 1 | 13 | 2 | **2** | 2 | 740.08 ms | VERIFIED |
| **E2-P2** | 2 | 19 | 3 | **4** | 4 | 734.96 ms | VERIFIED |
| **E2-P3** | 3 | 25 | 4 | **8** | 8 | 783.94 ms | VERIFIED |
| **E2-P4** | 4 | 31 | 5 | **16** | 16 | 834.51 ms | VERIFIED |

**Pilot Decision**: **`PILOT PASS — READY FOR FULL MATRIX PROPOSAL`** (delivered in [PR #13](https://github.com/roydza27/Research-Paper-eBPF/pull/13)).

### Architecture Established During Pilot
During pilot investigation, stack-allocated volatile sinks were found to be eliminated by LLVM Dead-Store Elimination (`opt -O3`) in KRAKENGUARD's lifted IR pipeline. The validated architecture routes symbolic data from `bpf_ktime_get_ns()` through orthogonal bitmask predicates that mutate external packet memory (`ctx->data`):
```text
bpf_ktime_get_ns() -> 64-bit symbolic value -> independent bit predicates -> packet-memory bitmask mutations -> surviving control flow -> KLEE symbolic path exploration
```

---

## 4. Full Corpus Specification

The full E2 corpus extends the validated P0–P4 pilot corpus to 7 levels using identical bitwise orthogonal predicates:

| Program ID | Source File | Predicates ($k$) | Target Paths ($2^k$) | Bitmask Predicates | Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **E2-P0** | `corpus/e2/programs/e2_p0.c` | 0 | 1 | None | Symbolic baseline |
| **E2-P1** | `corpus/e2/programs/e2_p1.c` | 1 | 2 | `t & (1ULL << 0)` | 1 symbolic split |
| **E2-P2** | `corpus/e2/programs/e2_p2.c` | 2 | 4 | Bits 0, 1 | 2 symbolic splits |
| **E2-P3** | `corpus/e2/programs/e2_p3.c` | 3 | 8 | Bits 0, 1, 2 | 3 symbolic splits |
| **E2-P4** | `corpus/e2/programs/e2_p4.c` | 4 | 16 | Bits 0, 1, 2, 3 | Pilot upper level |
| **E2-P5** | `corpus/e2/programs/e2_p5.c` | 5 | 32 | Bits 0, 1, 2, 3, 4 | Full matrix level |
| **E2-P6** | `corpus/e2/programs/e2_p6.c` | 6 | 64 | Bits 0, 1, 2, 3, 4, 5 | Full matrix upper level |

All programs adhere strictly to:
- Hook: `XDP` (`SEC("xdp")`)
- Helpers: Exactly 1 (`bpf_ktime_get_ns()`)
- Maps: 0
- Loops: 0

---

## 5. P5/P6 Pre-Execution Validation Gate

Before approving the full matrix, candidate programs `E2-P5` and `E2-P6` were authored and subjected to an offline **static compilation and disassembly inspection gate** (no KRAKENGUARD runs):

```text
=== e2_p5 Static Gate ===
  Source SHA256: 556257151e0a526ae9901c970cd6a3f7eaf8ead83460058cb36855b61aa96556
  Object SHA256: 9034d56a182791b52ac53366ba6e157b5c8634ec1035cf2b81d9fd4b877344c5
  Instructions: 37
  Branches: 6 (1 concrete packet boundary + 5 symbolic branches)
  Helpers: 1 (bpf_ktime_get_ns)
  Maps: 0 | Loops: 0 | Hook: XDP
  STATIC GATE VERDICT: PASS

=== e2_p6 Static Gate ===
  Source SHA256: 1a5d85c255421eff68e9c68e18208fc1e04cd2e526d491f22f38116d3b1e89e9
  Object SHA256: 44d91a3ca8c8b679c40360aac950b29e8826dec7ef5ca42ea56ed7f0a8f672b7
  Instructions: 43
  Branches: 7 (1 concrete packet boundary + 6 symbolic branches)
  Helpers: 1 (bpf_ktime_get_ns)
  Maps: 0 | Loops: 0 | Hook: XDP
  STATIC GATE VERDICT: PASS
```

Both programs conform to the expected structural scaling ($\approx 6$ instructions and 1 branch per level) and satisfy all architectural requirements.

---

## 6. Independent Variable

The primary independent variable for all statistical modeling and conclusions is:
> **Observed Feasible KLEE Explored Paths**

Source predicate count ($k$), target paths ($2^k$), and compiled branch count are structural explanatory variables. If a program exhibits an observed path count different from its theoretical target (e.g. 30 paths instead of 32), the actual observed count will be used as the independent coordinate.

---

## 7. Controlled Invariants

The following environment and policy variables are strictly frozen:

| Variable | Specification | Invariant State |
| :--- | :--- | :--- |
| **KRAKENGUARD Baseline Commit** | `e7bd84005b304c5a10efcdb04914d1882b3cccf7` | Matches container `artifact-krakenguard:latest` |
| **Security Policy** | `research/experiments/corpus/e1/policies/e1_fixed_policy.json` | SHA-256: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603` |
| **Hook Type** | XDP | `SEC("xdp")` across all 7 programs |
| **Symbolic Helper** | `bpf_ktime_get_ns()` | Call helper ID 5 |
| **Helper Count** | 1 | Verified in disassembly |
| **Map Count** | 0 | Relocations and map sections verified absent |
| **Loop Count** | 0 | Acyclic DAG verified |
| **Compiler Toolchain** | Clang 22.1.8 | `-target bpf -mcpu=v1 -O2 -g -D__TARGET_ARCH_x86 -I/usr/include` |
| **Host Kernel** | Linux 7.2.3-arch1-2 | Architecture: `x86_64` |
| **Host Hardware** | AMD Ryzen 5 5600H | 6 cores / 12 threads |

---

## 8. Replication Plan

- **Levels**: 7 candidate programs (`E2-P0` through `E2-P6`).
- **Warmups**: 2 warmup executions per program ($7 \times 2 = 14$ warmups).
- **Measured Runs**: 7 measured executions per program ($7 \times 7 = 49$ measured runs).
- **Total Executions**: Exactly 63 verifier executions.
- **Statistical Separation**: Measured runs form the empirical dataset; warmups are strictly excluded from descriptive statistics.

---

## 9. Warmup Policy

- Exactly 2 warmups per program level.
- Warmups execute under identical socket, container, and policy configurations as measured runs.
- Warmups serve solely to prime the container filesystem, JIT cache, and dynamic linker.
- Warmups are never selectively repeated, inspected to drop anomalies, or merged into the final performance statistics.

---

## 10. Execution Order Evaluation & Selection

Three scheduling options were evaluated:
- **Option A (Sequential by Level: P0 $\to$ P1 $\to$ ... $\to$ P6)**: Vulnerable to monotonic thermal buildup, background CPU frequency throttling, and daemon container state accumulation that could create an artificial correlation between run order and path count.
- **Option B (Fully Randomized Order)**: Eliminates systematic bias but prevents clean tracking of inter-run variance and complicates cache stability.
- **Option C (Blocked / Interleaved Order — SELECTED)**:
  - **Phase 1 (Warmups)**: 2 rounds across all programs ($W_1$: P0..P6, $W_2$: P0..P6).
  - **Phase 2 (Measured Runs)**: 7 sequential blocks, each executing all 7 programs in identical order ($B_1$: P0..P6, $B_2$: P0..P6, ..., $B_7$: P0..P6).
  - **Rationale**: Blocked execution ensures that system-wide temporal drift, background OS scheduling fluctuations, and daemon memory consumption are distributed uniformly across all 7 path levels.

---

## 11. Timeout Handling

- **Per-Run Verification Timeout**: 300 seconds.
- A timeout is a **valid experimental observation**, not an operational error.
- If a run exceeds 300 seconds, the runner marks `execution_status = "timeout"`, `verifier_result = "TIMEOUT"`, and preserves all partial logs.
- Timeouts will **not** be silently dropped, retried, or converted to policy violations.

---

## 12. Outlier Policy

- **No Outlier Deletion**: In accordance with the E1 protocol, all 49 measured runs will be reported. No observations will be pruned, trimmed, or replaced.
- For each program level, the full distribution will be reported: minimum, maximum, mean, median, sample standard deviation ($s$), and coefficient of variation ($CV$).
- If an outlier occurs, its cause will be investigated through container logs (e.g. solver pause, garbage collection) and explicitly documented; if unexplained, it will be labeled `cause undetermined`.

---

## 13. Primary & Secondary Metrics

### Primary Performance Metric
- `wall_time_us`: High-resolution client wall-clock duration from request transmission to complete response parsing (`time.perf_counter()`).
- `klee_paths_explored`: Total feasible paths explored by KLEE.
- `solver_queries`: Total queries dispatched to Z3.

### Secondary Metrics
- `klee_completed_paths`: Total paths terminating cleanly at normal program exit.
- `klee_total_instructions`: Total LLVM instructions executed across all symbolic states.
- `klee_valid_queries`, `klee_invalid_queries`, `klee_query_cex`: Solver query outcome breakdown.
- `compiled_instructions`, `basic_blocks`, `branches`: Static bytecode metrics.

---

## 14. Metric Semantics & Interpretations

To prevent overstatement or misattribution:
1. **Client Process CPU Time (`cpu_time_us`)**: Measures only the Python runner process (`time.process_time()`). It does **NOT** represent verifier CPU time inside the Docker container and will not be cited as headline verifier computational cost.
2. **Peak Memory (`peak_memory_bytes`)**: Marked **`NOT_REPORTED`**. The baseline daemon does not currently expose per-request cgroup RSS or allocator high-water marks. Peak memory will not be inferred or extrapolated.
3. **Solver Time (`solver_time_us`)**: Marked **`NOT_REPORTED`**. KRAKENGUARD's KLEE build logs query counts, but does not isolate aggregate Z3 wall time in its `info` stream. Solver time will not be inferred from query counts.

---

## 15. Path Semantics & Resolution of the Parsing Bug

Based on direct C++ source inspection of KLEE (`Executor.cpp:4091, 4205` and `main.cpp:2506`):
- **`KLEE Explored Paths`**: Total execution states that terminate within the symbolic engine. Incremented in `Executor::terminateState()`.
- **`KLEE Completed Paths`**: States that reach normal function return and exit cleanly (`Executor::terminateStateOnExit()`).
- **`Partially Completed Paths`**: States terminated prematurely by timeouts, memory caps, or errors (`pathsExplored - pathsCompleted`).
- **`Solver Queries`**: Number of satisfiability / validity queries sent to the Z3 backend.

### The Parsing Bug Root Cause
In previous runners, the regex parser used substring matching:
`elif "completed paths =" in line:`
Because KLEE outputs `completed paths = N` followed by `partially completed paths = 0`, the second line matched the substring and overwrote `completed_paths` with `0`. The audited runner uses anchored regex:
`re.search(r'^\s*KLEE:\s*done:\s*completed paths\s*=\s*(\d+)', line)`
which resolves the discrepancy and correctly captures both metrics.

---

## 16. Statistical Analysis Plan

For each program level $P \in \{\text{E2-P0}, \dots, \text{E2-P6}\}$ over $n = 7$ measured runs:
$$\mu = \frac{1}{n} \sum_{i=1}^n t_i, \quad s = \sqrt{\frac{1}{n-1} \sum_{i=1}^n (t_i - \mu)^2}, \quad CV = \frac{s}{\mu}$$
- Non-parametric comparisons will use the **median** and **interquartile range (IQR)**.
- **Trend Evaluation**: We will evaluate adjacent path regime growth ($\Delta t$ across $1 \to 2 \to 4 \to 8 \to 16 \to 32 \to 64$).
- Curve fitting (linear vs superlinear vs exponential) will be applied only if the data empirically departs from the flat regime.

---

## 17. Comparison with Experiment E1

| Dimension | Experiment E1 Baseline | Experiment E2 Path Scaling |
| :--- | :--- | :--- |
| **Independent Variable** | Micro-program complexity (instructions, maps, helpers) | Feasible symbolic path count ($1 \to 64$) |
| **Instruction Range** | 2 to 20 instructions | 7 to 43 instructions |
| **Feasible Path Regime** | 1 to 2 paths | 1 to 64 paths |
| **Observed Scaling** | Flat (~700–850 ms, dominated by translation) | Tested: does symbolic explosion overcome pipeline overhead? |
| **Policy** | `e1_fixed_policy.json` | Identical `e1_fixed_policy.json` |
| **Verifier** | Frozen KRAKENGUARD commit `e7bd8400...` | Identical frozen commit |

---

## 18. Threats to Validity

1. **Compiler Optimization**: High optimization levels (`opt -O3`) can flatten branches; guarded against via external packet memory mutations.
2. **Predicate Independence**: Bitwise masks on 64-bit integer ensure all $2^k$ paths are feasible and mutually reachable.
3. **Pipeline Overhead Masking**: If lifter and harness initialization take ~700 ms, symbolic search growth below 100 ms may appear relatively flat; guarded by extending to 64 paths.
4. **Host System Thermal / Background Drift**: Addressed via Blocked / Interleaved execution order.
5. **Metric Over-interpretation**: Clearly distinguishing explored paths from verifier states, client CPU from container CPU, and queries from solver time.

---

## 19. Failure Handling & Abort Criteria

The experiment runner will halt and flag an error if:
- Baseline daemon socket fails to respond or connection drops.
- SHA-256 of policy or compiled objects does not match expected provenance.
- A program is rejected by the verifier (since all candidates are policy-compliant by design).

---

## 20. Raw Telemetry & Evidence Requirements

All raw artifacts will be written to `research/experiments/results/e2/raw/`:
- `<slug>-compile.log`: Full compiler invocation stdout/stderr and exit code.
- `<slug>-llvm-objdump.txt`: Bytecode disassembly.
- `<slug>-readelf.txt`: Section headers and symbol tables.
- `<slug>-bpftool-btf.txt`: Raw BTF type dumps.
- `<slug>-b<block>-run<repeat>.stdout`: Full daemon stdout.
- `<slug>-b<block>-run<repeat>.stderr`: Full daemon stderr.
- `<slug>-b<block>-run<repeat>-klee-info.txt`: KLEE `info` stream.
- `e2-results.csv` and `e2-results.json`: Complete structured datasets.

---

## 21. Runner Script Audit Results (`execute-e2-matrix.py`)

The full-matrix runner script `research/experiments/scripts/execute-e2-matrix.py` was inspected and audited:
- [x] Corrected anchored regex parsing for `completed_paths`.
- [x] Implemented Blocked / Interleaved scheduling (2 warmup rounds, 7 measured blocks).
- [x] Deterministic run ID generation (`e2-m01-p0`, `e2-w01-p0`).
- [x] Strict 300s timeout enforcement.
- [x] No outlier deletion logic.
- [x] No silent retries.
- [x] Offline `--dry-run` flag implemented and validated.

---

## 22. FINAL EXECUTION GATE EVALUATION

| Gate Condition | Verification Result | Gate Status |
| :--- | :--- | :--- |
| **1. P0–P4 pilot evidence preserved** | Verified in `research/experiments/results/e2-pilot/` | **PASS** |
| **2. P5/P6 compile successfully** | Verified (Clang 22.1.8 -target bpf) | **PASS** |
| **3. P5/P6 compiled branches validated** | P5: 6 branches; P6: 7 branches | **PASS** |
| **4. P5/P6 use identical symbolic source** | Pure `bpf_ktime_get_ns()` | **PASS** |
| **5. Exactly one helper present** | Exactly 1 helper (`ktime`) | **PASS** |
| **6. Zero maps** | 0 maps across all programs | **PASS** |
| **7. Zero loops** | 0 loops across all programs | **PASS** |
| **8. XDP hook fixed** | `SEC("xdp")` across all programs | **PASS** |
| **9. Policy fixed** | SHA: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603` | **PASS** |
| **10. KRAKENGUARD commit fixed** | Commit: `e7bd84005b304c5a10efcdb04914d1882b3cccf7` | **PASS** |
| **11. Compiler configuration fixed** | `-target bpf -mcpu=v1 -O2 -g -D__TARGET_ARCH_x86 -I/usr/include` | **PASS** |
| **12. Environment matches baseline** | Linux 7.2.3-arch1-2 x86_64, Docker 29.7.2 | **PASS** |
| **13. KLEE path-field semantics understood** | Traced to `Executor.cpp` and `main.cpp` | **PASS** |
| **14. completed_paths anomaly explained** | Substring collision in parser resolved | **PASS** |
| **15. Timeout handling correct** | 300s, recorded as valid outcome | **PASS** |
| **16. Warmups excluded from statistics** | Explicitly separated in data schema | **PASS** |
| **17. Run IDs unique** | Deterministic block-level IDs | **PASS** |
| **18. Raw evidence preserved** | Saved per-run in `results/e2/raw/` | **PASS** |
| **19. CPU-time semantics not overstated** | Clarified as client-process only | **PASS** |
| **20. Peak memory marked NOT_REPORTED** | Explicit `NOT_REPORTED` invariant | **PASS** |
| **21. Solver time marked NOT_REPORTED** | Explicit `NOT_REPORTED` invariant | **PASS** |
| **22. No outlier deletion** | Strict retention of all 49 measured runs | **PASS** |
| **23. No silent retries** | Runner executes exact schedule | **PASS** |
| **24. Full matrix script passed static review** | Verified with `--dry-run` | **PASS** |
| **25. No E1 or Phase 3 artifacts modified** | Unmodified | **PASS** |

### Execution Gate Verdict
> **`FULL MATRIX APPROVED FOR EXECUTION`**
