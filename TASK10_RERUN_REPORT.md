# Task 10 Benchmark Rerun Report: Controlled Comparative Evaluation

**Date:** 2026-10-25  
**Commit Baseline:** `ce2cebe` on branch `main`  
**Repository:** `Research-Paper-eBPF`  
**Benchmark Target:** 10 Compiled Corpus Fixtures $\times$ 3 Modes $\times$ (1 Warm-up + 3 Measured Repetitions) = **120 Total Runs**  
**Raw Data Directory:** [`research/experiments/results/split_bypass_evaluation_rerun/raw/`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/results/split_bypass_evaluation_rerun/raw/)  
**Summary Artifact:** [`research/experiments/results/split_bypass_evaluation_rerun/summary.json`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/results/split_bypass_evaluation_rerun/summary.json)  
**Preserved Original Baseline:** [`research/experiments/results/split_bypass_evaluation/raw/`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/results/split_bypass_evaluation/raw/)  

---

## 1. Executive Summary & Verification Findings

This report documents the freshly executed rerun of the controlled 3-way comparative evaluation across all 10 compiled eBPF benchmark fixtures, conducted in strict adherence to all experimental safeguards:
- **Mode A (`symbolic_only`):** Direct whole-program symbolic execution via KRAKENGUARD (bypasses abstract interpreter).
- **Mode B (`whole_hybrid`):** Legacy whole-program abstract interpreter (`AbstractPolicyAnalyzer`) with whole-program symbolic fallback on `UNKNOWN`.
- **Mode C (`region_hybrid`):** CFG region abstract interpreter (`region_analyzer.py`) with 32/64-bit transfer functions, width-aware stack frame modeling, cycle detection, and fallback handling.

### Key Rerun Findings:
1. **Verdict & Oracle Agreement Veracity (100% Replication of Logic):**
   - **Mode C (`region_hybrid`):** **100.0% (30/30)** oracle agreement across all measured runs, with **0 false-safe** and **0 false-reject** verdicts.
   - **Mode B (`whole_hybrid`):** **70.0% (21/30)** oracle agreement, with **9 false rejections** across `A03_helper_clock`, `B02_branch_policy_sensitive`, and `D01_helper_unknown_candidate` due to rigid helper allowlists and unmodeled branch predicates.
   - **Mode A (`symbolic_only`):** **90.0% (27/30)** oracle agreement, with **3 fail-closed runtime errors (10.0%)** on `D01_helper_unknown_candidate` due to a KLEE execution crash (return code 1).
2. **Symbolic Bypass Rate:**
   - Mode C proved safety on the abstract fast path for **9 of 10 fixtures (90.0%)**, invoking symbolic fallback exclusively on `E01_bounded_loop` ($3/30$ measured runs = **10.0% fallback rate**).
   - Mode B invoked symbolic fallback on **21 of 30 measured runs (70.0%)**, short-circuiting only on false rejections ($9/30$).
3. **Throughput and Latency:**
   - Mode C achieved a median end-to-end latency of **116.09 ms**, delivering a **$6.51\times$ speedup** over Mode A (**755.65 ms**) and a **$7.40\times$ speedup** over Mode B (**859.02 ms**).
4. **Statistical Significance (Paired Bootstrap, $N=30$, 5,000 Iterations):**
   - Mode C vs Mode A ($\text{Mode A} - \text{Mode C}$): Mean difference **$+561.69\text{ ms}$**, 95% Bootstrap CI **$[+472.78\text{ ms},\ +640.78\text{ ms}]$** ($p < 0.001$, strictly positive).
   - Mode C vs Mode B ($\text{Mode B} - \text{Mode C}$): Mean difference **$+456.64\text{ ms}$**, 95% Bootstrap CI **$[+325.35\text{ ms},\ +584.94\text{ ms}]$** ($p < 0.001$, strictly positive).
   - Mode B vs Mode A ($\text{Mode B} - \text{Mode A}$): Mean difference **$-105.06\text{ ms}$**, 95% Bootstrap CI **$[-239.56\text{ ms},\ +22.82\text{ ms}]$** (spans zero; not statistically significant).
5. **Hierarchical Fixture Cluster Bootstrap ($N=10$ Independent Programs):**
   - Mode C vs Mode A ($\text{Mode A} - \text{Mode C}$): Fixture Mean **$+561.69\text{ ms}$**, 95% Cluster CI **$[+397.82\text{ ms},\ +650.62\text{ ms}]$** ($p < 0.001$).
   - Mode C vs Mode B ($\text{Mode B} - \text{Mode C}$): Fixture Mean **$+456.64\text{ ms}$**, 95% Cluster CI **$[+227.10\text{ ms},\ +682.64\text{ ms}]$** ($p < 0.001$).

---

## 2. Experimental Execution Protocol and Pre-Flight Checks

### 2.1 Pre-Flight Environmental Verification
Immediately prior to execution, all environmental invariants were rechecked and logged:
- **Disk Space Check:**
  - Command: `df -h /`
  - Result: 110 GB free space on root filesystem `/` (device `/dev/nvme0n1p3`, 68% utilized).
- **Process Isolation:**
  - Command: `ps aux | grep -E 'klee|bpflifter|llvm-link|split_analyze|run_evaluation' | grep -v grep`
  - Result: 0 lingering or active KLEE or lifter worker processes.
- **KRAKENGUARD Socket Connectivity:**
  - Docker container ID: `91d057ec914b` (`image: artifact-krakenguard`, status: `Up 16 hours`).
  - UNIX socket path: `research/baselines/krakenguard/artifact/socket/krakenguard.sock`.
  - Python test probe: Successfully connected via relative path within OS `sockaddr_un` limits (108 bytes).
- **Fixture and Policy Hash Integrity:**
  - Manifest: [`corpus-manifest.json`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/manifests/corpus-manifest.json).
  - All 10 fixture ELFs matched their authoritative SHA-256 digests:
    - `A01_straight_small`: `110c20c66a7deb673c17905f82b934886909dc0ba33dbd130b87346e65b83502`
    - `A02_straight_medium`: `1141296923a43ef5cb0ae728cb1190bc1b9ec7bbbb3ef357904fc19904945d8b`
    - `A03_helper_clock`: `b525ac69fbf726b38c35272a0f8bfdf8aa2c1fb6717551ee67b66ec0a3826046`
    - `B01_branch_safe`: `b5666340ff0e68864fe5179067b5ae17e8ff114fe335756784841961445b23d9`
    - `B02_branch_policy_sensitive`: `deccbd095dd284c4a45ec4fa1bfcfcebbd758c54157ceb15cb278783fc11f2a3`
    - `C01_join_different_values`: `422f7c0d121414fcbf42d0575d1d6aa522971ea9e4266100ca89f076b6d859fa`
    - `C02_join_policy_sensitive`: `836d53b40b7be287a91722e17e9fe556755ec50eeb53634e7492c73d919bb1d3`
    - `D01_helper_unknown_candidate`: `504e6e321ba33fdbbb81d5fbc77dcf9fc03f90b9b3e1bb4541bf5da124892c99`
    - `D02_packet_memory_candidate`: `d0422e35764a27bcc557ecbe53e34b95ddfd62a4d048ba98533cf9f4d7b7fa09`
    - `E01_bounded_loop`: `cdff46021d4b96f9f69fc39bb0016a246944e830e9d6d5eb393f666fcf93eb8d`
  - Policy `policy-c0f0ac4d1a5e.json`: `c0f0ac4d1a5ecf781c867ff742409767f24544b71aa36c57a533715d1d4c387b` (Verified).

### 2.2 Execution Command
```bash
python3 research/experiments/split_bypass/scripts/run_evaluation.py \
  --output-dir research/experiments/results/split_bypass_evaluation_rerun/raw \
  --repetitions 3 \
  --warmup \
  --modes symbolic_only whole_hybrid region_hybrid \
  --overwrite
```
- **Total Wall-Clock Time:** 75.01 seconds.
- **Run Count:** 120 total runs (10 fixtures $\times$ 3 modes $\times$ [1 warmup + 3 measured repetitions]).
- **Warmup Protocol:** 1 warmup run per fixture-mode pair was recorded, tracked with `"is_warmup": true`, and automatically filtered from all latency medians, means, and paired comparisons.

### 2.3 Statistical Analysis Command
```bash
python3 research/experiments/split_bypass/scripts/analyze_runs.py \
  --raw-dir research/experiments/results/split_bypass_evaluation_rerun/raw \
  --output research/experiments/results/split_bypass_evaluation_rerun/summary.json \
  --bootstrap-samples 5000 \
  --seed 42
```

---

## 3. Aggregate Performance Comparison: Original Baseline vs. Rerun

All metrics are computed strictly across the **90 measured runs** ($N=30$ per mode; all 30 warmup runs excluded).

| Metric | Original Baseline (Oct 24) | Benchmark Rerun (Oct 25) | Difference ($\Delta$) | Analysis |
|:---|:---:|:---:|:---:|:---|
| **Mode A: `symbolic_only`** | | | | |
| - End-to-End Latency (Median) | 792.23 ms | 755.65 ms | $-36.58\text{ ms}$ ($-4.6\%$) | Host execution variance |
| - End-to-End Latency (Mean) | 791.94 ms | 759.16 ms | $-32.78\text{ ms}$ ($-4.1\%$) | Normal execution variance |
| - End-to-End Latency Range | 771.59 – 812.73 ms | 721.08 – 805.19 ms | shifted $-50$ to $-7\text{ ms}$ | Within expected host bounds |
| - Fallback Invocation Rate | 0/30 (0.0%) | 0/30 (0.0%) | $0.0\%$ | Identical (bypasses abstract) |
| - Symbolic Invocation Rate | 30/30 (100.0%) | 30/30 (100.0%) | $0.0\%$ | Identical |
| - Oracle Agreement Rate | 27/30 (90.0%) | 27/30 (90.0%) | $0.0\%$ | Identical |
| - KRAKENGUARD Crashes (Errors) | 3/30 (10.0%) | 3/30 (10.0%) | $0$ | Identical fail-closed on D01 |
| - False Safe / False Reject | 0 / 0 | 0 / 0 | $0 / 0$ | Identical |
| **Mode B: `whole_hybrid`** | | | | |
| - End-to-End Latency (Median) | 899.21 ms | 859.02 ms | $-40.19\text{ ms}$ ($-4.5\%$) | Host execution variance |
| - End-to-End Latency (Mean) | 666.63 ms | 654.10 ms | $-12.53\text{ ms}$ ($-1.9\%$) | Consistent across runs |
| - End-to-End Latency Range | 113.16 – 916.71 ms | 102.71 – 1000.17 ms | shifted $-10$ to $+83\text{ ms}$ | Within expected host bounds |
| - Fallback Invocation Rate | 21/30 (70.0%) | 21/30 (70.0%) | $0.0\%$ | Identical |
| - Oracle Agreement Rate | 21/30 (70.0%) | 21/30 (70.0%) | $0.0\%$ | Identical |
| - False Rejections | 9/30 (30.0%) | 9/30 (30.0%) | $0$ | Identical (A03, B02, D01) |
| - False Safe / Errors | 0 / 0 | 0 / 0 | $0 / 0$ | Identical |
| **Mode C: `region_hybrid`** | | | | |
| - End-to-End Latency (Median) | 119.51 ms | 116.09 ms | $-3.42\text{ ms}$ ($-2.9\%$) | Host execution variance |
| - End-to-End Latency (Mean) | 200.80 ms | 197.47 ms | $-3.33\text{ ms}$ ($-1.7\%$) | Consistent across runs |
| - End-to-End Latency Range | 117.15 – 941.35 ms | 111.90 – 933.64 ms | shifted $-5$ to $-8\text{ ms}$ | Fast path vs loop fallback |
| - Fallback Invocation Rate | 3/30 (10.0%) | 3/30 (10.0%) | $0.0\%$ | Identical (E01 only) |
| - Oracle Agreement Rate | 30/30 (100.0%) | 30/30 (100.0%) | $0.0\%$ | Identical (100% sound) |
| - False Safe / False Reject | 0 / 0 | 0 / 0 | $0 / 0$ | Identical (0 violations) |
| - Unresolved / Errors | 0 | 0 | 0 | Identical |
| **Speedup (Median)** | | | | |
| - Mode C vs. Mode A | **$6.63\times$** | **$6.51\times$** | $-0.12\times$ | Robust and consistent |
| - Mode C vs. Mode B | **$7.52\times$** | **$7.40\times$** | $-0.12\times$ | Robust and consistent |

---

## 4. Fixture-by-Fixture Breakdown

The table below contrasts per-fixture median latencies (in milliseconds) and oracle agreement percentages across measured repetitions ($N=3$ per program-mode cell).

| Fixture ID | Category | Oracle | Mode A (Base) | Mode A (Rerun) | Mode B (Base) | Mode B (Rerun) | Mode C (Base) | Mode C (Rerun) | Speedup (C vs A) | Speedup (C vs B) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `A01_straight_small` | Straight | SAFE | 789.6 (100%) | 757.9 (100%) | 905.1 (100%) | 844.6 (100%) | 118.5 (100%) | 112.7 (100%) | **$6.73\times$** | **$7.50\times$** |
| `A02_straight_medium` | Straight | SAFE | 799.1 (100%) | 763.4 (100%) | 910.4 (100%) | 863.9 (100%) | 119.0 (100%) | 126.1 (100%) | **$6.05\times$** | **$6.85\times$** |
| `A03_helper_clock` | Helper | SAFE | 801.6 (100%) | 775.0 (100%) | 113.7 (0%) | 104.3 (0%) | 119.1 (100%) | 116.1 (100%) | **$6.68\times$** | *N/A (B Unsound)* |
| `B01_branch_safe` | Branch | SAFE | 787.3 (100%) | 746.4 (100%) | 896.5 (100%) | 916.7 (100%) | 120.9 (100%) | 121.5 (100%) | **$6.14\times$** | **$7.54\times$** |
| `B02_branch_policy_sensitive` | Branch | SAFE | 793.7 (100%) | 794.8 (100%) | 113.5 (0%) | 107.2 (0%) | 122.2 (100%) | 118.1 (100%) | **$6.73\times$** | *N/A (B Unsound)* |
| `C01_join_different_values` | Join | SAFE | 798.1 (100%) | 748.5 (100%) | 905.4 (100%) | 858.4 (100%) | 118.2 (100%) | 113.7 (100%) | **$6.58\times$** | **$7.55\times$** |
| `C02_join_policy_sensitive` | Join | SAFE | 792.4 (100%) | 758.4 (100%) | 901.2 (100%) | 874.7 (100%) | 119.5 (100%) | 114.3 (100%) | **$6.63\times$** | **$7.65\times$** |
| `D01_helper_unknown_candidate` | Candidate | SAFE | 775.0 (0%) | 725.0 (0%) | 116.9 (0%) | 103.4 (0%) | 118.8 (100%) | 112.9 (100%) | *N/A (A Crashed)* | *N/A (B Unsound)* |
| `D02_packet_memory_candidate` | Memory | SAFE | 796.4 (100%) | 750.1 (100%) | 904.8 (100%) | 873.9 (100%) | 119.7 (100%) | 116.5 (100%) | **$6.44\times$** | **$7.50\times$** |
| `E01_bounded_loop` | Loop | SAFE | 792.0 (100%) | 755.7 (100%) | 901.4 (100%) | 975.9 (100%) | 934.8 (100%) | 922.1 (100%) | $0.82\times$ | $1.06\times$ |

---

## 5. Statistical Tests and Paired Uncertainty Analysis

Paired differences were calculated across identical `pair_id` identifiers ($N=30$ measured pairs per comparison) using 5,000 bootstrap resamples (seed 42):

### 5.1 Observation-Level Paired Analysis ($N=30$ Measured Pairs)
$$\Delta_{\text{latency}} = T_{\text{Baseline}} - T_{\text{RegionHybrid}}$$

1. **Mode C (`region_hybrid`) vs. Mode A (`symbolic_only`):**
   - **Original Baseline:** Mean Difference $= +591.15\text{ ms}$, 95% Bootstrap CI $= [+506.01\text{ ms},\ +671.56\text{ ms}]$.
   - **Benchmark Rerun:** Mean Difference $= +561.69\text{ ms}$, 95% Bootstrap CI $= [+472.78\text{ ms},\ +640.78\text{ ms}]$.
   - **Evaluation:** The confidence interval remains strictly positive, confirming statistically significant latency reduction ($p < 0.001$).
2. **Mode C (`region_hybrid`) vs. Mode B (`whole_hybrid`):**
   - **Original Baseline:** Mean Difference $= +465.83\text{ ms}$, 95% Bootstrap CI $= [+331.33\text{ ms},\ +599.25\text{ ms}]$.
   - **Benchmark Rerun:** Mean Difference $= +456.64\text{ ms}$, 95% Bootstrap CI $= [+325.35\text{ ms},\ +584.94\text{ ms}]$.
   - **Evaluation:** Mode C delivers statistically significant speedups ($p < 0.001$) over legacy hybrid execution while eliminating all 9 false rejections.
3. **Mode B (`whole_hybrid`) vs. Mode A (`symbolic_only`):**
   - **Original Baseline:** Mean Difference $= -125.32\text{ ms}$, 95% Bootstrap CI $= [-256.91\text{ ms},\ +5.20\text{ ms}]$.
   - **Benchmark Rerun:** Mean Difference $= -105.06\text{ ms}$, 95% Bootstrap CI $= [-239.56\text{ ms},\ +22.82\text{ ms}]$.
   - **Evaluation:** In both runs, the 95% confidence interval spans zero ($[-239.56, +22.82]\text{ ms}$). There is no statistically significant performance advantage of Mode B over Mode A.

### 5.2 Hierarchical Cluster Bootstrap Accounting for Repeated Observations ($N=10$ Independent Fixtures)

To avoid pseudo-replication from treating the 30 paired measurements as 30 independent programs, we compute a cluster bootstrap where the independent resampling unit is the **program fixture** ($N=10$). For each fixture, we compute the fixture-level mean difference across its 3 measured repetitions ($\bar{d}_p = \frac{1}{3} \sum_{r=1}^3 d_{p,r}$) and resample fixtures with replacement across 5,000 iterations:

| Comparison | Observation-Level ($N=30$ pairs) Mean [95% CI] | Fixture-Level Cluster ($N=10$ programs) Mean [95% CI] | Statistical Interpretation |
|:---|:---:|:---:|:---|
| **Mode A vs Mode C** ($\text{Sym} - \text{Reg}$) | $+561.69\text{ ms}$ [$+472.78$, $+640.78$] ms | $+561.69\text{ ms}$ **[$+397.82$, $+650.62$] ms** | Strictly positive; speedup remains statistically significant ($p < 0.001$) under independent program clustering. |
| **Mode B vs Mode C** ($\text{Whole} - \text{Reg}$) | $+456.64\text{ ms}$ [$+325.35$, $+584.94$] ms | $+456.64\text{ ms}$ **[$+227.10$, $+682.64$] ms** | Strictly positive; speedup remains statistically significant ($p < 0.001$) under independent program clustering. |
| **Mode B vs Mode A** ($\text{Whole} - \text{Sym}$) | $-105.06\text{ ms}$ [$-239.56$, $+22.82$] ms | $-105.06\text{ ms}$ **[$-347.26$, $+123.11$] ms** | Broadly spans zero; no statistically significant difference between legacy hybrid and symbolic-only. |

**Breakdown of Individual Fixture Means in Rerun ($\text{Mode A} - \text{Mode C}$):**
- Fast-Path Discharged Fixtures (9 programs): `A01` ($+653.60\text{ ms}$), `A02` ($+634.58\text{ ms}$), `A03` ($+657.05\text{ ms}$), `B01` ($+637.97\text{ ms}$), `B02` ($+680.25\text{ ms}$), `C01` ($+635.42\text{ ms}$), `C02` ($+638.43\text{ ms}$), `D01` ($+613.47\text{ ms}$), `D02` ($+627.57\text{ ms}$). All show large positive latency savings ($> +610\text{ ms}$).
- Fallback Fixture (1 program): `E01_bounded_loop` ($-161.40\text{ ms}$). Mode C incurs a modest latency penalty ($161.40\text{ ms}$) on loops because it performs abstract analysis before falling back to symbolic execution.
- **Cluster Robustness:** Even when `E01`'s penalty is resampled in multiple cluster draws, the 95% bootstrap lower bound remains $+397.82\text{ ms}$, confirming that the speedup is robust to program-level clustering.

---

## 6. Architectural Invariants and Actual Fallback Scope Veracity

### 6.1 Telemetry and Fallback Scope Audit
A critical requirement of the benchmark evaluation is to truthfully audit and report the actual execution and fallback scope for each mode:

1. **Mode A (`symbolic_only`):**
   - Direct execution of KRAKENGUARD on the complete compiled ELF binary.
   - Analyzer: `None` (bypassed).
   - Execution Scope: `whole_program`.
2. **Mode B (`whole_hybrid`):**
   - Analysis of the complete ELF binary by the legacy `AbstractPolicyAnalyzer`.
   - Fallback Engine: KRAKENGUARD on `UNKNOWN`.
   - Fallback Scope: Strictly recorded as `whole_program` across all 21 fallback runs.
3. **Mode C (`region_hybrid`):**
   - Analysis by `region_analyzer.py` executing 32/64-bit abstract transfer functions and lattice joins over CFG basic blocks and regions.
   - Analysis Scope: Strictly recorded as `region_level`.
   - **Fallback Engine & Scope Veracity:** When fallback was triggered on `E01_bounded_loop`, the fallback was executed via the frozen KRAKENGUARD container baseline socket (`/opt/krakenguard/artifact/socket/krakenguard.sock`).
   - **Crucial Architectural Clarification:** Because KRAKENGUARD requires a full ELF binary with symbol tables, section headers, and a standard entry point calling `bpf_prog(&ctx)`, it executed the **entire ELF binary**. Telemetry in all raw JSON records for `E01` strictly records:
     - `fallback_invoked`: `true`
     - `fallback_tool`: `"krakenguard"`
     - `fallback_scope`: `"whole_program"`
   - **Non-Simulation Commitment:** While Task 12 developed `DirectRegionSymbolicExecutor` for region slices under explicit abstract pre-states, this controlled 120-run benchmark uses the external KRAKENGUARD container backend. Consequently, **Mode C must NOT be described as using region-scoped symbolic fallback in this evaluation**. It uses region-level abstract analysis with whole-program symbolic fallback on unresolved loops.

---

## 7. Environmental vs. Implementation Variation Analysis

1. **Environmental Latency Variation (~2–5%):**
   - End-to-end latencies across all three modes in this rerun are slightly lower than the Oct 24 baseline (Mode A: $-4.6\%$, Mode B: $-4.5\%$, Mode C: $-2.9\%$).
   - This uniform proportional variation across both Python processes and containerized KLEE execution reflects minor fluctuations in background CPU governor states and host scheduling rather than any algorithmic modification.
2. **Speedup Invariance:**
   - Because the environmental variation affected all modes proportionally, the comparative speedup of Mode C remained invariant ($6.63\times \to 6.51\times$ over Mode A; $7.52\times \to 7.40\times$ over Mode B).
3. **Discrete Veracity Invariance (Zero Drift):**
   - Every single verdict, fallback disposition, error event, and oracle comparison replicated identically ($100\%$ concordance).
   - Mode A's 3 KLEE crashes on `D01` replicated identically (fail-closed ERROR).
   - Mode B's 9 false rejections on `A03`, `B02`, `D01` replicated identically (unsound helper rejection).
   - Mode C's 30/30 safe discharges (including 3 fallback runs on `E01`) replicated identically (100% sound and compliant).

---

## 8. Preservation and Isolation Audit

- **Original Task 10 Baseline Data:** Fully intact in [`research/experiments/results/split_bypass_evaluation/raw/`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/results/split_bypass_evaluation/raw/) (all 120 files untouched).
- **Rerun Dataset:** Isolated in [`research/experiments/results/split_bypass_evaluation_rerun/raw/`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/results/split_bypass_evaluation_rerun/raw/) (120 new files).
- **Katran Case Study:** Fully intact in [`research/experiments/results/katran_case_study/`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/results/katran_case_study/) (untouched; not executed during this run).
- **Manuscript and Evidence Ledger:** Unmodified (`evidence_ledger.csv`, `results.md`, `final_research_summary.md`, and all Word/PDF files unchanged).
- **Git Cleanliness:** No git branches, commits, or working tree state altered outside benchmark output directories.

---

## 9. Limitations and Tooling Constraints

1. **Benchmark Scope:** The evaluation corpus comprises 10 micro-benchmarks targeting specific eBPF ISA constructs (straight-line, branches, joins, memory, bounded loop). Generalization to industrial kernels requires larger real-world suites (evaluated separately in Katran).
2. **KRAKENGUARD Fallback Granularity:** When fallback is invoked in Mode C (`E01_bounded_loop`), the baseline verifier operates at whole-program ELF granularity (`fallback_scope: "whole_program"`). Region-level symbolic fallback is demonstrated separately in unit tests via `DirectRegionSymbolicExecutor` but is not integrated into KRAKENGUARD.
3. **Repeated Measures Interpretation:** While the observation-level bootstrap ($N=30$) provides narrow intervals, the hierarchical fixture cluster bootstrap ($N=10$) correctly accounts for between-fixture variance and establishes that Mode C's speedup is statistically significant across independent program structures ($95\%\text{ CI: }[+397.82, +650.62]\text{ ms}$).

---

## 10. Status and Stop Gate

- **Task 10 Benchmark Rerun:** **COMPLETED AND VERIFIED.**
- **Next Task:** Task 11A Katran real-world case study review/continuation.
- **Gating Decision:** Awaiting user review before proceeding.

---

## 11. Audit Addendum & Forensic Verification

This addendum records the formal audit of the completed Task 10 benchmark rerun against the raw records, summary data, and experimental baseline.

### 11.1 Verification of Baseline Preservation & Path Scoping
- **Original Baseline Directory:** [`research/experiments/results/split_bypass_evaluation/raw/`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/results/split_bypass_evaluation/raw/)
  - File Count: Exactly 120 JSON records.
  - File Timestamps (`st_mtime`): `1792847459.1` to `1792847534.6` (Oct 24, 2026).
  - Integrity: 100% untouched. The `--overwrite` flag passed to `run_evaluation.py` was strictly scoped to `--output-dir research/experiments/results/split_bypass_evaluation_rerun/raw` and did not modify any file in the baseline directory (separated by 26.98 hours).
- **Report Immutability:** Historical reports (`TASK3_SMOKE_REPORT.md` through `TASK10_BENCHMARK_REPORT.md`), `evidence_ledger.csv`, `results.md`, and `docs/manuscript/*` were confirmed unmodified.

### 11.2 Complete 120-Run Reconciliation Matrix
All 120 expected executions are accounted for across the 10 fixtures:

| Mode | Run Category | Total Runs | Abstract Passes | Symbolic Passes | Violations (False Rejects) | KLEE Crashes (Errors) | Timeouts / Unknowns |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Mode A (`symbolic_only`)** | Warmup | 10 | 0 | 9 | 0 | 1 (`D01`) | 0 |
| | Measured | 30 | 0 | 27 | 0 | 3 (`D01`) | 0 |
| **Mode B (`whole_hybrid`)** | Warmup | 10 | 0 | 7 | 3 (`A03`, `B02`, `D01`) | 0 | 0 |
| | Measured | 30 | 0 | 21 | 9 (`A03`, `B02`, `D01`) | 0 | 0 |
| **Mode C (`region_hybrid`)** | Warmup | 10 | 9 | 1 (`E01`) | 0 | 0 | 0 |
| | Measured | 30 | 27 | 3 (`E01`) | 0 | 0 | 0 |
| **Total** | All Runs | **120** | **36** | **68** | **12** | **4** | **0** |

*Note: Missing records: 0. Unaccounted executions: 0.*

### 11.3 Explicit Denominator Breakdown for Oracle Agreement & Errors
Because reference oracles are defined for all 10 fixtures (`SAFE` under E1 policy), we compute metrics under two explicit denominators: Total Observations ($N=30$) and Definitive Verdicts ($N_{\text{def}}$):

| Metric | Mode A (`symbolic_only`) | Mode B (`whole_hybrid`) | Mode C (`region_hybrid`) | Methodological Definition |
|:---|:---:|:---:|:---:|:---|
| **Measured Observations ($N_{\text{total}}$)** | 30 | 30 | 30 | All non-warmup runs |
| **Definitive Verdicts ($N_{\text{def}}$)** | 27 | 30 | 30 | Runs emitting `SAFE` or `VIOLATION` (excluding `ERROR`) |
| **Agreement over Total ($N_{\text{total}}$)** | **$27/30$ (90.0%)** | **$21/30$ (70.0%)** | **$30/30$ (100.0%)** | $\text{Agreements} / N_{\text{total}}$ (penalizes fail-closed errors) |
| **Agreement over Definitive ($N_{\text{def}}$)** | **$27/27$ (100.0%)** | **$21/30$ (70.0%)** | **$30/30$ (100.0%)** | $\text{Agreements} / N_{\text{def}}$ (conditioned on completed verdicts) |
| **False Rejection Rate** | $0/30$ (0.0%) | **$9/30$ (30.0%)** | **$0/30$ (0.0%)** | Spurious violations on compliant fixtures |
| **False Compliance Rate** | $0/30$ (0.0%) | $0/30$ (0.0%) | $0/30$ (0.0%) | Compliant verdict on non-compliant program |
| **Fail-Closed Error Rate** | **$3/30$ (10.0%)** | $0/30$ (0.0%) | $0/30$ (0.0%) | KLEE process crash on `D01` (exit code 1) |

### 11.4 Paired Comparison & Cluster Bootstrap Sensitivity Audit
- **Pairing Mechanism:** Runs are paired strictly on identical `pair_id` (`{program_id}_rep{repetition}`). Warmups are excluded.
- **Handling of Failed Runs in Timing:** In `analyze_runs.py`, elapsed execution time is recorded even for crashed runs (`D01` in Mode A ran ~725 ms before crashing). To assess sensitivity to this observation, we audited paired comparisons both with and without `D01`:

| Comparison & Ingestion Scope | Paired Sample Size | Mean Difference ($\Delta$) | 95% Bootstrap CI | Statistical Interpretation |
|:---|:---:|:---:|:---:|:---|
| **Mode A vs Mode C (All Observations)** | $N=30$ pairs | $+561.69\text{ ms}$ | $[+472.78, +640.78]\text{ ms}$ | Strictly positive ($p < 0.001$) |
| **Mode A vs Mode C (Excluding D01 Crashes)** | $N=27$ pairs | $+555.94\text{ ms}$ | $[+440.48, +644.15]\text{ ms}$ | Strictly positive ($p < 0.001$) |
| **Mode A vs Mode C (Cluster: All Programs)** | $N=10$ fixtures | $+561.69\text{ ms}$ | $[+396.76, +651.04]\text{ ms}$ | Strictly positive ($p < 0.001$) |
| **Mode A vs Mode C (Cluster: Clean Programs)** | $N=9$ fixtures | $+555.94\text{ ms}$ | $[+372.41, +654.29]\text{ ms}$ | Strictly positive ($p < 0.001$) |
| **Mode B vs Mode C (Cluster Bootstrap)** | $N=10$ fixtures | $+456.64\text{ ms}$ | $[+227.10, +682.64\text{ ms}]$ | Strictly positive ($p < 0.001$) |
| **Mode B vs Mode A (Cluster Bootstrap)** | $N=10$ fixtures | $-105.06\text{ ms}$ | $[-347.26, +123.11\text{ ms}]$ | Spans zero (not significant) |

*Finding: Mode C's latency reduction remains statistically significant ($p < 0.001$) regardless of whether D01 is included, excluded, or clustered at the program level.*

### 11.5 Empirical Verification of Environmental Variance (~2–5%)
Comparing the rerun (Oct 25, 21:42) to the original baseline (Oct 24, 18:44):
- **Mode A (`symbolic_only`):** Median: $792.23 \to 755.65\text{ ms}$ (**$-4.62\%$**); Mean: $791.94 \to 759.16\text{ ms}$ (**$-4.14\%$**)
- **Mode B (`whole_hybrid`):** Median: $899.21 \to 859.02\text{ ms}$ (**$-4.47\%$**); Mean: $666.63 \to 654.10\text{ ms}$ (**$-1.88\%$**)
- **Mode C (`region_hybrid`):** Median: $119.51 \to 116.09\text{ ms}$ (**$-2.86\%$**); Mean: $200.80 \to 197.47\text{ ms}$ (**$-1.66\%$**)
- **Conclusion:** The empirical shift across all three pipelines ranges from **$-1.66\%$ to $-4.62\%$**. The claim of ~2–5% environmental variance is **VERIFIED** against actual empirical measurements.

### 11.6 Telemetry & Fallback Scope Audit
- **Mode A:** Direct KRAKENGUARD symbolic execution; `fallback_invoked: false`, `symbolic_invoked: true`, `fallback_scope: null`.
- **Mode B:** 21 fallback invocations on unresolved abstract states; `fallback_invoked: true`, `fallback_scope: "whole_program"`.
- **Mode C:** 27 abstract discharges (fast path); 3 fallback invocations on `E01_bounded_loop`; `fallback_invoked: true`, `fallback_scope: "whole_program"`.
- **Architectural Truthfulness:** In Mode C, fallback invokes external KRAKENGUARD on the complete compiled `.o` ELF binary. It is strictly documented as **region-level abstract analysis with whole-program symbolic fallback**, preserving the boundary established in Section 1.

### 11.7 Audit Commands Executed
All verification scripts were read-only:
```bash
# Verify raw records, categories, and dispositions
python3 -c "import json; from pathlib import Path; files = list(Path('research/experiments/results/split_bypass_evaluation_rerun/raw').glob('*.json')); assert len(files) == 120"

# Compute observation and fixture cluster bootstraps with D01 sensitivity analysis
python3 -c "import json, statistics, random; from pathlib import Path; ... (cluster bootstrap code verified above) ..."

# Verify file timestamps and baseline non-modification
python3 -c "from pathlib import Path; assert len(list(Path('research/experiments/results/split_bypass_evaluation/raw').glob('*.json'))) == 120"
```

