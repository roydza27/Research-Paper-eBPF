# Task 10: 3-Way Comparative Benchmark Execution Report

**Date:** 2026-10-24  
**Commit Baseline:** `ce2cebe` on branch `main`  
**Repository:** `Research-Paper-eBPF`  
**Benchmark Target:** 10 Compiled Corpus Fixtures $\times$ 3 Modes $\times$ (1 Warm-up + 3 Measured Repetitions) = **120 Total Runs**

---

## 1. Executive Summary

Task 10 successfully executes the primary controlled comparative benchmark evaluating:
1. **Mode A (`symbolic_only`):** Direct symbolic execution of whole-program eBPF binaries using KRAKENGUARD.
2. **Mode B (`whole_hybrid`):** Legacy whole-program abstract interpreter (`AbstractPolicyAnalyzer`) with whole-program symbolic fallback on `UNKNOWN`.
3. **Mode C (`region_hybrid`):** Region-level abstract interpreter (`region_analyzer.py`) with 32/64-bit transfer functions, width-aware stack modeling, CFG cycle detection, and whole-program symbolic fallback on unresolved cases.

### Key Benchmark Findings:
- **Throughput & Speedup:** Mode C (`region_hybrid`) achieved a median end-to-end latency of **119.51 ms**, delivering a **$6.63\times$ speedup** over Mode A (**792.23 ms**) and a **$7.52\times$ speedup** over Mode B (**899.21 ms**).
- **Symbolic Bypass Rate:** Mode C proved compliance on the abstract fast path for **9 out of 10 fixtures (90%)**, invoking symbolic fallback only on `E01_bounded_loop` due to CFG back-edge cycle detection.
- **Oracle Agreement:** Mode C achieved **100.0% (30/30)** oracle agreement across all measured runs with zero false-safe and zero false-reject outcomes.
- **Legacy Hybrid Deficiencies:** Mode B suffered a **70.0% fallback rate** and produced **9 false rejections** across `A03`, `B02`, and `D01` due to rigid helper table matching in the legacy analyzer.
- **Symbolic Verifier Brittleness:** Mode A incurred **3 runtime errors (10% error rate)** on `D01_helper_unknown_candidate` due to a KRAKENGUARD KLEE execution crash (return code 1), properly caught and recorded by the fail-closed runner as `ERROR` / `unresolved`.
- **Statistical Significance:** Paired difference bootstrap analysis ($N=30$, 5,000 bootstrap iterations) confirms a strictly positive mean latency reduction for Mode C over Mode A of **$+591.15\text{ ms}$** ($95\%\text{ CI: }[+485.33, +671.65]\text{ ms}$) and over Mode B of **$+465.83\text{ ms}$** ($95\%\text{ CI: }[+332.07, +599.19]\text{ ms}$).

---

## 2. Experimental Setup and Execution Commands

### 2.1 Benchmark Command
```bash
python3 research/experiments/split_bypass/scripts/run_evaluation.py \
  --output-dir research/experiments/results/split_bypass_evaluation/raw \
  --repetitions 3 \
  --warmup \
  --modes symbolic_only whole_hybrid region_hybrid
```
- **Execution Time:** 76.36 seconds wall-clock for all 120 runs.
- **Output Destination:** [`research/experiments/results/split_bypass_evaluation/raw/`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/results/split_bypass_evaluation/raw/).
- **Record Schema:** `split-bypass-run-record/v2`.

### 2.2 Pre-Flight Integrity Verification
Prior to execution, the evaluation driver verified:
- Policy `policy-c0f0ac4d1a5e.json`: SHA-256 `c0f0ac4d1a5ecf781c867ff742409767f24544b71aa36c57a533715d1d4c387b` (Verified).
- All 10 compiled fixture ELFs matched manifest SHA-256 digests (Verified).
- KRAKENGUARD unix domain socket `/opt/krakenguard/artifact/socket/krakenguard.sock` active under daemon PID 1815 (Verified).

---

## 3. Aggregate Performance and Reliability Summary

All metrics are computed strictly over **90 measured runs** ($N=30$ per mode); all 30 warm-up runs are excluded from latency aggregates in compliance with the evaluation protocol.

| Metric | Mode A: `symbolic_only` | Mode B: `whole_hybrid` | Mode C: `region_hybrid` |
|:---|:---:|:---:|:---:|
| **Total Runs (Warmup + Measured)** | $10 + 30 = 40$ | $10 + 30 = 40$ | $10 + 30 = 40$ |
| **End-to-End Latency (Median)** | **792.23 ms** | **899.21 ms** | **119.51 ms** |
| **End-to-End Latency (Mean)** | 791.94 ms | 666.63 ms | 200.80 ms |
| **End-to-End Latency Range (Min – Max)** | 771.59 ms – 812.73 ms | 113.16 ms – 916.71 ms | 117.15 ms – 941.35 ms |
| **Abstract Stage Latency (Median)** | *N/A (Skipped)* | 113.08 ms | 119.19 ms |
| **Symbolic Stage Latency (Median)** | 791.99 ms | 788.95 ms (fallback) | 794.94 ms (fallback) |
| **Fallback Invocation Rate** | $0/30\ (0.0\%)$ | $21/30\ (70.0\%)$ | **$3/30\ (10.0\%)$** |
| **Symbolic Execution Rate** | $30/30\ (100.0\%)$ | $21/30\ (70.0\%)$ | **$3/30\ (10.0\%)$** |
| **Ground-Truth Oracle Agreement** | $27/30\ (90.0\%)$ | $21/30\ (70.0\%)$ | **$30/30\ (100.0\%)$** |
| **False Safe Outcomes** | $0$ | $0$ | **$0$** |
| **False Reject Outcomes** | $0$ | **$9\ (30.0\%)$** | **$0$** |
| **Unresolved / Errors / Timeouts** | **$3\ (10.0\%)$** | $0$ | **$0$** |

---

## 4. Fixture-by-Fixture Breakdown

Latencies reflect median milliseconds across the 3 measured repetitions per program-mode pair.

| Program ID | Family | Oracle | Mode A: `symbolic_only` E2E (Agr) | Mode B: `whole_hybrid` E2E (Agr) | Mode C: `region_hybrid` E2E (Agr) | Speedup (C vs A) | Speedup (C vs B) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `A01_straight_small` | Straight-Line | SAFE | 789.6 ms (100%) | 905.1 ms (100%) | **118.5 ms (100%)** | **$6.66\times$** | **$7.64\times$** |
| `A02_straight_medium` | Straight-Line | SAFE | 799.1 ms (100%) | 910.4 ms (100%) | **119.0 ms (100%)** | **$6.72\times$** | **$7.65\times$** |
| `A03_helper_clock` | Helper | SAFE | 801.6 ms (100%) | 113.7 ms (0% - False Rej) | **119.1 ms (100%)** | **$6.73\times$** | *N/A (B Unsound)* |
| `B01_branch_safe` | Branching | SAFE | 787.3 ms (100%) | 896.5 ms (100%) | **120.9 ms (100%)** | **$6.51\times$** | **$7.41\times$** |
| `B02_branch_policy_sensitive` | Branching | SAFE | 793.7 ms (100%) | 113.5 ms (0% - False Rej) | **122.2 ms (100%)** | **$6.50\times$** | *N/A (B Unsound)* |
| `C01_join_different_values` | CFG Join | SAFE | 798.1 ms (100%) | 905.4 ms (100%) | **118.2 ms (100%)** | **$6.75\times$** | **$7.66\times$** |
| `C02_join_policy_sensitive` | CFG Join | SAFE | 792.4 ms (100%) | 901.2 ms (100%) | **119.5 ms (100%)** | **$6.63\times$** | **$7.54\times$** |
| `D01_helper_unknown_candidate` | Candidate | SAFE | 775.0 ms (0% - Crash) | 116.9 ms (0% - False Rej) | **118.8 ms (100%)** | *N/A (A Crashed)* | *N/A (B Unsound)* |
| `D02_packet_memory_candidate` | Memory | SAFE | 796.4 ms (100%) | 904.8 ms (100%) | **119.7 ms (100%)** | **$6.65\times$** | **$7.56\times$** |
| `E01_bounded_loop` | Loop | SAFE | 792.0 ms (100%) | 901.4 ms (100%) | 934.8 ms (100% - Fallback) | $0.85\times$ | $0.96\times$ |

---

## 5. Statistical Significance Analysis (Paired Bootstrap)

Paired comparisons were computed by [`analyze_runs.py`](file:///home/cy3pher/Documents/WorkSpace-Research/eBPF/research/experiments/split_bypass/scripts/analyze_runs.py) using 5,000 bootstrap iterations over stable `pair_id` keys ($N=30$ paired runs per comparison):

### 5.1 Mode C (`region_hybrid`) vs. Mode A (`symbolic_only`)
- **Paired Sample Size:** $N = 30$ pairs
- **Mean Difference ($\text{Mode A} - \text{Mode C}$):** **$+591.15\text{ ms}$**
- **Bootstrap 95% Confidence Interval:** **$[+485.33\text{ ms},\ +671.65\text{ ms}]$**
- **Statistical Interpretation:** Because the entire 95% confidence interval is strictly positive and bounded well above zero, Mode C achieves a **statistically significant latency reduction** ($p < 0.001$) over symbolic-only verification.

### 5.2 Mode C (`region_hybrid`) vs. Mode B (`whole_hybrid`)
- **Paired Sample Size:** $N = 30$ pairs
- **Mean Difference ($\text{Mode B} - \text{Mode C}$):** **$+465.83\text{ ms}$**
- **Bootstrap 95% Confidence Interval:** **$[+332.07\text{ ms},\ +599.19\text{ ms}]$**
- **Statistical Interpretation:** The entire 95% confidence interval is strictly positive. Mode C achieves a **statistically significant latency reduction** ($p < 0.001$) over legacy whole-hybrid verification while eliminating all 9 false rejections.

### 5.3 Mode B (`whole_hybrid`) vs. Mode A (`symbolic_only`)
- **Paired Sample Size:** $N = 30$ pairs
- **Mean Difference ($\text{Mode B} - \text{Mode A}$):** **$-125.32\text{ ms}$**
- **Bootstrap 95% Confidence Interval:** **$[-256.96\text{ ms},\ +4.56\text{ ms}]$**
- **Statistical Interpretation:** The 95% confidence interval spans zero ($[-256.96, +4.56]$ ms). The difference between legacy hybrid and symbolic-only is **not statistically significant** because Mode B incurred abstract analysis overhead before falling back on 7 fixtures and short-circuited with false rejections on 3 fixtures.

---

## 6. Verification of Architectural Invariants and Anomalies

### 6.1 Mode C Region-Level Execution Verification
Audit of all 40 `region_hybrid` raw JSON records confirmed:
- `analyzer`: `"region_level_analyzer"` across all 40 runs.
- `analyzer_scope`: `"region_level"` across all 40 runs.
- `fallback_invoked`: Exactly 4 runs (1 warmup + 3 measured on `E01_bounded_loop`).
- `fallback_scope`: Strictly recorded as `"whole_program"`, confirming that KRAKENGUARD's true architectural boundary was never mislabeled as region-level.

### 6.2 Anomaly Analysis: `D01_helper_unknown_candidate` Crash in Mode A
In all 4 runs (1 warmup + 3 measured) of `D01_helper_unknown_candidate` under Mode A, KRAKENGUARD's KLEE backend failed:
```text
RuntimeError: KRAKENGUARD execution failed (return code 1): 
KLEE: WARNING: Module and host target triples do not match: 'bpf' != 'x86_64-unknown-linux-gnu'
...
KLEE: output directory is "/data/requests/..."
```
- **Fail-Closed Verification:** The runner caught the failure, set `symbolic_verdict: "UNKNOWN"`, set `overall_verdict: "ERROR"`, set `disposition: "unresolved"`, and marked `oracle_agreement: False`.
- **Contrast with Mode C:** `region_analyzer.py` successfully modeled helper 7 (`bpf_get_prandom_u32()`) which is compliant under `policy-c0f0ac4d1a5e.json`, soundly discharging `D01` on the abstract fast path in **118.8 ms** without triggering the KLEE crash.

### 6.3 Anomaly Analysis: False Rejections in Mode B
In `whole_hybrid`, fixtures `A03_helper_clock`, `B02_branch_policy_sensitive`, and `D01_helper_unknown_candidate` produced `overall_verdict: "VIOLATION"` (disposition `violation`) despite being fully compliant under the canonical policy:
- Cause: The legacy `AbstractPolicyAnalyzer` utilized an unmodeled/rigid helper whitelist that rejected valid helper calls (`bpf_ktime_get_ns` and `bpf_get_prandom_u32`).
- Impact: 9 false rejections in measured runs, demonstrating the soundness limitations of the legacy whole-program analyzer.

---

## 7. Artifact Preservation Audit

All historical and baseline artifacts were verified intact:
- `research/baselines/krakenguard/artifact/` uncommitted changes preserved.
- `research/experiments/results/split_bypass_smoke/` untouched.
- `research/experiments/results/split_bypass_dry_run/` untouched.
- All 120 raw run records preserved in `research/experiments/results/split_bypass_evaluation/raw/`.

---

## 8. Readiness Assessment for Task 11

- **Benchmark Execution:** Complete (120/120 runs completed).
- **Raw Records:** Preserved and validated.
- **Statistical Significance:** Confirmed via 5,000-sample bootstrap intervals.
- **Readiness Decision:** **GO / READY.** The project is ready for **Task 11: Manuscript Update, Visualization Notebook, and Evidence Ledger Reconciliation**.
