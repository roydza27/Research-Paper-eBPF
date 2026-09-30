# Phase 5 — Correction Failure Investigation Report

**Investigation Date:** 2026-09-30  
**Host:** `archlinux` (Linux 7.2.3-arch1-2 x86_64)  
**KRAKENGUARD Container:** `kg-artifact-krakenguard:latest`  
**Container Digest:** `kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4`  
**Frozen Policy:** `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`  

---

## 1. Executive Summary

During initial Phase 5 host validation, the B04 provenance gate and B01 soundness test suite succeeded. However, execution of `validate-phase5-corpus.py` halted with assertion failures across Category A (3/6), Category C (2/6, plus false VIOLATION on c2), and Category D (3/6).

A thorough code audit of KRAKENGUARD source (`e7bd84005b304c5a10efcdb04914d1882b3cccf7`), the Abstract Policy Analyzer, and the corpus programs revealed four distinct root causes:
1. **Corpus Policy Mismatch (Return Values):** The frozen E1 policy lacks a `return_value` rule. KRAKENGUARD's conditional parser treats absent return rules as allowing all return values (`Executor.cpp:5427`). Programs `c2`, `c6`, `d1`, `d3`, `d5` assumed `return XDP_TX` was a policy violation, but it is legally compliant under this policy.
2. **KRAKENGUARD Execution Error vs. Violation:** Programs calling `bpf_get_prandom_u32` (helper 7) crashed KLEE (`failed external call: bpf_get_prandom_u32.toreplace`) because helper 7 is un-stubbed in KRAKENGUARD's lifter/runtime. Execution crashes were erroneously conflated with policy violations.
3. **KRAKENGUARD Daemon Wrapper Gap:** For supported helpers like `bpf_trace_printk`, KLEE detected the unauthorized helper and wrote `POLICY VIOLATIONS DETECTED` to `conditional_policy.results.txt`. However, the legacy daemon wrapper (`pipeline.py`) only inspected legacy `helperFunc.results` (which requires `helper_func`), returning `passed=True`.
4. **Abstract Analyzer 64-bit Immediate Parsing:** The regex in `abstract_policy_analyzer.py` did not accept the `ll` suffix in `r1 = 0x0 ll`, triggering premature `UNKNOWN` on relocation loads.
5. **Category A Stratification:** The analyzer soundly marks unresolved symbolic branches as `UNKNOWN` (`eb23fbd8`). Category A programs must contain abstractly provable compliant code rather than unresolved runtime branch conditions.

---

## 2. Failure Classification Matrix

| Program | Initial Analyzer | Initial KRAKENGUARD | Expected | Root Cause | Reconciliation Action |
|---|---|---|---|---|---|
| a4 | UNKNOWN | COMPLIANT | SAFE | Unresolved symbolic branch on `ktime` | Stratify A to abstractly provable compliant code (permitted helpers/maps) |
| a5 | UNKNOWN | COMPLIANT | SAFE | Unresolved symbolic branch on `ktime` | Stratify A to abstractly provable compliant code |
| a6 | UNKNOWN | COMPLIANT | SAFE | Unresolved symbolic branch on `ktime` | Stratify A to abstractly provable compliant code |
| c2 | VIOLATION | COMPLIANT | VIOLATION | Policy lacks `return_value`; `XDP_TX` allowed by KLEE | Use genuine policy constraint (`bpf_trace_printk` or map violation) |
| c3 | UNKNOWN | COMPLIANT | VIOLATION | Analyzer choked on `0x0 ll`; daemon ignored `conditional_policy.results.txt` | Fix regex; validator inspects `conditional_policy.results.txt` |
| c5 | UNKNOWN | COMPLIANT | VIOLATION | Analyzer choked on `ll` and branch; daemon ignored `conditional_policy.results.txt` | Structure clean unconditional violation; fix regex and validator |
| c6 | UNKNOWN | COMPLIANT | VIOLATION | Policy lacks `return_value` | Use genuine policy constraint |
| d1 | UNKNOWN | COMPLIANT | VIOLATION | Policy lacks `return_value` | Use supported unauthorized helper on branch |
| d2 | UNKNOWN | POLICY VIOLATION | VIOLATION | KLEE crashed on un-stubbed helper 7 (execution error) | Use supported helper (`bpf_trace_printk`) so KLEE verifies cleanly |
| d3 | UNKNOWN | COMPLIANT | VIOLATION | Policy lacks `return_value` | Use supported unauthorized helper on branch |
| d4 | UNKNOWN | POLICY VIOLATION | VIOLATION | KLEE crashed on un-stubbed helper 7 | Use supported helper (`bpf_trace_printk`) |
| d5 | UNKNOWN | COMPLIANT | VIOLATION | Policy lacks `return_value` | Use supported unauthorized helper on branch |
| d6 | UNKNOWN | POLICY VIOLATION | VIOLATION | KLEE crashed on un-stubbed helper 7 | Use supported helper (`bpf_trace_printk`) |

---

## 3. Scientific Invariants Preserved
- The frozen policy hash `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603` remains **unchanged**.
- Analyzer soundness is **preserved**; conservative `unresolved_branch_seen -> UNKNOWN` is maintained.
- KLEE execution crashes are **strictly rejected** as evidence of policy violation.
- Performance gates remain **strictly closed** (`execution_approved = false`, `independent_review_complete = false`).
