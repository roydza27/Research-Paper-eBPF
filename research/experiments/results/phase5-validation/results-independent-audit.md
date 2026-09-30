# Phase 5 — Final Independent Experimental Results Audit

**Repository:** `roydza27/Research-Paper-eBPF`  
**Research:** *Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification*  
**Audit type:** Independent audit of claimed completed Phase 5 experimental evidence  
**Audit boundary:** No experiment execution, rerun, result modification, telemetry modification, protocol modification, analyzer/corpus/policy modification, deletion, or regeneration.

# Final verdict

## FAIL — EXPERIMENTAL EVIDENCE REQUIRES CORRECTION

The claimed Phase 5 execution cannot be independently audited from the current repository because the supplied execution provenance is not present in the repository state.

## 1. Execution provenance

The requested execution state identifies:

- execution branch: `phase5-execution-e3-e4-e5`
- execution commit: `0e1d96cf13574222e58de349ce885b28b6e0ac9d`
- parent authorization: `b8593f35fde7c6281eacc272feaa166af89c5527`

Direct repository verification found:

- `b8593f35...` exists as the Phase 5 execution-gate authorization commit.
- `0e1d96cf...` does **not** exist in the repository's Git object/commit history exposed by GitHub.
- `phase5-execution-e3-e4-e5` is **not present** in the repository branch list.
- No committed execution result tree corresponding to that execution commit is present.

This means the claimed execution state cannot be established from the repository.

## 2. Current authoritative main

Current `origin/main` is:

`6c42798a94e647ce558d60f562ac5d1546996c60`

Its latest commit is the Phase 5 execution-gate review merge.

The authoritative gate file is:

`research/experiments/design/phase5-execution-gate.json`

Its current state still records:

- `execution_approved = true`
- `design_status = CORRECTION_VALIDATED`
- E3 `executed = false`
- E4 `executed = false`
- E5 `executed = false`
- E4 total executions = 432 as a protocol definition, not as completed evidence
- E5 execution count = TBD after corpus validation

Therefore the current authoritative repository does **not** contain a completed-execution state.

## 3. E3 audit

Required evidence:

- 216 actual executions
- 24 programs
- 2 warmups + 7 measured per program
- unique run IDs
- raw execution artifacts
- recomputable SAFE/VIOLATION/UNKNOWN counts
- reference-verdict comparison

Current repository inspection did not locate a committed E3 execution result set or an execution branch containing the claimed results.

Consequently the following cannot be independently recomputed:

- SAFE = 6
- VIOLATION = 6
- UNKNOWN = 12
- discharge fraction = 50.0%
- Wilson 95% CI = 31.4%–68.6%
- false SAFE = 0
- false VIOLATION = 0
- correctness = 24/24

These values are therefore **not accepted as completed experimental evidence** by this audit.

## 4. E4 audit

Required evidence:

- 432 actual executions
- 96 warmups
- 336 measured runs
- 24 programs
- both conditions for every program
- 7 measured repetitions per program/condition
- unique run IDs
- no missing runs
- no silent retries
- no timeout/failure rows
- raw telemetry for every execution
- machine-readable aggregate data

The current repository contains no committed E4 execution dataset matching the claimed execution commit.

Therefore the audit cannot independently recompute:

- per-program symbolic-only medians
- per-program hybrid medians
- Delta
- Ratio
- Savings
- pooled/aggregate summaries
- the claimed 694.28 ms symbolic median
- the claimed 382.32 ms hybrid median
- the claimed 45.53% overall savings
- the claimed 684.0 ms / 38.0 ms discharged-subpopulation medians
- the claimed 94.4% discharged-subpopulation savings

No E4 performance conclusion is accepted.

## 5. E4 raw-to-aggregate reconciliation

Because the claimed execution artifacts are absent, the following requested comparisons cannot be performed:

- raw measured repetitions → per-program medians
- per-program medians → paired analysis
- paired analysis → `e4-paired-analysis.csv`
- raw data → `e4-results.json`
- raw data → `e4-summary.json`
- machine-readable data → README/report

The requested a3 report-formatting inspection also cannot establish whether the claimed post-execution report is malformed because the claimed execution report itself is not present in the current repository state.

## 6. E4 correctness/fallback audit

The current repository contains pre-execution correctness/fallback validation evidence, including the previously audited fallback fixtures. It does **not** contain the claimed completed E4 execution evidence.

Therefore this audit cannot independently establish, for all 432 executions:

- symbolic-only verdict
- hybrid verdict
- reference verdict
- zero correctness mismatches
- A/C abstract discharge without KRAKENGUARD
- B/D UNKNOWN → actual KRAKENGUARD fallback

The pre-execution validation evidence must not be substituted for the missing E4 execution evidence.

## 7. E5 audit

The current repository contains the E5 protocol/design material and pre-execution validation material, but no committed execution result set corresponding to the claimed Phase 5 execution.

Therefore the requested post-execution verification of:

- strata 1, 2, 4, 8, 16, 32
- explicit 64-unreachable result
- program counts
- discharge/fallback counts
- fallback fractions
- abstract-analysis time
- symbolic fallback time
- total hybrid time
- KLEE paths
- solver queries

cannot be performed independently.

The claim that stratum 64 is unreachable cannot be accepted as a completed experimental result without the corresponding execution artifact.

## 8. Raw telemetry completeness

The current repository contains committed raw fallback validation evidence, but the requested complete E3/E4/E5 execution telemetry is absent.

In particular, this audit cannot establish raw evidence for all claimed E3/E4/E5 executions containing:

- stdout
- stderr
- request data
- daemon responses
- conditional-policy results
- timing metadata
- run IDs
- environment metadata

For E4 specifically, there is no repository-visible chain tracing all 432 claimed executions to raw telemetry.

## 9. No-result-manipulation assessment

Because the execution commit and branch are absent, this audit cannot establish:

- whether failed runs were deleted
- whether runs are missing
- whether retries occurred
- whether measured values were edited
- whether outliers were removed
- whether raw evidence was preserved for every execution

This is an evidence-availability failure, not a finding that manipulation occurred.

No manipulation allegation is made.

## 10. Formatting issue

The requested a3 rendering issue cannot be classified as either:

A. human-readable formatting only, or  
B. underlying artifact corruption

because the claimed post-execution report is not present in the repository state being audited.

This must be revisited against the actual execution artifacts once they are committed and reachable.

## 11. Provenance controls

The previously frozen controls remain identifiable in the current repository:

- KRAKENGUARD: `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- Policy: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`
- Container: `kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4`
- Kernel: `Linux 7.2.3-arch1-2`
- Compiler: `Clang 22.1.8`
- Architecture: `x86_64`
- Hook: `XDP`

However, frozen controls alone do not establish that a completed E3/E4/E5 execution occurred under those controls.

The claimed execution commit and deterministic seed `42` cannot be tied to completed execution artifacts in the current repository.

## 12. Cross-experiment consistency

The existing repository supports auditing the Phase 5 **design and pre-execution validation state**, but not the claimed completed E3/E4/E5 result state.

No completed-experiment claim is inferred from E2, E3 validation, or fallback validation artifacts.

The audit therefore does not perform or imply any statistical interpretation.

## 13. Required correction

Before a PASS can be issued, the actual execution provenance must become independently reachable and auditable.

At minimum, the repository must expose:

1. execution commit `0e1d96cf13574222e58de349ce885b28b6e0ac9d`, or an explicitly documented replacement execution commit;
2. the `phase5-execution-e3-e4-e5` execution branch, or an equivalent immutable ancestry proving the execution;
3. committed E3 machine-readable results and raw telemetry;
4. committed E4 machine-readable results, paired analysis, aggregate summaries, and raw telemetry for all 432 executions;
5. committed E5 machine-readable results and raw telemetry;
6. complete provenance tying those artifacts to the approved gate, frozen environment, policy, corpus, compiler, seed, and execution commit.

The results must then be audited without rerunning the experiments.

# Final audit verdict

**FAIL — EXPERIMENTAL EVIDENCE REQUIRES CORRECTION**

This verdict does **not** claim that the experiments failed.

It means the claimed completed experimental evidence is not currently available in the repository in a provenance-verifiable form, so it is not yet safe to declare the dataset ready for formal statistical analysis.

**No experiments were rerun.**

**No experiment results, raw telemetry, analyzer, corpus, policy, or protocol were modified.**
