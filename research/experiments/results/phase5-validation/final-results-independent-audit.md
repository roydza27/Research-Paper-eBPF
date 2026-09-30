# Phase 5 — Final Independent Experimental Results Audit

Repository: roydza27/Research-Paper-eBPF  
Research: Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification  
Audit type: Independent results / provenance audit  
Audit execution: No experiment execution performed

## 1. Executive verdict

# PASS — PHASE 5 EXPERIMENTAL EVIDENCE VERIFIED

The previous reachability failure is resolved. GitHub exposes the original execution commit 0e1d96cf13574222e58de349ce885b28b6e0ac9d, the recovery branch phase5-execution-evidence-recovery points exactly to that commit, and its parent is the authorized execution-gate review commit b8593f35fde7c6281eacc272feaa166af89c5527.

The recovered execution tree c105b05fa8719433598f05814d42ccb3fe8978f0 contains the complete E3/E4/E5 evidence. Current main also contains the same E3, E4, and E5 result-tree blobs byte-for-byte: 3,828 relevant result blobs were compared and none are missing or changed.

Independent reconciliation establishes:

- E3: 216 records = 24 programs × 9 repetitions; 48 warmups + 168 measured; 12 discharged programs and 12 UNKNOWN; 50.0% discharge.
- E3 correctness: 24/24 agreement with the frozen KRAKENGUARD reference; false SAFE = 0; false VIOLATION = 0.
- E3 Wilson 95% interval for 12/24 = 31.4%–68.6%.
- E4: 432 records = 24 programs × 2 conditions × 9 repetitions; 96 warmups + 336 measured.
- E4: 0 timeouts, 0 execution failures, and 0 correctness mismatches; 432 unique raw run directories.
- E4 primary paired endpoint recomputes to symbolic-only median 694.277 ms, hybrid median 382.3205 ms, and median per-program savings 45.527%, matching the reported 694.277 ms, 382.320 ms, and 45.53% after rounding.
- All 24 per-program paired-analysis rows independently recompute from measured E4 data with no discrepancies.
- Discharged A/C programs: median symbolic 684.362 ms, hybrid 38.801 ms, median savings 94.335%, consistent with approximately 94.4%.
- Fallback B/D programs: median symbolic 702.7205 ms, hybrid 736.722 ms, median savings -4.947%, consistent with approximately -4.9%.
- E5 reachable strata are 1, 2, 4, 8, 16, and 32. Stratum 1 has 12 discharged / 0 fallback; strata 2–32 have 100% fallback. Stratum 64 is explicitly recorded as unreachable with zero eligible programs.
- E5 scaling values are independently derivable from the preserved E4 measured raw telemetry.
- Representative discharged and fallback raw E4 records demonstrate the intended independent execution paths; fallback records contain KRAKENGUARD request/response evidence rather than merely a copied reference verdict.

## 2. Repository state

| Item | Verified value |
|---|---|
| Current main | 33c1fc6f3fd40555cc4c3483803d6d01c84e50b4 |
| Current main tree | 6824c66b82e973714d074b9c15e3cb86227beb58 |
| Recovery branch | phase5-execution-evidence-recovery |
| Recovery branch SHA | 0e1d96cf13574222e58de349ce885b28b6e0ac9d |
| Execution commit | 0e1d96cf13574222e58de349ce885b28b6e0ac9d |
| Execution tree | c105b05fa8719433598f05814d42ccb3fe8978f0 |
| Execution parent | b8593f35fde7c6281eacc272feaa166af89c5527 |

The recovery branch points exactly to the execution commit. The execution commit is a real commit object, is publicly reachable, and has the expected authorized parent and tree.

The current main integration is not required to preserve the execution commit as a direct ancestor. The current main commit is a recovery integration commit, and recursive tree comparison establishes preservation of the experimental evidence itself.

## 3. Execution commit provenance

Verified from the Git commit object:

- SHA: 0e1d96cf13574222e58de349ce885b28b6e0ac9d
- Parent: b8593f35fde7c6281eacc272feaa166af89c5527
- Tree: c105b05fa8719433598f05814d42ccb3fe8978f0
- Author: Royal DSouza
- Committer: Royal DSouza
- Author/committer timestamp: 2026-09-30 19:53:03 UTC
- Commit message records execution of E3, E4, and E5 and preservation of raw telemetry.

The execution commit is immutable by SHA. The recovery branch points exactly to it.

## 4. Recovery branch verification

The Git ref refs/heads/phase5-execution-evidence-recovery currently resolves to:

0e1d96cf13574222e58de349ce885b28b6e0ac9d

This exactly matches the recovered execution commit. No ref mutation was performed during this audit.

## 5. Main integration verification

Recursive tree comparison between execution tree c105b05fa8719433598f05814d42ccb3fe8978f0 and current main tree 6824c66b82e973714d074b9c15e3cb86227beb58 gives:

| Result family | Execution-tree blobs | Main blobs | Missing | Changed blob SHA |
|---|---:|---:|---:|---:|
| E3 | 364 | 364 | 0 | 0 |
| E4 | 3,461 | 3,461 | 0 | 0 |
| E5 | 3 | 3 | 0 | 0 |
| Total | 3,828 | 3,828 | 0 | 0 |

The 432 E4 raw run directories are also present on main.

Therefore the published main tree preserves the recovered experimental evidence without content changes in the E3/E4/E5 result families.

## 6. E3 audit

The E3 machine-readable CSV contains exactly 216 records:

- 24 unique programs.
- 2 warmups per program.
- 7 measured repetitions per program.
- 48 warmups.
- 168 measured records.
- No duplicate run IDs.
- No missing program/repetition combinations.
- Every program has exactly 9 records.

Measured category distribution is 42 records each for A, B, C, and D.

At the program level:

- A1–A6: SAFE and discharged.
- B1–B6: UNKNOWN and not discharged.
- C1–C6: VIOLATION and discharged.
- D1–D6: UNKNOWN and not discharged.

Therefore discharge = 12 / 24 = 50.0%.

Correctness was independently checked from stored measured records:

- reference agreement: 24/24
- false SAFE: 0
- false VIOLATION: 0

The Wilson score interval for 12/24 at 95% is [31.43%, 68.57%], which rounds to the reported [31.4%, 68.6%].

E3 raw evidence contains 216 run-level JSON records and 24 reference-evidence directories, so the accounting is not summary-only.

## 7. E4 audit

The E4 CSV contains exactly 432 records:

- 24 programs.
- 2 conditions: symbolic_only and hybrid.
- 9 repetitions per program/condition.
- 96 warmups.
- 336 measured records.
- 0 duplicate run IDs.
- 0 malformed repetition records.
- 0 non-success execution statuses in the stored aggregate dataset.
- 0 correctness mismatches.

The recursive raw evidence contains exactly 432 unique E4 run directories.

Every raw run directory contains at least:

- meta.json
- stdout.txt
- stderr.txt

Representative symbolic-only runs additionally contain KRAKENGUARD request/response and conditional-policy artifacts.

Hybrid runs contain analyzer_output.json. Fallback hybrid runs additionally contain KRAKENGUARD request/response evidence.

The raw tree contains:

- 216 hybrid run directories with analyzer output.
- 108 hybrid run directories with KRAKENGUARD request/response evidence, corresponding to the fallback hybrid runs.
- 216 symbolic-only run directories with request/response evidence.

Representative fallback run e4-b1-hyb-m01 independently records UNKNOWN, fallback_invoked=true, a concrete KRAKENGUARD request ID, symbolic fallback timing, KLEE paths and queries, successful return code, and matching reference/final verdict. Its stored KRAKENGUARD response contains the same request ID, successful status, retained result, execution telemetry, and KLEE path count.

Representative discharged runs A1 and C1 record fallback false, KRAKENGUARD request ID NONE, and zero symbolic fallback time.

## 8. E4 statistical recomputation

The primary endpoint is the paired per-program median end-to-end wall-time endpoint.

For each of the 24 programs, the 7 measured symbolic-only times and 7 measured hybrid times were independently reduced to medians. Delta, ratio, and savings were recomputed.

All 24 rows agree with e4-paired-analysis.csv within stored numerical precision. No paired-analysis discrepancy was found.

Independent aggregate recomputation:

- median of 24 symbolic-only program medians: 694.277 ms
- median of 24 hybrid program medians: 382.3205 ms
- median of 24 per-program savings values: 45.5271%

Reported values are 694.277 ms, 382.320 ms, and 45.53%; these agree after rounding.

Discharged A/C subpopulation:

- 12 programs.
- symbolic-only median: 684.362 ms.
- hybrid median: 38.801 ms.
- median savings: 94.3351%.

Fallback B/D subpopulation:

- 12 programs.
- symbolic-only median: 702.7205 ms.
- hybrid median: 736.722 ms.
- median savings: -4.9473%.

The fallback overhead is visible in the measured data rather than being hidden by an aggregate-only statistic.

## 9. E4 raw-run integrity

The raw directory mapping is one-to-one:

- 432 aggregate E4 records.
- 432 unique raw run directories.
- 432 unique run names.
- no missing raw directories.
- no empty raw directories.
- no raw directory lacking meta.json, stdout.txt, and stderr.txt.

The aggregate CSV includes the raw artifact directory for each run, enabling direct traceability.

Representative raw metadata agrees with aggregate identifiers for A1, B1, C1, and D1, including program, category, condition, repetition, verdict, timing, policy hash, and raw artifact path.

No duplicate IDs, impossible repetition numbers, missing measurements, or inconsistent condition labels were found in the aggregate dataset.

## 10. E5 audit

Stored E5 data identifies reachable strata 1, 2, 4, 8, 16, and 32 and explicitly records stratum 64 as unreachable with zero eligible programs and N/A timing/statistical fields.

| Stratum | Programs | Discharged | Fallback | Fallback fraction |
|---:|---:|---:|---:|---:|
| 1 | 12 | 12 | 0 | 0.0 |
| 2 | 4 | 0 | 4 | 1.0 |
| 4 | 2 | 0 | 2 | 1.0 |
| 8 | 2 | 0 | 2 | 1.0 |
| 16 | 2 | 0 | 2 | 1.0 |
| 32 | 2 | 0 | 2 | 1.0 |
| 64 | 0 | 0 | 0 | N/A |

The E5 timing and KLEE path/query values are independently derivable from preserved E4 measured raw telemetry grouped by target path stratum. The stored E5 scaling table agrees with those derived values under the same per-program median aggregation.

E5 does not introduce a separate 64-path execution; the corpus contains no eligible 64-path program.

## 11. Frozen-control verification

The execution evidence consistently records:

- KRAKENGUARD commit: e7bd84005b304c5a10efcdb04914d1882b3cccf7
- Policy SHA-256: 270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603
- Container digest: kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4
- Kernel: 7.2.3-arch1-2
- Architecture: x86_64
- Compiler: Clang 22.1.8
- Flags: -target bpf -mcpu=v1 -D__TARGET_ARCH_x86 -O2 -g -I/usr/include
- Hook: XDP
- Seed: 42
- Timeout: 300 seconds

The policy hash is present consistently in stored E3/E4 execution records.

The Phase 5 environment manifest is provenance-frozen and records the same KRAKENGUARD commit, compiler, compiler flags, kernel, architecture, hook, container digest, and policy hash.

## 12. Corpus and policy provenance

The authoritative gate records corpus metadata SHA-256:

0afd9ceeb34240c0398381a54b745f10516eb5fd536f310c3c3e6fa71ff31e2a

E3/E4 result records preserve per-program source and object SHA-256 values and the frozen policy SHA-256. Source/object identities are stable across repeated records for each program.

No post-execution corpus or policy modification is present in the relevant execution/main result trees.

## 13. Fallback independence

For discharged hybrid runs:

- abstract verdict is conclusive;
- fallback_invoked=false;
- symbolic fallback time is zero;
- KRAKENGUARD request ID is NONE;
- analyzer output is retained.

For fallback hybrid runs:

- abstract verdict is UNKNOWN;
- fallback_invoked=true;
- a concrete KRAKENGUARD request ID is recorded;
- symbolic fallback timing and KLEE telemetry are recorded;
- raw request/response artifacts are retained.

This establishes that fallback results were not synthesized from the reference verdict alone.

## 14. Gate-state verification

The authoritative gate currently records:

- execution_approved = true
- E3 executed = true
- E4 executed = true
- E5 executed = true
- E3 total executions = 216
- E4 total executions = 432
- E5 execution count = 7
- independent_review_complete = false
- correction_status = CORRECTION_VALIDATED — EXECUTION_APPROVED

The gate was not modified during this audit.

Leaving independent_review_complete=false during this audit is consistent with the requested boundary: this audit records the evidence but does not change the authoritative gate.

## 15. Discrepancies / anomalies

### Historical execution metadata fields

The E3/E4 machine-readable provenance objects contain:

- git_branch = phase5-execution-e3-e4-e5
- git_head = b8593f35fde7c6281eacc272feaa166af89c5527
- git_tree = f0ae25160e21b30be156c62af2ec9484ea1a8306

These values do not equal the recovered execution ref. This is not treated as a failed provenance binding because the validation code explicitly captures the local repository branch/HEAD/tree as an environment snapshot. The immutable execution identity is independently established by the Git commit object, its parent, its tree, and the recovery branch.

The authoritative immutable execution identity is therefore:

0e1d96cf13574222e58de349ce885b28b6e0ac9d → parent b8593f35fde7c6281eacc272feaa166af89c5527, tree c105b05fa8719433598f05814d42ccb3fe8978f0.

This historical metadata distinction is documented rather than silently normalized.

### E5 raw evidence representation

E5 has no separate per-run raw directory family. Its scaling analysis is derived from preserved E4 measured telemetry. The E5 values were independently recomputed from that raw E4 evidence and agree with the stored scaling table. Therefore this is not treated as missing evidence for this experiment definition.

No unexplained numerical discrepancy remains in the E3/E4/E5 machine-readable evidence.

## 16. Scientific boundaries

This audit verifies only the recovered experimental evidence and its internal/provenance consistency.

The evidence supports statements about this tested corpus and environment, including:

- the hybrid analyzer discharged 12 of 24 programs in E3;
- E4 measurements show the reported paired timing differences;
- fallback cases incurred abstract-analysis plus symbolic-verification overhead in this experiment;
- E5 exhibited the observed fallback pattern across reachable path strata;
- the experimental artifacts are provenance-bound and preserved in the published main tree.

The audit does not establish universal claims about hybrid verification, arbitrary eBPF scaling, universal abstract-analysis soundness, a universal symbolic-execution complexity law, production readiness, or generalization beyond the tested corpus/environment.

## 17. Final conclusion

The recovered Phase 5 execution evidence is publicly reachable, ancestry-bound, preserved in main, internally reconciled, and independently auditable.

The previous reachability blocker is resolved.

PASS — PHASE 5 EXPERIMENTAL EVIDENCE VERIFIED

No E3, E4, E5, or 432-run experimental execution was performed during this audit.

Phase 5 can now be considered experimentally evidenced for the tested corpus/environment, subject to the scientific boundaries above.
