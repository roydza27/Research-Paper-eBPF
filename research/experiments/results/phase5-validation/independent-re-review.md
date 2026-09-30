# Phase 5 — Independent Re-Review of Correctness, Provenance & Experimental Readiness

> [!NOTE]
> **Historical Review Record — Superseded**  
> This review evaluated pre-correction commit `51e1dc2683bc1ffef02172193aee6bcf79be6037` against base `799412ed885d2e7dd754f4bee55849a71b8e4e0a`.  
> All three identified technical blockers (fail-closed conditional extraction, B01 12-test regression suite, and request-linked raw fallback artifacts) were subsequently resolved and squashed into PR #17 (`adc57ab2f7bc29b35be7e3f23535c7c209dfcc8d`) on `main`. This document is preserved for historical review provenance.

## Executive verdict

**FAIL — PHASE 5 CORRECTION REQUIRES FURTHER WORK**

The correction materially resolves the previously documented semantic problems: the frozen E1 policy is unchanged, the corpus now uses genuine helper-policy violations rather than relying on forbidden return values, helper-7 KLEE crashes are avoided, the abstract analyzer remains conservative on unsupported behavior, and the 24-case CSV/JSON accounting is internally consistent.

However, the evidence is **not yet sufficient to recommend opening the Phase 5 execution gate**. Three concrete issues remain:

1. **Authoritative KRAKENGUARD extraction is not fail-closed.** extract_krakenguard_verdict() reads conditional_policy.results.txt when it recognizes one of two status strings, but otherwise falls back to response.verification_result. The review requirement explicitly requires missing/malformed conditional output to remain a validation failure rather than becoming COMPLIANT or POLICY VIOLATION through a secondary result path.
2. **Correction-era provenance is stale/inconsistent.** correction-validation.md records the validation HEAD as 799412ed885d2e7dd754f4bee55849a71b8e4e0a, while the corrected validation commit is 51e1dc2683bc1ffef02172193aee6bcf79be6037 and the current branch has subsequently advanced to 1a6c01f0a7c56bbd46e81dcfbc363db696ecd23c. The validation report therefore does not bind its claims to the corrected implementation commit.
3. **The B01 regression suite does not test the two most important correction boundaries.** The nine tests cover conservative UNKNOWN behavior and map/helper cases, but do not exercise the corrected 64-bit-immediate ll parsing or the absence of a return_value rule. Those were explicit prior failure modes, so the correction is not protected by a regression test.

A secondary evidence weakness is that the fallback artifacts record request IDs and derived verdicts, but the repository does not contain matching raw artifacts for those request IDs. This prevents the reviewer from independently tracing the recorded fallback verdict back to the actual KRAKENGUARD response.

## Repository state

- Repository: roydza27/Research-Paper-eBPF
- Branch: phase5-experimental-design
- Reported HEAD in the review brief: 51e1dc28532f14643df65d3ec85a2107452d3a95 — not found
- Corrected validation commit found in Git history: 51e1dc2683bc1ffef02172193aee6bcf79be6037
- Current branch HEAD at review start: 1a6c01f0a7c56bbd46e81dcfbc363db696ecd23c
- Corrected validation commit is the parent of the current merge commit.
- Base used for the correction comparison: 799412ed885d2e7dd754f4bee55849a71b8e4e0a

The correction commit changes the analyzer, Phase 5 corpus sources/metadata, environment manifest, validation scripts, validation results, failure investigation, and correction reports. The current branch then merges main without changing the Phase 5 gate to approved.

## B01 — Abstract analyzer soundness

**FAIL**

### What passes

The current analyzer implements the intended conservative boundary:
- SAFE only when every reachable abstract path is proven compliant.
- VIOLATION only when every reachable terminal path is proven violating, or an unconditionally forbidden action is proven reachable.
- Unsupported instructions, unknown helpers, unresolved map identity, unsupported map writes, analysis failures, and unresolved/mixed behavior become UNKNOWN.
- The analyzer does not consult corpus labels, filenames, or expected results.
- The corrected parser accepts numeric assignments with an optional ll suffix.
- Return-value restrictions are now optional: when the frozen policy contains no return_value rule, the analyzer does not invent one.

### Why B01 still fails independent re-review

The nine regression tests do not exercise the two correction boundaries that caused prior failures:
- no test for r1 = 0x0 ll or equivalent 64-bit immediate syntax;
- no test proving that an absent return_value policy rule permits values such as XDP_TX rather than manufacturing a default {1,2} restriction.

The test suite therefore demonstrates conservative behavior generally, but does not independently protect the exact corrections that were required to make Phase 5 valid.

Required correction: add regression fixtures for both boundaries and make them part of the mandatory soundness suite.

## B02 — Policy consistency

**PASS**

The committed frozen policy remains:
270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603

The policy contains the E1 action definition and helper allowlist, with no added return_value restriction and no added helper_func restriction. The corrected corpus was changed to use bpf_trace_printk as the explicit forbidden helper under the frozen helper allowlist instead of redefining policy semantics around XDP_TX.

## B03 — Environment/provenance

**FAIL**

The environment manifest records the KRAKENGUARD commit e7bd84005b304c5a10efcdb04914d1882b3cccf7, clang 22.1.8, kernel 7.2.3-arch1-2, x86_64, XDP, the immutable container digest kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4, and the frozen policy SHA-256 above.

The validator also contains a fail-closed preflight that checks the kernel, architecture, compiler, KRAKENGUARD commit, manifest fields, policy hash, and Docker image digest.

The blocker is the committed validation evidence binding: correction-validation.md says the validation HEAD was the pre-correction parent 799412ed..., which is inconsistent with the corrected validation commit and current branch state. The report must be regenerated with the exact corrected commit/tree provenance before the results can be treated as correction-bound evidence.

## B04 — Immutable container identity

**PASS**

The immutable image digest is present in the committed Phase 5 environment manifest, and the validator checks Docker's observed RepoDigests against that exact value before producing validation evidence.

The execution gate remains closed.

## Corpus

**PASS**

### A — Provable compliant
A1–A6 are now deliberately simple enough for the abstract domain to prove. They use permitted bpf_ktime_get_ns operations and arithmetic and return XDP_PASS. The revised cases remove the earlier unresolved symbolic branch structure.

### B — Abstractly uncertain, symbolically compliant
B1–B6 remain compliant programs but contain packet-memory operations and runtime-dependent branches. The committed validation evidence reports conservative UNKNOWN from the abstract stage and COMPLIANT from KRAKENGUARD.

The current abstract proof text shows that the UNKNOWN classification is primarily caused by an unsupported packet-memory load, not solely by the dynamic return branch. This is still a legitimate selective-fallback case, but the category description should not be interpreted as proof that the abstract analyzer understands the full packet-memory semantics.

### C — Provable policy violation
C1–C6 use the frozen policy's helper allowlist boundary: bpf_trace_printk is not permitted. The violations are unconditional and therefore appropriate for abstract fast-path rejection.

### D — Symbolic-only policy violation
D1–D6 conditionally call bpf_trace_printk. The abstract analyzer observes both compliant and violating paths and therefore returns UNKNOWN; KRAKENGUARD reports the policy violation. The corrected corpus avoids the previously observed unsupported bpf_get_prandom_u32 / helper-7 KLEE crash.

## 24/24 result reconciliation

**PASS for internal accounting; NOT sufficient as gate evidence**

The committed validation-results.csv contains 24 unique program IDs: A 6, B 6, C 6, D 6.

The CSV and validation-results.json contain the same program ordering and the same abstract/reference/hybrid verdicts for all 24 cases.

Reported correctness: A 6/6 SAFE + COMPLIANT; B 6/6 UNKNOWN + COMPLIANT; C 6/6 VIOLATION + POLICY VIOLATION; D 6/6 UNKNOWN + POLICY VIOLATION; false SAFE 0; false VIOLATION 0; abstract discharge 12/24.

This establishes internal consistency of the committed result tables. It does not independently cure the provenance and authoritative-output problems above.

## Validation independence

**PASS**

The abstract analyzer and KRAKENGUARD are invoked as separate stages. The analyzer does not read category labels or stored reference verdicts. The validator compares independently obtained abstract and reference results against category expectations after both stages execute.

No circular construction of the KRAKENGUARD result from the abstract result was found.

## Fallback

**FAIL**

The fallback script genuinely invokes KRAKENGUARD only after asserting that the analyzer returned UNKNOWN. That part of the control flow is correct.

The committed fallback records b1: UNKNOWN → KRAKENGUARD → COMPLIANT and d1: UNKNOWN → KRAKENGUARD → POLICY VIOLATION, with request IDs.

However:
1. the repository contains no matching raw artifact for those request IDs;
2. the validator's extraction function falls back to response.verification_result if the conditional policy output is missing or does not contain one of the two recognized status strings;
3. the review requirement explicitly requires missing/malformed output, crashes, timeouts, and infrastructure failures to remain failures rather than being converted into policy verdicts.

Therefore the current evidence does not prove a strictly authoritative UNKNOWN → KRAKENGUARD → verdict chain under all failure conditions.

Required correction: make conditional-policy output mandatory and fail closed on missing/unrecognized output; preserve the raw response/output artifact or another immutable request-linked execution record for the fallback fixtures.

## KLEE crash handling

**PASS**

The correction investigation explicitly distinguishes helper-7 KLEE external-call crashes from policy violations. The corrected D corpus uses supported bpf_trace_printk policy violations instead of relying on helper-7 execution failures.

## E3 / E4 / E5 readiness

**E3: NOT RUN** — The design remains capable of measuring the fraction of corpus cases conclusively discharged by the abstract stage, but execution should remain blocked until the correction evidence is repaired.

**E4: NOT RUN** — The design retains a baseline-vs-hybrid comparison under a fixed policy/environment and treats correctness disagreements as failures. No performance estimate is made here.

**E5: NOT RUN** — The fallback-scaling design is methodologically compatible with the corrected UNKNOWN routing, but execution must not begin until fallback provenance and authoritative verdict extraction are repaired.

**432-run matrix: NOT RUN**

## Remaining blockers

1. Regenerate correction-validation provenance against the actual corrected commit/tree; remove the stale pre-correction HEAD from the correction-era report.
2. Make conditional_policy.results.txt authoritative and fail closed when it is missing, malformed, ambiguous, or unavailable.
3. Preserve request-linked raw KRAKENGUARD fallback evidence for b1/d1 (or an equivalent immutable execution artifact that permits independent verification).
4. Add B01 regression tests for 64-bit ll immediate parsing and absent return_value semantics.
5. Re-run the correction-only validation after those changes and regenerate the CSV/JSON/Markdown evidence so all metadata is bound to the same corrected implementation/environment state.

## Gate decision

Recommended state: **PHASE 5 RE-REVIEW FAIL**

Do **not** open the execution gate.

execution_approved = false

independent_review_complete = false

E3, E4, E5, and the 432-run matrix were **not executed** during this review.

## Evidence reviewed

- research/analyzer/abstract_policy_analyzer.py
- research/tests/test_phase5_abstract_soundness.py
- research/experiments/scripts/validate-phase5-corpus.py
- research/experiments/scripts/validate-phase5-fallback.py
- research/experiments/corpus/phase5/phase5-environment.json
- research/experiments/corpus/phase5/policies/phase5_policy.json
- research/experiments/corpus/phase5/metadata.csv
- corrected A/B/C/D corpus source files
- validation-results.csv
- validation-results.json
- correction-validation.md
- correction-validation.json
- audit.md
- audit.json
- fallback-validation.md
- fallback-validation.json
- correction-failure-investigation.md
- phase5-execution-gate.json

No local experiments, E3, E4, E5, or 432-run matrix were executed. No implementation, corpus, policy, or gate files were modified by this review.