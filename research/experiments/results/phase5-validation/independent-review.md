# Phase 5 — Independent Implementation Review

**Review status:** FAIL — EXECUTION BLOCKED  
**Reviewed branch:** `phase5-experimental-design`  
**Research:** Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification  
**Review date:** 2026-09-30

## Scope

This review independently inspected the Phase 5 design, execution gate, abstract analyzer, corpus generator, validation orchestrator, frozen corpus metadata/policy, validation CSV/JSON, and Phase 5 audit artifacts. E1 and E2 evidence was cross-checked for baseline consistency.

No E3, E4, or E5 performance matrix was executed. No timing experiment was repeated. No implementation or corpus was modified during the review.

## Implementation findings

### Abstract domain and semantics

The analyzer does implement the three-valued verdict enum:

- SAFE
- VIOLATION
- UNKNOWN

It disassembles the compiled object with `llvm-objdump`, constructs a CFG, tracks a small register-value abstraction, records unresolved branch predicates, recognizes helper calls, and has conservative UNKNOWN fallbacks.

However, the implemented abstract domain is substantially narrower than the Phase 5 design specification.

The implementation defines types such as `INTERVAL`, `PACKET_PTR`, and `MAP_PTR`, but the active transfer logic does not implement a general interval domain, pointer-provenance analysis, map-state analysis, policy-condition abstraction, or memory-range proof system.

Most importantly, memory stores are not handled by the transfer semantics. A store can therefore be encountered and ignored while analysis continues to an allowed return. SAFE is ultimately decided from exit return values plus observed helper calls; there is no requirement that all policy-relevant memory writes have been proven compliant.

Similarly, map accesses are not semantically analyzed. The Phase 5 corpus contains no map-access cases that exercise the claimed map policy semantics.

This creates a soundness gap: an unsupported or incompletely modeled policy-relevant instruction can be present without forcing UNKNOWN.

### Helper handling

Unknown helper IDs are converted to a synthetic helper name and then treated as forbidden when the allowed-helper set is non-empty. This does not implement the required distinction:

`unknown helper -> UNKNOWN`

Instead, an unrecognized helper can become VIOLATION. That violates the required separation between uncertainty and an established policy violation.

### CFG and instruction handling

The analyzer uses textual disassembly parsing and recognizes only a limited set of instruction patterns. There is no explicit unsupported-instruction state that forces UNKNOWN.

Errors while reading relocations are swallowed, and unrecognized instruction forms do not produce a soundness failure. The analysis can therefore continue with incomplete semantics.

LLVM documents `llvm-objdump -d` as a disassembler for executable sections; relying on textual parsing is therefore an implementation detail that requires a complete instruction-semantic coverage policy before SAFE can be trusted. citeturn1search0

### Corpus leakage

No Phase-5 corpus identifiers (`a1`–`d6`) or expected-category labels were found in the abstract analyzer. The analyzer does not consult `validation-results` or corpus metadata to select its verdict.

**Leakage assessment: PASS.**

## Corpus findings

The corpus contains 24 programs: 6 each in A, B, C and D.

The category structure is internally consistent with the generated source:

- A: compliant programs with permitted returns/helpers.
- B: compliant programs with unresolved dynamic return conditions.
- C: unconditional forbidden helpers or returns.
- D: conditionally reachable forbidden helpers or returns.

The observed validation table reports 6/6 agreement for every category, with 0 false SAFE and 0 false VIOLATION.

However, the corpus does not exercise several dimensions claimed by the Phase 5 design:

- map lookup/update/delete semantics;
- policy-relevant map state;
- meaningful pointer provenance;
- policy-relevant memory-write restrictions;
- unsupported-instruction behavior;
- unknown-helper behavior;
- richer interval reasoning.

The B/D cases are legitimate demonstrations of the current abstraction boundary, but they are also narrowly constructed around unresolved branch conditions. They do not establish soundness of the analyzer outside that narrow family.

## Correctness findings

### Reported validation results

The committed validation artifacts report:

- 24/24 category agreements;
- 0 false SAFE;
- 0 false VIOLATION;
- 12/24 abstract discharges.

Those results are reproducible at the aggregate level from the committed CSV.

### Limitation of the validation orchestrator

The validation script executes the KRAKENGUARD reference for every program after abstract analysis.

For an UNKNOWN result it then constructs the hybrid result by assigning:

`hybrid_verdict = reference_verdict`

and:

`hybrid_duration = abstract_duration + reference_duration`

Thus the validation artifact verifies the abstract/reference relationship and the intended accounting formula, but it does not independently execute a selective hybrid pipeline.

For A/C programs, the reference is still executed as part of validation even though the recorded hybrid route is FAST_PATH. Therefore the pilot does not itself demonstrate that symbolic execution was actually avoided; that remains an execution-stage property.

### Correctness classification

- False SAFE: 0 in the committed 24-case validation.
- False VIOLATION: 0 in the committed 24-case validation.
- Unexpected UNKNOWN: none relative to the frozen category labels.
- Reference discrepancies: none in the committed validation table.

These empirical results are valid as corpus-specific observations, but they do not establish general SAFE soundness because the implementation has unmodeled operations that can be silently ignored.

## Leakage assessment

**PASS.**

The analyzer contains no corpus-specific program identifiers or expected labels. Verdicts are derived from disassembled object content and the supplied policy.

The validation orchestrator does contain the expected category mapping, but that mapping is used for validation assertions after analyzer execution; it is not passed into the analyzer.

## Reference-verifier assessment

### Baseline revision

The Phase 5 gate records KRAKENGUARD commit:

`e7bd84005b304c5a10efcdb04914d1882b3cccf7`

This agrees with the Phase 4 baseline.

### Policy provenance — blocker

The Phase 5 design specifies the E1 fixed policy hash as:

`270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`

and describes it as the mandatory reference/control policy.

The actual Phase 5 corpus policy and validation artifacts use:

`8e349d091fd4c1af9127c8fe19ceb99ad0468ef8a565d5e47224993f051204b6`

These are different policy objects.

The Phase 5 plan permits a conditional policy family, but it simultaneously says the E1 fixed policy remains the mandatory reference. The current implementation therefore does not cleanly establish which policy is authoritative for the Phase 5 correctness gate.

This must be resolved and re-frozen before execution.

### Reference configuration enforcement

The validation script computes the current policy hash and invokes the locally available KRAKENGUARD client, but it does not enforce the expected KRAKENGUARD commit, compiler version, kernel version, architecture, or exact policy hash at runtime.

The gate JSON records these values, but the validation orchestrator does not independently verify them.

## Reproducibility assessment

The corpus metadata correctly records:

- source SHA-256;
- object SHA-256;
- policy SHA-256.

However, the Phase 5 `metadata.csv` does **not** record:

- compiler;
- compiler version;
- compiler flags;
- kernel;
- architecture;
- KRAKENGUARD commit;
- hook;
- image/tag/digest.

Those fields are explicitly required by the Phase 5 protocol.

Consequently, the frozen corpus metadata does not by itself permit reconstruction of the exact validation environment.

The validator also does not assert the environment against the gate's declared configuration.

## Statistical-design assessment

The E3/E4/E5 design itself is structurally coherent:

- E3: 24 programs × 2 warmups × 7 measured = 216 executions.
- E4: 24 programs × 2 conditions × 2 warmups × 7 measured = 672? **Correction:** the approved E4 accounting is 24 × 2 conditions × 9 total executions = 432.
- E5 is correctly deferred until path strata are validated.

The approved E4 endpoint is per-program median end-to-end wall time, with paired program-level comparisons and uncertainty/effect-size reporting.

The hybrid cost definition correctly includes abstract-analysis time plus symbolic fallback time for UNKNOWN cases.

No performance conclusion is drawn from the validation telemetry.

## E3/E4/E5 methodology

**E3:** Definition is appropriate. The primary discharge metric is `(SAFE + VIOLATION) / total`. Actual E3 execution remains pending.

**E4:** The baseline/hybrid comparison is correctly defined as complete end-to-end pipelines. Abstract-only time must not be compared with symbolic-only time.

**E5:** The design correctly focuses on selective symbolic invocation and fallback fraction rather than claiming that abstract analysis makes KLEE intrinsically faster.

The major unresolved issue is that the current abstract analyzer is not sufficiently sound to be the front-end whose performance is measured.

## Findings

| ID | Severity | Finding | Evidence | Required Action |
|---|---|---|---|---|
| P5-B01 | BLOCKER | SAFE can be produced despite unmodeled policy-relevant memory stores/instructions. | Abstract analyzer transfer logic has no sound store/policy-memory semantics and no explicit unsupported-instruction-to-UNKNOWN rule. | Implement complete conservative handling for the supported instruction/policy subset; unsupported constructs must force UNKNOWN. |
| P5-B02 | BLOCKER | Phase 5 reference policy is not consistent with the approved E1 fixed-policy control. | Plan specifies hash `270403...`; actual Phase 5 policy/validation uses `8e349...`. | Resolve the policy choice, freeze the authoritative policy, and update the design/gate before re-review. |
| P5-B03 | BLOCKER | Exact reference/environment provenance is not enforced by the validation implementation. | Validator computes current hashes but does not enforce baseline commit/toolchain/kernel/architecture against the gate. | Add hard provenance assertions and fail closed on mismatch. |
| P5-B04 | BLOCKER | Corpus metadata is insufficient for exact reconstruction. | Phase 5 metadata.csv lacks compiler/version/flags/kernel/architecture/KRAKENGUARD revision/hook/image provenance. | Extend and re-freeze metadata with all required environment fields. |
| P5-M01 | MAJOR | Validation synthesizes UNKNOWN hybrid results from the reference result rather than independently executing the selective fallback pipeline. | Validator assigns `hybrid_verdict = ref_verdict` for UNKNOWN. | Keep correctness pilot separate from execution evidence; add a true selective-routing pilot before performance execution. |
| P5-M02 | MAJOR | Corpus does not exercise map semantics, memory-policy semantics, unknown helpers, or unsupported instructions. | All 24 programs are concentrated in return/helper/branch constructions. | Add representative boundary cases or explicitly narrow the research claim and review the narrowed scope. |
| P5-M03 | MAJOR | Claimed abstract domain is broader than implemented semantics. | Design calls for intervals, known bits, pointer/memory ranges, map summaries and policy-condition facts; implementation primarily tracks constants and unresolved predicates. | Align documentation and implementation; do not claim unsupported abstract capabilities. |
| P5-M04 | MAJOR | Unknown helper handling can produce VIOLATION rather than UNKNOWN. | Unrecognized helper IDs are treated as non-whitelisted/forbidden when the allowed-helper set is non-empty. | Return UNKNOWN for unrecognized helpers unless reachability and prohibition are independently established. |
| P5-M05 | MINOR | Corpus generator contains a misleading B2 comment describing a packet payload check while the implementation uses a time-derived condition. | `generate-phase5-corpus.py`. | Correct the comment in the next correction commit. |

## Gate decision

The current validation results demonstrate useful corpus-specific agreement and no observed leakage, but they do not establish a sufficiently sound abstract verifier or reproducible frozen reference configuration.

The existence of 0 false SAFE results in this 24-program corpus cannot compensate for an implementation path where unmodeled policy-relevant operations may be ignored.

Therefore:

**FAIL — EXECUTION BLOCKED**

The Phase 5 execution gate must remain closed.

`independent_review_complete = false`  
`execution_approved = false`

A correction commit followed by a fresh independent review is required before E3/E4/E5 may begin.
