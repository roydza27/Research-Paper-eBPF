# Phase 5 Correction Report

**Status:** CORRECTIONS INCOMPLETE — BLOCKED BY CONTAINER DIGEST / CORRECTNESS REVALIDATION

**Correction branch:** phase5-experimental-design

## Scope

This correction sprint addresses P5-B01 through P5-B04. No E3, E4, E5, or 432-run performance matrix has been executed.

Historical Phase 3, E1, and E2 evidence has not been modified.

## P5-B01

### Problem
The abstract analyzer could silently ignore unsupported instructions and could classify unknown helper IDs as violations.

### Root cause
Instruction dispatch did not have a complete fail-closed path, and helper resolution conflated unknown helpers with known policy-forbidden helpers. Memory/map semantics were also broader in the documentation than in the implementation.

### Implementation fix
- Replaced the analyzer with an explicit conservative transfer boundary.
- Unsupported instructions and analysis failures return UNKNOWN.
- Unknown helper IDs return UNKNOWN.
- Known forbidden helpers remain VIOLATION when reachable.
- Mixed reachable SAFE/VIOLATION outcomes return UNKNOWN.
- State/loop limits return UNKNOWN.
- Map helper operations require resolvable map identity.
- Map update/delete/redirect behavior is not assumed safe without supported policy semantics.
- Memory stores are only policy-neutral while the frozen policy has no memory predicates; constrained memory policy returns UNKNOWN.

### Soundness boundary
SAFE means every reachable abstract terminal path was interpreted with supported semantics and ended in a policy-allowed return.

VIOLATION means every reachable terminal path establishes violation, or a forbidden helper is proven unconditionally reachable.

Anything else is UNKNOWN.

### Regression tests
Added:

research/tests/test_phase5_abstract_soundness.py

The suite covers SAFE, VIOLATION, unresolved condition, unknown helper, forbidden helper, constrained memory store, unsupported instruction, analysis failure, and map-update conservatism.

### Status
IMPLEMENTATION FIXED — correctness-only execution still pending.

## P5-B02

### Old policy
Phase 5 policy hash:

8e349d091fd4c1af9127c8fe19ceb99ad0468ef8a565d5e47224993f051204b6

This policy added top-level helper restrictions and explicit return values that were not part of the E1 frozen policy.

### New/frozen policy
Phase 5 now reuses the E1 fixed policy unchanged:

270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603

Policy file:

research/experiments/corpus/phase5/policies/phase5_policy.json

### Semantic difference
The former Phase 5 policy added explicit forbidden-helper and return-value entries. The E1 policy does not contain those additional fields.

### Resolution
Resolution A — reuse E1 policy unchanged.

This restores the mandatory E1 control/reference relationship specified by the Phase 5 design.

### Policy hash
270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603

### Status
RESOLVED IN IMPLEMENTATION — reference results must be regenerated/revalidated under the frozen policy.

## P5-B03

### Checks added
validate-phase5-corpus.py now has a hard preflight for:

- KRAKENGUARD commit;
- compiler/version;
- compiler configuration;
- kernel;
- architecture;
- XDP hook;
- container image;
- immutable container image digest;
- policy SHA-256;
- environment manifest consistency.

### Failure behavior
Any mismatch raises a non-zero failure before corpus validation proceeds.

Missing/invalid container digest is a hard failure.

### Reference configuration
- KRAKENGUARD: e7bd84005b304c5a10efcdb04914d1882b3cccf7
- compiler: clang 22.1.8
- flags: -target bpf -mcpu=v1 -D__TARGET_ARCH_x86 -O2 -g -I/usr/include
- kernel: 7.2.3-arch1-2
- architecture: x86_64
- hook: XDP
- image: kg-artifact-krakenguard:latest
- policy: 270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603

### Status
IMPLEMENTED — blocked until the immutable container digest is captured on the validation host.

## P5-B04

### Metadata added
Phase 5 metadata now references:

research/experiments/corpus/phase5/phase5-environment.json

The manifest freezes compiler, compiler version, compiler flags, kernel, architecture, KRAKENGUARD commit, hook, container image tag, and policy hash.

### Environment manifest
The manifest currently records container_image_digest as null rather than fabricating a value.

### Image digest
NOT YET AVAILABLE IN THIS EXECUTION ENVIRONMENT.

The repository build provenance identifies kg-artifact-krakenguard:latest, but an immutable digest must be captured on the actual validation host.

### Status
BLOCKED — digest capture required before metadata can be considered fully frozen.

## Fallback validation

A dedicated correctness-only integration script was added:

research/experiments/scripts/validate-phase5-fallback.py

It is designed to demonstrate:

UNKNOWN compliant fixture
→ actual KRAKENGUARD invocation
→ COMPLIANT

UNKNOWN violating fixture
→ actual KRAKENGUARD invocation
→ POLICY VIOLATION

No performance matrix is involved.

Execution is pending the same reference-environment preflight.

## Correctness

No new correctness result is claimed by this correction report.

The previous 24/24 result belongs to the superseded Phase 5 policy/analyzer state and must not be reused as post-correction evidence.

Required post-correction evidence:

A: 6/6
B: 6/6
C: 6/6
D: 6/6

false SAFE: 0
false VIOLATION: 0
actual UNKNOWN fallback: demonstrated for compliant and violating fixtures

## Gate

The correction sprint does not self-approve the independent review.

independent_review_complete = false
execution_approved = false

## Final status

CORRECTIONS INCOMPLETE — BLOCKED BY CONTAINER DIGEST / CORRECTNESS REVALIDATION

The next concrete action is to capture the immutable KRAKENGUARD image digest on the actual validation host, freeze it in phase5-environment.json, then run correctness-only validation and the real UNKNOWN fallback pilot. After that, request a fresh independent review.

