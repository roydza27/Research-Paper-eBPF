# Phase 3 — KRAKENGUARD Smoke / Correctness Matrix

Date: 2026-09-25
Artifact commit: e7bd84005b304c5a10efcdb04914d1882b3cccf7
Object toolchain: frozen Clang 13
Mode: verification-only / conditional policy mode

## Applicability

- A: applicable
- B: unsupported at KRAKENGUARD lifting stage because of the atomic instruction path
- C: applicable
- D: applicable
- E: applicable

## P1
- A: NO VIOLATIONS, 1 path, 12695 instructions, request 9855ebe6-213d-4c30-a240-9ffc668aa8f4
- C: NO VIOLATIONS, 1 path, 13127 instructions, request 5bc93b88-144b-40c6-a97a-26bd5f464390
- D: NO VIOLATIONS, 1 path, 13277 instructions, request a6ccd9ae-c62d-45f3-b99e-5b1ac09fba70
- E: NO VIOLATIONS, 1 path, 12712 instructions, request fe9e16ff-431e-4141-8334-d17214aa16a7

## P2
- A: NO VIOLATIONS, request c702fc17-2e15-4a40-ae44-f4774bccbfda
- C: POLICY VIOLATION — Unauthorized map access to state, request eeb90984-514f-4408-8789-21cb57478627
- D: POLICY VIOLATION — Unauthorized map access to policy_state, request 497b2509-b6eb-4bf3-8d81-dbeab8ed4aaa
- E: NO VIOLATIONS, request 17a2c8f1-ab25-403c-b0d2-e0c8947057fc

## P2 helper-isolation diagnostic
- D with policy_state explicitly allowed: POLICY VIOLATION — Unauthorized helper bpf_ktime_get_ns, request 6eae4d7a-1197-4599-a24d-251edd181f87
- E with same helper allowlist and no map access: NO VIOLATIONS, request 9b64bad6-d34d-43f6-997b-43e42e9aa8b0

## P4
- A: NO VIOLATIONS, request bfbd94e9-5d35-4979-9ad3-6e55c399b18b
- C: POLICY VIOLATION — Unauthorized map access to state, request 8cd08f3e-e9f4-4303-b822-5cbebbf3206a
- D: POLICY VIOLATION — Write access to read-only map policy_state, request 611c7fc2-fedb-494c-b9c1-411ce89e6092
- E: NO VIOLATIONS, request 7241e948-5b43-491f-89c5-b970d48ee2ea

## Interpretation

- Top-level Passed=True is not sufficient as a conditional-policy correctness verdict.
- E demonstrates a missed unauthorized bpf_ktime_get_ns report under both P2 and P4.
- D demonstrates that the same forbidden helper can be detected when the map permission is explicitly satisfied.
- Empty map_access produced unauthorized-map violations for tested mapped programs; this behavior is retained as an observed implementation result.
- P3 is not benchmark-applicable because its target map counter belongs to unsupported program B.
- These observations are baseline findings; no Phase 4 implementation is justified by these results alone.
