# KRAKENGUARD Helper-Policy Gate — 2026-09-25

## Frozen baseline
- Artifact commit: e7bd84005b304c5a10efcdb04914d1882b3cccf7
- Corpus objects: frozen Clang 13 build
- Mode: verification-only / conditional policy mode

## Evidence

### D — explicit map permission + helper allowlist
- Request: 6eae4d7a-1197-4599-a24d-251edd181f87
- Program: d_policy_sensitive.o
- Policy: d-helper-only-map-allowed.json
- Top-level status: success
- Top-level Passed: True
- Paths explored: 1
- Total instructions: 13277
- Conditional result: POLICY VIOLATIONS DETECTED
- Conditional violation: Unauthorized helper bpf_ktime_get_ns
- Legacy helperFunc.results: No use of restricted function detected

### E — helper-only allowlist
- Request: 9b64bad6-d34d-43f6-997b-43e42e9aa8b0
- Program: e_adversarial_helper.o
- Policy: d-helper-only-map-allowed.json
- Top-level status: success
- Top-level Passed: True
- Paths explored: 1
- Total instructions: 12712
- Conditional result: NO VIOLATIONS
- Actual program helper: bpf_ktime_get_ns
- Legacy helperFunc.results: No use of restricted function detected

## Interpretation
- The frozen conditional-policy engine detected unauthorized bpf_ktime_get_ns in D but not E under the tested helper allowlist.
- Therefore helper-policy enforcement is program-dependent in this corpus; E is a clean reproduction of a missed unauthorized-helper report because E performs no map access.
- Top-level Passed=True must not be used as the sole policy-correctness verdict.
- Raw request artifacts remain authoritative; this file is a derived evidence index only.
