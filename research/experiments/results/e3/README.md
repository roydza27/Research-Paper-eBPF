# Phase 5 — Experiment E3: Selective Abstract Discharge

## Research Question
How many programs can the abstract policy analyzer conclusively classify without symbolic execution?

## Primary Endpoint
`abstract_discharge_rate = (SAFE + VIOLATION) / total`

- **Total Programs:** 24
- **Discharged Programs:** 12
- **Discharge Rate:** 50.0%
- **Wilson Score 95% Confidence Interval:** [31.4%, 68.6%]
- **Correctness Agreement:** 100% (24/24 programs agree with KRAKENGUARD authoritative reference)
- **False SAFEs:** 0
- **False VIOLATIONs:** 0

## Category Breakdown
| Category | Role | Count | Discharged | Discharge Rate | Verdicts | Correctness |
|---|---|---:|---:|---:|---|---|
| A | Provable Compliant | 6 | 6 | 100.0% | SAFE | PASS (6/6) |
| B | Uncertain Compliant | 6 | 0 | 0.0% | UNKNOWN | PASS (6/6 fallback) |
| C | Provable Violation | 6 | 6 | 100.0% | VIOLATION | PASS (6/6) |
| D | Symbolic Violation | 6 | 0 | 0.0% | UNKNOWN | PASS (6/6 fallback) |

## Provenance
- **KRAKENGUARD Commit:** `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- **Policy SHA-256:** `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`
- **Compiler:** clang 22.1.8
- **Kernel / Arch:** 7.2.3-arch1-2 (x86_64)
- **Total Executions:** 216 (2 warmups + 7 measured repetitions across 24 programs)
