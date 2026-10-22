# Comparative Verification Analysis

Generated only from work/results/runs.csv. Raw observations are not modified.

## Primary endpoint
- Median paired absolute saving: 318.80449999999996 ms
- Median paired percentage saving: 46.15728150712778%
- Bootstrap 95% CI for median absolute saving: (-31.619000000000028, 670.7239999999999)
- Exact two-sided paired sign test: {'n': 24, 'positive': 12, 'negative': 12, 'p_two_sided': 1.0}
- Successfully paired programs: 24 / 24
- Failed measured runs: 0 ({'symbolic_only': 0, 'abstract_only': 0, 'hybrid': 0})
- Programs missing a symbolic/hybrid pair: []

## Correctness and Row Accounting
- Total measured rows: 504
- Checked definitive rows: 420
- All checked definitive rows agree: True
- Conservative abstentions: 84 (abstract_only mode conservative UNKNOWN verdicts on Groups B & D (fallback disabled by definition))
- False SAFE: 0
- False VIOLATION: 0
- Unreferenced or malformed rows: 0
- Accounting balanced: True (420 definitive + 84 abstentions + 0 failed = 504 total)

### Mode Breakdown
- `symbolic_only`: 168/168 definitive agree (100%), 0 abstentions, 0 errors
- `hybrid`: 168/168 definitive agree (100%), 0 abstentions, 0 errors
- `abstract_only`: 84/84 definitive agree (100%), 84 abstentions (UNKNOWN by design), 0 errors

## Fallback
- Measured hybrid rows: 168
- Fallback fraction: 0.5

## Interpretation
Positive saving means hybrid required less wall time than symbolic-only.
Reference verdicts are loaded from the frozen validation manifest; they are not timed benchmark runs.
Peak memory is not measured in this campaign; it requires a separate non-perturbative measurement design.
The empirical path/time fits are descriptive for this corpus and are not asymptotic complexity proofs.
