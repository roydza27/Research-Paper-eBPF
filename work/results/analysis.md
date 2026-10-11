# Comparative Verification Analysis

Generated only from work/results/runs.csv. Raw observations are not modified.

## Primary endpoint
- Median paired absolute saving: 258.3115 ms
- Median paired percentage saving: 45.30993293057918%
- Bootstrap 95% CI for median absolute saving: (-31.594999999999914, 549.855)
- Exact two-sided paired sign test: {'n': 24, 'positive': 12, 'negative': 12, 'p_two_sided': 1.0}
- Successfully paired programs: 24 / 24
- Failed measured runs: 0 ({'symbolic_only': 0, 'abstract_only': 0, 'hybrid': 0})
- Programs missing a symbolic/hybrid pair: []

## Correctness
- Checked measured rows: 420
- All checked rows agree: True
- False SAFE: 0
- False VIOLATION: 0

## Fallback
- Measured hybrid rows: 168
- Fallback fraction: 0.5

## Interpretation
Positive saving means hybrid required less wall time than symbolic-only.
Reference verdicts are loaded from the frozen validation manifest; they are not timed benchmark runs.
Peak memory is not measured in this campaign; it requires a separate non-perturbative measurement design.
The empirical path/time fits are descriptive for this corpus and are not asymptotic complexity proofs.
