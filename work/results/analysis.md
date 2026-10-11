# Comparative Verification Analysis

Generated only from work/results/runs.csv. Raw observations are not modified.

## Primary endpoint
- Median paired absolute saving: 258.3115 ms
- Median paired percentage saving: 45.30993293057918%
- Bootstrap 95% CI for median absolute saving: (-31.594999999999914, 549.855)
- Exact two-sided paired sign test: {'n': 24, 'positive': 12, 'negative': 12, 'p_two_sided': 1.0}

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
Oracle timing is a same-client sanity check for the symbolic critical section; it is not an independent verifier.
Memory peak fields are retained only for compatibility with older runs and are not treated as a primary endpoint.
The empirical path/time fits are descriptive for this corpus and are not asymptotic complexity proofs.
