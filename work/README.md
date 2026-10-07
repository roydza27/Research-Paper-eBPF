# Comparative Verification Workbench

This directory is an isolated experimental work area for the research:

**Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification**

## Goal

Evaluate three execution modes on the same compiled eBPF corpus and frozen policy:

1. **symbolic_only** — every program is verified directly by the frozen KRAKENGUARD baseline.
2. **abstract_only** — every program is handled only by the repository's conservative abstract policy analyzer.
3. **hybrid** — abstract analysis runs first; SAFE/VIOLATION terminate locally, while UNKNOWN invokes KRAKENGUARD.

The primary comparison is **complete end-to-end wall time per program**. Peak memory, symbolic paths, symbolic queries, fallback rate, failures, and verdict agreement are secondary measurements.

## Important scope

This workbench is intentionally separate from `research/experiments/results/phase5-validation/`.

It must not overwrite, reinterpret, or repair existing Phase 5 evidence.

It does not assume that the hybrid architecture is superior. The result generator computes the comparison from measured observations and reports the evidence-supported conclusion.

## Default experimental controls

- Corpus: existing Phase 5 24-program corpus
- Policy: existing frozen Phase 5/E1 policy
- KRAKENGUARD commit: `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- Policy SHA-256: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`
- Container digest: `kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4`
- Kernel: `7.2.3-arch1-2`
- Compiler: Clang `22.1.8`
- Architecture: `x86_64`
- Hook: XDP
- Warmups: 2
- Measured repetitions: 7
- Timeout: 300 s
- Random seed: 42

## Run

From the repository root:

```bash
python3 work/run_comparison.py --mode all
python3 work/analyze_comparison.py
```

Results are written only under:

```text
work/results/
```

The benchmark refuses to run when the frozen controls cannot be verified.

## Evidence model

Every measured execution gets a unique run identifier and a machine-readable record.

KRAKENGUARD runs also preserve:

- request metadata
- response metadata
- conditional-policy verdict output
- KLEE info when available
- stdout/stderr when exposed by the client

Failures and timeouts are recorded rather than silently retried or converted into security verdicts.

## Analysis policy

The analysis script reports:

- paired per-program symbolic-only vs hybrid medians
- median savings
- confidence interval for the paired median difference using a bootstrap over program-level paired observations
- exact sign/permutation test over paired program differences
- fallback fraction
- correctness agreement
- false SAFE / false VIOLATION counts
- resource measurements when available
- path/query relationships
- conservative complexity-fit summaries

A performance claim is only reported over successfully measured observations under the verified controls.
