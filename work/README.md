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
- Kernel: recorded at run time (must remain constant across the campaign)
- Compiler: recorded at run time; compiled corpus objects are hashed and frozen
- Architecture: `x86_64`
- Hook: XDP
- Warmups: 2
- Measured repetitions: 7
- Timeout: 300 s
- Random seed: 42

## Timing boundary

The primary timing endpoint is intentionally narrow and symmetric:

- KRAKENGUARD symbolic section: client.verify(...) plus extraction of the authoritative verdict artifact.
- Abstract section: in-process AbstractPolicyAnalyzer(...).analyze().
- Hybrid: the abstract section plus the same timed KRAKENGUARD symbolic section only when the abstract result is UNKNOWN.

Raw evidence archival (response.json, verdict copies, logs) occurs after the timed verifier section. The previous benchmark also sampled docker stats every 50 ms while the verifier ran; that monitoring work is no longer part of the primary benchmark because it can perturb CPU scheduling and inflate wall time.

The repository still contains work/abstract_worker.py as an auxiliary isolated-process probe. Its subprocess launch/IPC cost is not the primary hybrid endpoint because the research architecture is conceptually an integrated analyzer rather than a per-program process spawn.

KRAKENGUARD is a persistent verifier service, so a per-invocation peak container memory value cannot be recovered cleanly without intrusive sampling or restarting the service. Memory peak fields from older raw runs are therefore not used as a primary result. Memory should be treated as a separate secondary campaign once a non-perturbative measurement method is established.

The 24-program oracle is run with the exact same symbolic timing helper used by symbolic_only. Its duration is recorded as a sanity check for timing symmetry, while its verdict is the reference verdict for correctness.

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

Reference verdicts are loaded from the previously audited Phase 5 validation manifest after verifying its program IDs, policy hash and KRAKENGUARD revision. No reference-verdict daemon calls are made before timed measurements, avoiding an avoidable cache/warm-state disturbance.

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

## Real-world workload evaluation

A separate real-world XDP workload study is under `work/real-world/`. It evaluates pinned public workloads such as Katran, hXDP firewall, Fluvia, CRAB, XDP SYNPROXY, xdp-filter and xdp-forward without modifying the validated Phase 5 evidence or the synthetic scaling runtime.

See [`work/real-world/README.md`](real-world/README.md) for the corpus, provenance, compatibility workflow, timing protocol and analysis commands.
