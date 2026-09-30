# Phase 4 E1 — Program Complexity Scaling

## Status

**Blocked before the required P0/P7 KRAKENGUARD smoke-test gate.**

This report records the execution attempt exactly as performed in the available connected environment. No verifier measurements, timing values, memory values, symbolic-state counts, solver counts, compiled-object measurements, or security verdicts were fabricated.

The E1 corpus and fixed policy were inspected from the repository. The experiment could not proceed to the smoke tests because the required research-host execution environment is not available in this session.

## Objective

E1 asks:

> How does eBPF policy-verification cost change as program complexity increases while the security policy remains fixed?

The independent variable is program complexity. The policy, baseline, hook, compiler/toolchain, environment, warmups, measured repetitions, and timeout are intended to remain fixed.

## Research context

Research direction:

**Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification**

Core question:

> Can fine-grained eBPF isolation policies be checked with predictable cost by combining inexpensive abstract analysis with selective symbolic execution?

E1 is an evidence phase. It does not implement the proposed hybrid verifier.

## Baseline freeze

- Baseline: KRAKENGUARD
- Frozen commit: `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- Hook: XDP
- Policy: `research/experiments/corpus/e1/policies/e1_fixed_policy.json`
- Planned warmups: 2 per program
- Planned measured runs: 7 per program
- Timeout: 300 seconds
- Planned measured executions: 56
- Planned warmup executions: 16

## Corpus audit

The dedicated E1 corpus already exists and was not recreated or modified:

| Program | Intended increment |
| --- | --- |
| P0 | Minimal XDP |
| P1 | Arithmetic/data-flow |
| P2 | One conditional branch |
| P3 | Multiple branches |
| P4 | Helper interaction |
| P5 | Single map lookup |
| P6 | Map-dependent branching |
| P7 | Combined branches + helper + map state |

The committed `metadata.csv` contains expected estimates. Those estimates were **not promoted to measured compiled complexity** because the required BPF compilation step could not be completed in this environment.

## Fixed policy audit

The policy is unchanged and was inspected as committed.

It grants read access to `e1_map` and `e1_state`, and permits `bpf_map_lookup_elem` and `bpf_ktime_get_ns`.

Policy SHA-256: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`

The policy was not adapted to individual programs.

## Source integrity

The eight E1 source files were retrieved from the repository and hashed before any experimental work. Their SHA-256 values are stored in `e1-results.json`.

No source file was changed.

## Validation performed in this session

### JSON validation

The E1 fixed policy is valid JSON.

### Source syntax diagnostic

All eight source files passed a local C syntax-only diagnostic using Clang 17 with minimal stand-in declarations for the Linux BPF/libbpf interfaces.

This is **not** an E1 compilation result. It only establishes that the committed source text is syntactically parseable under the diagnostic declarations.

### Official BPF compilation

The prescribed compilation could not be performed.

The available Clang reports:

`unable to create target: 'No available targets are compatible with triple "bpf"'`

for the required `clang -target bpf ...`.

Therefore no E1 object files were produced in this session, and no object-derived instruction/basic-block/branch measurements are reported.

## Environment gate

| Capability | Observed |
| --- | --- |
| Research repo mounted at documented host path | No |
| Docker | unavailable |
| Docker Compose | unavailable |
| bpftool | unavailable |
| Clang | 17.0.0 Swift LLVM build |
| Clang BPF backend | unavailable |
| Python | 3.13.5 |
| Frozen KRAKENGUARD Docker artifact | not executable here |

The repository's own KRAKENGUARD reproduction notes state that this class of connected environment can inspect and prepare the reproduction but cannot execute Docker, kernel tooling, or the user's host environment.

## Required smoke-test gate

The experiment specification requires compiling and validating P0 and P7 first, then running both with the fixed policy. Only if both smoke tests are valid should the full matrix run.

Because KRAKENGUARD execution and official BPF compilation were unavailable, **P0 and P7 smoke tests were not run**.

The full matrix was therefore correctly **not launched**.

## Measurement status

No rows exist in `e1-results.csv`.

The machine-readable JSON records experiment status, baseline identity, fixed policy identity, corpus metadata hash, planned matrix, smoke-test status, source hashes, environment observations, and integrity rules. It contains no fabricated measurements.

## Aggregation status

The E1 protocol requires seven measured runs per program. Since zero programs passed the smoke-test gate, there are no valid timing samples from which to calculate mean, median, minimum, maximum, or standard deviation.

Reporting zeros would incorrectly convert missing measurements into measurements. The results therefore use explicit `not_run`, `blocked`, and empty-measurement states.

## Failure classification

**Primary classification:** environment / reproducibility issue.

Secondary observations:
- source syntax diagnostic: passed;
- official BPF compilation: unavailable because the installed Clang lacks a BPF target;
- KRAKENGUARD smoke execution: unavailable because Docker/Compose and the research host artifact environment are unavailable.

This is not a KRAKENGUARD rejection, policy rejection, timeout, or unsupported-program verdict.

## Required next execution on the research host

1. confirm the repository is at current `main` containing the E1 corpus;
2. switch to `phase4-e1-complexity-scaling`;
3. run the environment collector;
4. build all eight E1 objects using the established corpus compiler/toolchain;
5. measure compiled structural complexity;
6. run P0 + fixed policy;
7. run P7 + fixed policy;
8. proceed to 2 warmups + 7 measured runs for P0–P7 only if both smoke tests are valid;
9. preserve raw stdout/stderr/status/timing/environment evidence;
10. generate run-level and aggregated results from those raw records;
11. update this report with measured evidence without editing raw records;
12. push the branch and open the PR into `main`.

## Limitations

Even after execution, E1 will remain limited by eight synthetic programs, one XDP hook, one KRAKENGUARD baseline, one fixed policy, one host environment, compiler/toolchain effects, KRAKENGUARD-specific behavior, unsupported constructs, timing noise, and the distinction between instruction count and actual policy-verification complexity.

E1 must not be used to claim that the complete hybrid-verifier thesis is proven.

## Conclusion

The E1 experimental question is **not yet answered**.

The corpus and fixed policy are intact and reproducibly identified, but the required P0/P7 smoke-test gate could not be executed in the available environment. Consequently, there is currently no valid E1 evidence about how KRAKENGUARD verification cost scales with program complexity.

The correct next action is execution on the documented research host, not extrapolation from the committed metadata estimates.
