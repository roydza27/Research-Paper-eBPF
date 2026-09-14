# KRAKENGUARD Reproduction Notes

## Status

**Phase 3A execution is blocked on the actual research host.** The repository/connector can inspect and prepare the exact reproduction, but it cannot execute Docker, kernel tooling, or the user's host environment.

Therefore this file deliberately contains no fabricated build, runtime, memory or correctness results.

## Exact host procedure

From the research repository:

```bash
cd research/experiments/environment
chmod +x collect-environment.sh
./collect-environment.sh
```

Then from the repository root:

```bash
chmod +x research/experiments/scripts/reproduce-krakenguard.sh
RUN_OFFICIAL=1 ./research/experiments/scripts/reproduce-krakenguard.sh
```

The runner:

1. checks Git, Python and Docker Compose;
2. runs the existing environment collector;
3. clones KRAKENGUARD recursively if absent;
4. checks out commit `e7bd84005b304c5a10efcdb04914d1882b3cccf7` exactly;
5. records submodule state and clean/dirty status;
6. builds the documented Docker artifact;
7. starts the verification-only daemon;
8. performs a health check;
9. runs `fw:test-object` as the smallest smoke target;
10. runs representative official workloads when `RUN_OFFICIAL=1`;
11. preserves raw logs/status files under `research/experiments/results/krakenguard/`.

## Official workloads selected

- `fw:test-object`
- `electrode:test-object-reply`
- `electrode:test-object-quorum`
- `katran:test-object`
- `cross_prog:test-object-fastreply`
- `cross_prog:test-object-quorum`

These correspond to targets exposed by the frozen artifact. The cross-program targets are intentionally included because the published evaluation reports substantially higher path counts and runtime for the FAST_QUORUM_PRUNE pair.

## What must be captured after execution

For each target, preserve:

- build result;
- verification status;
- pass/fail result;
- execution duration reported by KRAKENGUARD;
- paths explored;
- instruction count;
- raw daemon output;
- wall-clock timing from the host runner;
- peak RSS where practical;
- timeout/error status;
- exact host and artifact versions.

The KRAKENGUARD client exposes paths, total instructions, duration and output files. If a requested metric is not exposed, record it as unavailable rather than estimating it.

## Important interpretation rule

The paper already establishes a published bottleneck involving exhaustive symbolic execution and large SMT expressions for a `bmc_cache` program. Our reproduction must test whether this behavior can be reproduced on the frozen host and controlled corpus; the paper's observation must not be relabeled as our measurement.

Likewise, the paper reports that changing H/M/P policy constraints did not change execution time, explored paths or memory in its evaluation. Therefore an incremental-policy thesis cannot be justified merely from the existence of KRAKENGUARD policies. It requires evidence that small policy deltas cause substantial repeated work in our experiment.
