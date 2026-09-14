# Phase 3A — KRAKENGUARD Reproduction & Evidence Gate

**Status:** host execution pending; artifact and experiment procedure frozen.

> This report intentionally does not claim successful reproduction or new benchmark measurements. Published KRAKENGUARD results are kept separate from our measurements.

## 1. Objective

Reproduce the strongest relevant baseline, KRAKENGUARD, and determine from measurements what actually limits its analysis cost before implementing any research contribution.

The current repository infrastructure already identified KRAKENGUARD as the primary direct baseline and deferred Phase 4 until a measurable limitation is reproduced.

## 2. Environment

The published KRAKENGUARD evaluation used an Azure B16als_v2 VM with 16 vCPUs, 32 GiB RAM and a 64 GiB NVMe SSD, running Ubuntu 24.04 LTS with kernel `6.17.0-1008-azure`.

Our research-host environment is **not yet frozen in this report** because this execution interface cannot run the user's Docker/kernel environment. The repository's existing collector must be run on the actual host and its JSON preserved with the results.

## 3. Baseline Version

Frozen target:

```text
repository: krakenguard-ebpf/krakenguard
commit: e7bd84005b304c5a10efcdb04914d1882b3cccf7
```

Artifact versions documented by the frozen source include LLVM 13, KLEE v3.0, klee-uclibc v1.3 and Z3 4.8.15.

## 4. Original Claims

KRAKENGUARD is a trusted user-space manager that enforces fine-grained policy constraints over eBPF bytecode. Its analysis lifts ELF eBPF objects to LLVM IR, generates an execution harness, and uses KLEE-based symbolic execution to check policy-relevant actions.

The published evaluation reports single-program and cross-program timing, memory and path counts. It also reports a concrete non-termination/scalability case involving `bmc_cache` and large SMT expressions generated from symbolic packet-hash branches.

The paper further reports that changing H/M/P policy constraints did not change runtime, explored paths or memory in its evaluation. That observation is significant because it means a policy-delta contribution cannot be assumed from policy syntax alone.

## 5. Reproduction Procedure

The frozen procedure is implemented in:

```text
research/experiments/scripts/reproduce-krakenguard.sh
```

The runner collects the host environment, clones the exact artifact commit with submodules, builds the documented Docker artifact, starts the verification-only daemon, runs a health check, runs `fw:test-object`, and then runs representative published workloads when `RUN_OFFICIAL=1`.

## 6. Deviations

The deviation table is maintained in:

```text
research/baselines/krakenguard/deviations.md
```

All host-specific rows remain pending until the actual research host is collected.

## 7. Build Results

**Pending.** No claim is made that the Docker build has succeeded from this execution interface.

The local container clone attempt from this environment could not resolve GitHub networking. This is an execution-environment limitation, not evidence that KRAKENGUARD fails to build.

## 8. Official Example Results

**Pending.** The first smoke target is `fw:test-object`.

## 9. Official Benchmark Results

**Pending.** Representative targets selected for the first pass are:

- `fw:test-object`
- `electrode:test-object-reply`
- `electrode:test-object-quorum`
- `katran:test-object`
- `cross_prog:test-object-fastreply`
- `cross_prog:test-object-quorum`

## 10. Custom Corpus Results

**Pending.** The Phase 3 controlled corpus exists, but it must only be mapped into KRAKENGUARD's actual accepted policy/input format after the native artifact smoke test succeeds.

## 11. Program Complexity Results

**Pending.** The experiment will vary branches, helpers, maps and control-flow complexity while keeping the policy as constant as practical.

## 12. Policy Complexity Results

**Pending.** This experiment remains necessary even though the published paper reports no observable runtime/path/memory change from H/M/P constraint toggling in its own evaluation. Our controlled corpus must confirm whether that observation generalizes to the policy vocabulary and workload used here.

## 13. Program × Policy Results

**Pending.** The existing Phase 3 matrix will be run only for policy features supported by the baseline. Unsupported combinations remain `UNSUPPORTED`, not failures.

## 14. Repeated Policy Change Results

**Pending.** This is the decisive experiment for the previous incremental-policy hypothesis. The same object will be analyzed under small policy deltas, and independent analysis cost will be measured. A cheap policy delta will count against the incremental-policy hypothesis.

## 15. Timeout Results

**Pending.** The experiment will preserve `TIMEOUT` separately from `UNSAFE`/`REJECT` and record the complexity characteristics of timeout cases.

## 16. Correctness Results

**Pending.** Expected safe/unsafe labels will be compared with KRAKENGUARD results. Disagreements will be investigated before any soundness claim is made.

## 17. Resource Consumption

**Published baseline only:** the paper reports most evaluated programs below 30 seconds and generally below 100 MiB, with `Electrode FAST_QUORUM_PRUNE` at 28.30 s / 218.184 MiB and cross-program `FAST_QUORUM_PRUNE` at 62.69 s / 256.363 MiB.

These values are reference points, not our measurements.

## 18. Failure Analysis

Any build or run failure must use the schema:

```text
System:
Version/commit:
Environment:
Expected:
Observed:
Failure:
Root cause:
Workaround:
Impact on reproduction:
```

The repository must distinguish environment/dependency failures from baseline algorithmic limitations.

## 19. Bottleneck Analysis

The authoritative paper already identifies one concrete scalability limitation: exhaustive symbolic execution can become impractical when symbolic values feed branches and create large SMT expressions. The paper explicitly discusses abstract interpretation plus symbolic execution as a possible future direction.

However, our research question still requires local reproduction. The key competing explanations are:

- program/control-flow complexity;
- solver/SMT cost;
- symbolic state/path explosion;
- program × policy interaction;
- repeated policy analysis;
- memory/resource pressure;
- or no meaningful bottleneck on our controlled workload.

## 20. Threats to Validity

1. The controlled corpus may not represent production eBPF.
2. Artifact telemetry may expose only some internal metrics.
3. Published and local hardware may differ.
4. Kernel compatibility is important because KRAKENGUARD models kernel-specific helper behavior.
5. Timing results are environment-sensitive.
6. Unsupported policy features cannot be treated as verifier failures.
7. A timeout is not automatically an unsafe result.
8. Published results and reproduced results must remain separate.

## 21. Research Implications

There is already authoritative evidence for a program-side symbolic-analysis limitation. There is **not yet local evidence** that small policy deltas cause expensive repeated analysis. Therefore the repository should not implement incremental verification merely because it was the Phase 2 surviving hypothesis.

A Phase 4 design should be chosen only after the local experiments distinguish these possibilities.

# Required Final Table

| Question | Evidence | Result |
|---|---|---|
| Can KRAKENGUARD be reproduced? | Host build/smoke run | **Pending** |
| Does program complexity affect cost? | Controlled program sweep | **Pending** |
| Does policy complexity affect cost? | Controlled policy sweep | **Pending** |
| Is there program × policy explosion? | Factorial matrix | **Pending** |
| Is solver cost significant? | Internal telemetry / timing correlation | **Pending** |
| Is state/path explosion significant? | Path/state telemetry and timeout cases | **Pending** |
| Are repeated policy changes expensive? | Delta-policy experiment | **Pending** |
| Are timeouts significant? | Complexity/timeout experiment | **Pending** |
| Is there a clear scalability bottleneck? | Combined measurements | **Pending** |
| Is incremental verification justified? | Delta-policy evidence | **Pending** |
| Is hybrid verification justified? | Bottleneck evidence + soundness rationale | **Pending** |

# Research Gate

## OPTION D — CONTINUE PHASE 3

> The current experiments are insufficient because the actual research host has not yet executed the frozen KRAKENGUARD artifact and therefore no local build, timing, memory, path, solver, timeout or correctness measurements exist.
>
> The next experiment required is to run `research/experiments/scripts/reproduce-krakenguard.sh` on the frozen host, preserve its environment/build/smoke/official-workload logs, then execute the Phase 3 controlled corpus and policy-delta experiments.

This is a successful Phase 3 result only in the methodological sense: the evidence gate prevents an unsupported Phase 4 implementation. It does **not** constitute a claim that the thesis direction is false.
