# Phase 4 E1 — Independent Evidence Audit

**Audit date:** 2026-09-30  
**Baseline commit:** `e7bd84005b304c5a10efcdb04914d1882b3cccf7`  
**E1 execution commit audited:** `45f64f1693a4eee20759109d3904e13b267d554a`  
**Research question:** How does eBPF policy-verification cost change as program complexity increases while the security policy remains fixed?

## Audit Status

**PASS WITH QUALIFICATIONS**

The committed E1 dataset is internally complete and its seven-run wall-time aggregates reproduce exactly from the CSV. The raw execution evidence supports the reported success/compliance outcomes for sampled runs and supports the reported object instruction/control-flow/helper/map characteristics.

However, several claims require qualification before E1 is used in the paper:

1. P2's source-level conditional branch was optimized away by Clang 22.1.8 at the selected `-O2 -mcpu=v1` configuration. Its compiled object contains 4 instructions and **0 branches**, not the intended one-branch structure.
2. The runner computes `verifier_states` from KLEE's `explored paths` statistic. It should not be interpreted as a generic verifier-state count.
3. `basic_blocks` is produced by the heuristic `1 + branch_count`, not a CFG-derived basic-block analysis.
4. `maps` is inferred from the program slug rather than detected from the object. The committed readelf/BTF artifacts independently confirm the map for P5/P7, but the runner metric itself is heuristic.
5. `cpu_time_us` is Python `time.process_time()` around the host-side client call. It is CPU time for the runner/client process, not total CPU consumed by the KRAKENGUARD daemon/container/KLEE.
6. `peak_memory_bytes` and `solver_time_us` were not measured.
7. Solver-query and path counts are extracted from KLEE's generated `output/info` file, which was consumed by the runner but is not preserved as a committed raw artifact. The committed stderr supports KLEE total instructions and completed paths, but not the query count directly.
8. The compiled object binaries themselves are not committed. The disassembly/readelf/BTF inspection artifacts are committed, so structural claims can be inspected, but the recorded object SHA-256 values cannot be independently recomputed from a committed binary.
9. The README's "~95%+" fixed-pipeline-overhead claim is **not a measured component-level decomposition**. No separate timings for lifting, LLVM optimization, harness generation/compilation, linking, or KLEE startup were collected.
10. The Clang `-mcpu=v1` choice is a documented compatibility adaptation, but the repository does not preserve a controlled failed `v3/v4` comparison, so its necessity and material effect cannot be independently quantified from E1 alone.

## Dataset Integrity

Expected: 8 programs, 2 warmups/program, 7 measured runs/program.

Observed:

- 72 total rows
- 16 warmups
- 56 measured runs
- P0–P7 all present
- every program has exactly 2 warmups and 7 measured runs
- all run IDs are unique
- all execution statuses are `success`
- all successful rows have exit code 0
- one policy SHA-256 across all rows: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`
- one KRAKENGUARD commit across all rows: `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- one compiler/version: Clang 22.1.8
- one kernel version: 7.2.3-arch1-2

**DATASET_INTEGRITY = PASS**

The JSON contains 56 measured records and 8 aggregate records. Recalculation from the CSV produced no mismatches against the JSON aggregates.

## Raw-Evidence Cross-Check

### P0 measured

The sampled P0 measured metadata reports 681,817 us wall time, success/VERIFIED/COMPLIANT, one explored KLEE path, zero queries, 12,695 KLEE instructions and exit code 0. Its stdout contains the complete KRAKENGUARD pipeline and the conditional-policy compliance result; stderr contains the corresponding KLEE completion statistics.

### P0 warmup

The sampled P0 warmup has the same object/policy/baseline identity and the same KLEE path/instruction profile. This confirms the warmup is represented separately from measured runs rather than being folded into the seven-run sample.

### P3 measured

The sampled P3 run reports 18 instructions, 4 basic blocks, 3 branches, one explored KLEE path and zero queries. The committed disassembly independently shows three conditional jump instructions.

### P4 outlier

P4 measured repetition 5 reports 935,658 us wall time, 584 us client-process CPU time, one KLEE path, one query and 12,712 KLEE instructions.

The raw stdout for the same run reports internal pipeline elapsed time of 558 ms. Neighboring P4 repetitions report internal elapsed times of approximately 383 ms and 398 ms, while their wall times are approximately 679 ms and 694 ms.

Therefore the outlier is a genuine execution-time spike in the observed verifier pipeline, not merely a CSV aggregation error. The raw evidence does not establish whether its cause was host scheduling/I/O, a pipeline-stage delay, or another runtime event.

**P4 outlier cause = undetermined.**

The outlier must remain in all analyses.

### P7 measured and warmup

Both sampled P7 records report the same 20-instruction/5-BB/4-branch/2-helper/1-map object, two explored KLEE paths and three queries. Raw stdout shows the `e1_state` relocation/map handling, `bpf_map_lookup_elem` and `bpf_ktime_get_ns` transformations, two policy test cases, and KLEE completion of two paths.

## Compiled Complexity Audit

The committed object disassemblies support these instruction/branch/helper counts:

| Program | Instructions | Basic Blocks* | Branches | Helpers | Maps |
| --- | ---: | ---: | ---: | ---: | ---: |
| P0 | 2 | 1 | 0 | 0 | 0 |
| P1 | 5 | 2 | 1 | 0 | 0 |
| P2 | 4 | 1 | **0** | 0 | 0 |
| P3 | 18 | 4 | 3 | 0 | 0 |
| P4 | 6 | 2 | 1 | 1 | 0 |
| P5 | 11 | 2 | 1 | 1 | 1 |
| P6 | 17 | 4 | 3 | 1 | 1 |
| P7 | 20 | 5 | 4 | 2 | 1 |

*The runner's BB values are based on `1 + branch_count`, so these should be described as runner-derived structural estimates rather than a general CFG analysis.

### Critical P2 finding

The source contains:

`if (x & 1) return XDP_PASS; return XDP_DROP;`

but the compiled P2 object is:

- load ingress_ifindex
- mask with 1
- increment by 1
- exit

There is no conditional jump. The compiler transformed the source-level branch into branchless arithmetic.

**Consequences:**

- P2 cannot be described as a compiled one-branch benchmark.
- The source ladder is not a strictly monotonic branch-complexity ladder.
- The timing result for P2 remains valid for the compiled object that was actually executed, but it does not isolate a one-branch feature.
- E1 should therefore be interpreted as a small **compiled-feature corpus**, not as proof of a clean source-level complexity ladder.

P1 also contains a source-level conditional expression and compiles to one branch, confirming that compiler lowering materially affects the feature ladder.

## Statistical Verification

Recomputed from the seven measured wall-time values per program using sample standard deviation:

| Program | Mean ms | Median ms | Min ms | Max ms | StDev ms | CV |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| P0 | 680.773 | 681.817 | 665.293 | 690.269 | 9.386 | 0.0138 |
| P1 | 680.624 | 679.871 | 671.959 | 695.706 | 7.391 | 0.0109 |
| P2 | 675.277 | 677.554 | 657.391 | 686.327 | 9.052 | 0.0134 |
| P3 | 673.520 | 672.432 | 665.117 | 683.669 | 7.150 | 0.0106 |
| P4 | 721.258 | 688.569 | 670.805 | 935.658 | 94.984 | 0.1317 |
| P5 | 688.619 | 692.902 | 675.139 | 696.976 | 8.744 | 0.0127 |
| P6 | 686.087 | 686.699 | 675.008 | 694.633 | 7.981 | 0.0116 |
| P7 | 705.687 | 707.609 | 695.130 | 708.549 | 4.767 | 0.0068 |

The JSON aggregates exactly match the independent CSV calculation.

For P0–P3:

- P0 median = 681.817 ms
- P3 median = 672.432 ms
- median range = 9.385 ms
- P3 is 1.376% below P0's median

For P0 → P7:

- P0 median = 681.817 ms
- P7 median = 707.609 ms
- difference = **+3.783%**

These numbers support the statement that end-to-end wall time changed only modestly across this small corpus. They do **not** by themselves establish why.

## Toolchain Deviation

E1 used Clang 22.1.8 with:

`-target bpf -mcpu=v1 -D__TARGET_ARCH_x86 -O2 -g`

KRAKENGUARD's frozen artifact uses LLVM 13 internally for lifting/optimization and clang-13 for generated verification harnesses.

The `-mcpu=v1` setting should be classified as a **controlled compatibility adaptation**, not as a failed experiment condition. It fixes the exact host compiler configuration used to generate objects that the frozen LLVM-13 lifter can process.

However, E1 does not contain a preserved A/B experiment comparing `-mcpu=v1` against `v3/v4`. Therefore:

- the result is specifically for **Clang 22.1.8 + BPF + mcpu=v1 + O2 + debug**;
- it should not be generalized to "Clang 22" without the configuration;
- the magnitude of the code-generation difference from other CPU targets was not measured in E1.

## AF_UNIX Socket Workaround

The runner derives a relative socket path to avoid the Linux AF_UNIX path-length limit rather than modifying the frozen KRAKENGUARD repository.

The KRAKENGUARD client ultimately performs a normal AF_UNIX stream connection to the supplied socket path. The workaround changes path resolution only; it does not alter the verification request, policy, object, daemon code, lifting, KLEE configuration or policy semantics.

There was no A/B timing experiment isolating absolute-vs-relative socket resolution. Therefore the audit can classify the workaround as **semantically neutral by inspection**, but should not claim that its performance effect was experimentally measured.

## CPU-Time Semantics

The runner records:

`time.process_time()`

around the host-side Python client call.

This is not total CPU time for the verification computation. It measures CPU consumption of the runner process itself and does not aggregate CPU used by the separate KRAKENGUARD daemon/container/KLEE processes.

Therefore `cpu_time_us` must not be presented as "total verifier CPU time."

The very large wall-time/client-CPU gap is expected under this measurement design and is not evidence that the verifier itself used only hundreds of microseconds of CPU.

## Memory and Solver-Time Gaps

Peak memory is explicitly `NOT_REPORTED`. E1 therefore provides no defensible memory-scaling result.

Solver time is explicitly `NOT_REPORTED`. Solver query counts are available, but they are not equivalent to solver time.

The runner extracts query counts from KLEE's generated `output/info` file. That file is not committed as raw evidence, so the query-count extraction is reproducible from the runner implementation but not independently auditable from the committed stdout/stderr alone.

## Verifier-State Semantics

The CSV field `verifier_states` is populated from KLEE's `explored paths` value.

Therefore the scientifically correct terminology is:

**KLEE explored/completed symbolic paths**

rather than generic "verifier states."

The current evidence does not justify "state explosion" language. E1 observes:

- P0–P6: 1 explored path
- P7: 2 explored paths

That is a small path-count increase, not state explosion.

## Fixed-Pipeline Overhead Claim

The current README claims approximately 95%+ fixed pipeline overhead.

That percentage is not directly measured.

The raw stdout does expose pipeline steps and an internal elapsed value, but E1 does not separately instrument:

- lifting duration;
- LLVM optimization duration;
- harness generation duration;
- harness compilation duration;
- llvm-link duration;
- KLEE startup duration;
- symbolic execution duration.

Therefore the defensible claim is:

> Across the small E1 corpus, end-to-end wall time changed only modestly despite changes in compiled instruction count and enabled features. This is consistent with substantial fixed pipeline cost, but E1 does not directly decompose the wall time into component-level percentages.

The "~95%+" figure should not appear as a measured result unless a component-level timing experiment is performed.

## What E1 Establishes

With the above qualifications, E1 reliably establishes a scoped empirical baseline:

1. On one host, one frozen KRAKENGUARD revision, one XDP hook and one fixed policy, the eight small compiled programs completed verification successfully.
2. For P0–P3, increasing compiled instruction count from 2 to 18 did not produce a corresponding increase in end-to-end wall time; the P0-to-P3 median difference was only -1.376%.
3. Helper/map features changed symbolic-analysis behavior: P4 produced one KLEE query, while P7 produced three queries and two explored paths.
4. P7's median wall time was only 3.783% above P0's median, despite P7 having 20 instructions, 4 branches, 2 helpers and 1 map.
5. Therefore, within this micro-corpus, raw instruction count alone is not a useful predictor of end-to-end verification cost.
6. The experiment provides a baseline for identifying which program-side features activate additional symbolic work.

## What E1 Does Not Establish

E1 does not establish:

- that verification scales predictably for production-scale eBPF programs;
- that wall time remains flat beyond 20 compiled instructions;
- that branch/path complexity remains cheap once path counts grow substantially;
- that policy complexity is the dominant or limiting factor;
- that the proposed hybrid verifier works;
- that abstract analysis plus selective symbolic execution improves performance;
- a general CPU-cost model;
- a memory-scaling relationship;
- solver-time scaling;
- behavior across multiple hosts/kernels/toolchains;
- behavior for loops;
- behavior for large or interacting map state;
- behavior for large path counts;
- a clean monotonic source-level complexity ladder, because P2's branch disappeared during compilation.

## Scientific Contribution

E1 should be treated as a **baseline/feature-sensitivity experiment**.

Its strongest contribution is not "fixed overhead is 95%" and not "complexity is solved."

Its strongest contribution is that, under the frozen baseline and fixed policy, this micro-corpus shows a separation between:

- **instruction-count growth**, which produced little wall-time movement at this scale; and
- **symbolic-feature activation**, where helper/map combinations changed KLEE paths and solver-query counts.

That distinction gives the next experiment a concrete target: deliberately increase symbolic branching while controlling instruction growth.

## Recommended Next Experiment

### E2 — Controlled Symbolic Branching / Path Scaling

**Research question**

> With the security policy and verifier pipeline fixed, how does verification cost change as the number of feasible symbolic control-flow paths increases?

**Why E2 follows from E1**

E1's largest unresolved empirical gap is not another micro-program with a few more instructions. P0–P7 never produced substantial path growth: the maximum observed path count was 2. The experiment therefore cannot determine whether KRAKENGUARD's end-to-end flatness persists when symbolic branching becomes genuinely large.

**Independent variable**

Controlled feasible path count / branch structure.

**Controlled variables**

- KRAKENGUARD commit
- fixed E1 policy
- XDP hook
- host/kernel
- compiler/toolchain
- optimization configuration
- timeout
- warmup/repetition protocol

**Measurements**

- compiled instructions
- CFG-derived basic blocks
- branch count
- KLEE explored paths
- KLEE total instructions
- solver queries
- solver time, if instrumentation can provide it
- end-to-end wall time
- daemon-reported duration
- process/container CPU and peak RSS, if added without changing verifier semantics

**Design requirement**

The branch family must prevent compiler optimization from collapsing intended branches, as happened with P2. Complexity must be verified from the compiled object before execution.

E2 should not be implemented until its corpus and measurement protocol are reviewed.

## Git / Artifact Handling

This audit is intentionally additive. It does not modify E1 historical measurements, the E1 corpus, Phase 3 evidence, or the already-merged PR #11.

Proposed artifacts:

- `research/experiments/results/e1/audit.md`
- `research/experiments/results/e1/audit.json`

Branch:

`phase4-e1-evidence-audit`
