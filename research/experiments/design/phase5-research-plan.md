
# Phase 5 — Experimental Research Plan

**Status:** DESIGN COMPLETE — EXECUTION NOT APPROVED  
**Branch:** phase5-experimental-design

## 1. Phase 4 evidence synthesis

### E1 established

E1 is a 72-execution controlled XDP micro-corpus: 16 warmups and 56 measured runs across P0–P7. All measured executions completed successfully under the fixed E1 policy and frozen KRAKENGUARD revision e7bd84005b304c5a10efcdb04914d1882b3cccf7.

Independent recomputation from e1-results.csv reproduces the published means, medians, minima, maxima and sample standard deviations.

P0–P3 stayed in a one-path regime despite increasing compiled structure. Helper/map features introduced additional symbolic work in later programs. E1 therefore establishes that raw instruction count alone does not explain end-to-end verification time in this small corpus.

E1 does not establish production-scale scalability, solver-memory scaling, or that symbolic path count is the causal bottleneck.

### E2 established

E2 was executed on the audited branch phase4-e2-full-matrix. The complete result artifacts are currently on that branch rather than main.

The matrix contains:

- 7 path levels
- 2 warmups per level
- 7 measured repetitions per level
- 63 total executions
- 49 measured observations
- 0 timeouts
- 0 failures

Observed KLEE path ladder:

~~~text
1 → 2 → 4 → 8 → 16 → 32 → 64
~~~

Independent recomputation of the CSV reproduces:

| Paths | Median ms | Mean ms |
|---:|---:|---:|
| 1 | 746.14 | 757.28 |
| 2 | 749.93 | 752.64 |
| 4 | 762.77 | 770.22 |
| 8 | 789.88 | 789.19 |
| 16 | 853.02 | 854.79 |
| 32 | 973.44 | 972.45 |
| 64 | 1231.16 | 1266.86 |

The E2 audit also reports one Z3 query per explored feasible path for this controlled family.

### What E2 resolved

E1 remained largely in a 1–2-path regime, so it could not isolate path-dependent symbolic cost from fixed translation/lifting/harness overhead.

E2 controlled feasible path growth while holding policy, verifier revision, XDP hook, compiler and host constant. It therefore provides evidence that increasing feasible symbolic paths can increase end-to-end verification cost within the tested family.

### Remaining uncertainty

Phase 4 does not establish:

- universal/asymptotic complexity for arbitrary eBPF;
- peak-memory scaling;
- solver-time scaling;
- behavior beyond 64 paths;
- production-scale behavior;
- correctness of the proposed hybrid verifier;
- abstract-stage discharge coverage;
- hybrid end-to-end performance.

### Combined evidence

~~~text
E1: small feature/size changes
        ↓
mostly stable end-to-end cost
        ↓
path growth insufficiently exercised

E2: controlled feasible path growth
        ↓
measurable verification-cost increase
        ↓
symbolic work becomes increasingly relevant
~~~

This motivates testing selective abstract discharge. It does not prove that hybrid verification is faster.

All Phase 5 claims must remain bounded by: within the tested synthetic XDP program family, within the tested path range, under the fixed KRAKENGUARD configuration.

## 2. Phase 5 research question

> Can inexpensive abstract policy analysis discharge policy-safe eBPF programs before symbolic execution, while selectively forwarding unresolved programs to symbolic verification?

This separates:

1. whether the abstract stage can soundly classify a useful subset;
2. whether avoiding symbolic verification reduces complete end-to-end verification cost.

No performance improvement is assumed.

## 3. Hypotheses

### H5-C — Correctness

For programs classified SAFE or VIOLATION by the abstract stage, the hybrid final verdict agrees with the authoritative reference verdict.

### H5-COV — Selective discharge

A measurable subset of the validation corpus is conclusively discharged without symbolic fallback.

### H5-P — End-to-end cost

Hybrid verification may reduce complete end-to-end cost when abstract-analysis cost plus fallback cost is lower than universal symbolic-only cost.

### H5-S — Fallback scaling

As symbolic path complexity increases, unresolved programs may incur increasing fallback cost. The experiment measures this rather than assuming it.

## 4. Baselines

### Baseline A — Symbolic-only

Every program goes directly through frozen KRAKENGUARD.

~~~text
T_symbolic = complete KRAKENGUARD end-to-end wall time
~~~

### Candidate B — Hybrid

Every program first goes through the abstract policy analyzer:

~~~text
SAFE       → terminate
VIOLATION  → terminate
UNKNOWN    → KRAKENGUARD fallback
~~~

Complete cost:

~~~text
SAFE/VIOLATION:
T_hybrid = T_abstract

UNKNOWN:
T_hybrid = T_abstract + T_symbolic_fallback
~~~

The comparison is always between complete pipelines. Abstract-only time must never be compared against full symbolic-only time.

## 5. Abstract policy-analysis mechanism

This specifies the experimental analyzer; it does not authorize implementation during this design task.

### Input

Compiled eBPF ELF object plus frozen policy. Analyze the compiled CFG, not source-level C.

### Abstract state

Track:

- reachability;
- integer intervals and selected known-bit facts;
- policy-condition facts: true / false / unknown;
- helper-access summary;
- map-access summary and access mode;
- memory read/write ranges;
- possible return values;
- analysis status.

### Transfer functions

Initial support must cover the corpus:

- ALU operations;
- conditional jumps;
- loads/stores;
- helper calls;
- map lookup/update/delete;
- XDP returns;
- CFG joins.

Unsupported instructions or policy predicates conservatively produce UNKNOWN.

### Join

Join states conservatively at CFG merges. Precision may be lost; soundness may not.

### Decision rules

SAFE only when every reachable abstract state is proven compliant.

VIOLATION only when a policy-forbidden action is proven reachable.

UNKNOWN when compliance or violation cannot be proved.

A syntactic forbidden operation is not enough to declare VIOLATION if reachability is unproved.

### Soundness requirement

The abstract stage must never return SAFE for a program whose authoritative reference verdict is a policy violation.

A false UNKNOWN is acceptable for this research question. A false SAFE or false VIOLATION is a correctness defect.

## 6. Policy design

### Reference policy

Keep the E1 fixed policy as a mandatory control/reference:

- e1_map: Read
- e1_state: Read
- bpf_map_lookup_elem
- bpf_ktime_get_ns

Policy SHA-256:

~~~text
270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603
~~~

### Conditional policy family

For path-sensitive cases, use the existing KRAKENGUARD MEM_CONDITION + ACTION policy mechanism demonstrated by the frozen baseline examples.

The exact policy files must be frozen and hashed before corpus execution.

No new policy dimension may be introduced unless its semantics are demonstrated against the frozen KRAKENGUARD policy engine.

## 7. Validation corpus

Initial corpus: 24 programs, six per category.

Each category contains 3 low-path and 3 higher-path programs.

Target strata:

~~~text
low:   1–4 feasible paths
high:  8–64 feasible paths
~~~

Actual KLEE path counts become authoritative after execution.

### Category A — Abstractly provable compliant

Six programs where the abstract stage should prove compliance.

Examples: allowed helper, allowed map read, bounded allowed memory access, simple policy predicates.

Reference verdict: COMPLIANT. Expected hybrid classification: SAFE.

### Category B — Abstractly uncertain but symbolically compliant

Six compliant programs requiring information outside the initial abstract domain.

Examples: packet-content-dependent policy conditions, relational packet predicates, symbolic conditions controlling allowed actions, path correlations lost at joins.

Reference verdict: COMPLIANT. Expected hybrid path: UNKNOWN → symbolic fallback → COMPLIANT.

### Category C — Abstractly provable violation

Six programs where the abstract stage can directly establish a policy violation.

Examples: unconditional forbidden helper, forbidden map update, out-of-policy memory write, forbidden return action.

Reference verdict: VIOLATION/REJECTED. Expected hybrid path: VIOLATION without symbolic fallback.

### Category D — Symbolically discovered violation

Six programs where the violation depends on path-sensitive information outside the initial abstract domain.

Examples: forbidden action reachable only under a symbolic packet predicate, policy-conditioned memory violation requiring path correlation, branch-dependent forbidden helper/map action.

Reference verdict: VIOLATION/REJECTED. Expected hybrid path: UNKNOWN → symbolic fallback → VIOLATION.

Category labels and expected outcomes are frozen before performance measurement.

## 8. Complexity and path control

Reuse E2's validated path-generation discipline where practical.

Record for every program:

- source SHA-256;
- object SHA-256;
- instruction count;
- CFG basic blocks;
- conditional jumps;
- loops;
- helpers;
- maps;
- observed KLEE paths;
- observed KLEE queries.

Program size, feasible paths, policy complexity and abstract-analysis difficulty remain separate dimensions.

## 9. E3 — Selective Discharge

### Question

What fraction of the validation corpus can the abstract stage conclusively classify without symbolic execution?

### Sample

24 program/policy pairs: 6 A, 6 B, 6 C, 6 D.

### Primary endpoint

~~~text
abstract_discharge_rate =
(SAFE + VIOLATION) / total programs
~~~

Report overall and per category.

### Secondary endpoints

- SAFE / VIOLATION / UNKNOWN counts;
- category discharge rate;
- correctness agreement;
- abstract wall time;
- CFG nodes;
- abstract states;
- rules triggered;
- UNKNOWN reason.

Acceptance requires zero incorrect SAFE results, zero incorrect VIOLATION results, and measurable discharge coverage. No arbitrary minimum discharge percentage is assumed beforehand.

## 10. E4 — End-to-end cost

### Question

Does hybrid verification reduce complete end-to-end verification cost relative to symbolic-only verification?

### Unit and conditions

Each of the 24 programs is evaluated under symbolic-only and hybrid.

### Repetitions

2 warmups + 7 measured repetitions per condition.

Total:

~~~text
24 × 2 × 9 = 432 executions
~~~

### Primary endpoint

Per-program median end-to-end wall time.

Report:

~~~text
Delta   = median(T_hybrid) - median(T_symbolic)
Ratio   = median(T_hybrid) / median(T_symbolic)
Savings = 1 - Ratio
~~~

### Statistical comparison

Use paired program-level comparisons.

Primary: paired differences in per-program medians with a 95% confidence interval.

Secondary if assumptions are unsuitable: paired permutation/randomization test or Wilcoxon signed-rank test.

Do not use significance language unless the selected test is actually performed.

Always report practical effect size and uncertainty.

## 11. E5 — Fallback scaling

### Question

As symbolic path complexity increases, how does selective abstract discharge affect the amount and cost of symbolic fallback?

Use validated path strata 1, 2, 4, 8, 16, 32 and 64 where reachable.

For each stratum retain representative:

- abstractly discharged compliant;
- unresolved compliant;
- abstractly discharged violation;
- unresolved violation.

### Primary endpoints

- fallback fraction by path level;
- median symbolic fallback time by path level;
- median hybrid end-to-end time by path level;
- KLEE paths and queries for fallback cases.

Do not claim the abstract stage makes symbolic execution intrinsically faster. Measure whether it invokes symbolic verification less often and therefore performs less total symbolic work.

## 12. Experimental matrix

| Experiment | Programs | Conditions | Warmups | Measured | Total |
|---|---:|---|---:|---:|---:|
| E3 | 24 | Abstract | 2 | 7 | 216 |
| E4 | 24 | Symbolic + Hybrid | 2 each | 7 each | 432 |
| E5 | validated subset | Symbolic + Hybrid | 2 each | 7 each | TBD |

E3 measurements may be reused for E4 only if execution context and telemetry are identical and shared run IDs are preserved. Otherwise keep them separate.

E5 opens only after actual path strata are validated.

## 13. Execution order and randomization

Within each measured block:

1. compile all programs;
2. freeze object hashes;
3. run warmups;
4. interleave symbolic-only and hybrid conditions;
5. randomize condition order per program using a recorded deterministic seed;
6. preserve absolute execution order.

Do not run all symbolic-only executions first and all hybrid executions afterward.

## 14. Environment controls

Hold fixed:

- KRAKENGUARD revision e7bd84005b304c5a10efcdb04914d1882b3cccf7;
- policy hash;
- Linux 7.2.3-arch1-2;
- x86_64;
- Clang 22.1.8;
- -target bpf -mcpu=v1 -D__TARGET_ARCH_x86;
- -O2 -g;
- XDP hook;
- KRAKENGUARD image/tag/digest;
- host CPU and memory;
- daemon configuration;
- timeout;
- analyzer configuration.

Changing abstract-domain precision is a separate independent variable and must not be mixed into the primary E4 comparison.

## 15. Timeout policy

Initial timeout: 300 seconds per verification execution.

Timeout is distinct from rejection and UNKNOWN and is never silently rerun.

If abstract analysis times out, classify that stage as timeout according to the predeclared pipeline rule; do not invent fallback behavior after observing the result.

## 16. Failure handling

Allowed statuses:

- accepted;
- rejected;
- unknown;
- timeout;
- unsupported;
- error.

A hybrid/reference disagreement is retained as a correctness failure and investigated.

A documented environment failure may be repeated once under a new run ID; the original failure remains in raw evidence.

Do not repeat statistical outliers.

## 17. Raw telemetry

Every run preserves:

- experiment/program/condition/run ID;
- deterministic execution order;
- source/object/policy hashes;
- baseline commit;
- kernel/architecture/compiler/flags;
- KRAKENGUARD image/tag/digest;
- host CPU/memory;
- abstract classification and timing;
- CFG/abstract-state/rule telemetry;
- UNKNOWN reason;
- symbolic timing and verdict;
- KLEE paths/completed paths/instructions/queries;
- solver time and peak memory only when directly exposed;
- total hybrid time;
- exit status;
- stdout/stderr;
- raw verifier/KLEE logs.

Raw logs are authoritative; aggregates are generated from raw data.

## 18. Correctness methodology

The authoritative reference is frozen KRAKENGUARD on the same object and policy.

For each program/policy pair:

1. run symbolic-only reference;
2. record authoritative verdict;
3. run hybrid;
4. compare final verdicts.

Required:

~~~text
hybrid_final_verdict == reference_verdict
~~~

SAFE must match COMPLIANT. VIOLATION must match REJECTED/VIOLATION. UNKNOWN is resolved through symbolic fallback and that result must match the reference.

Agreement validates the hybrid relative to the selected reference implementation; it does not independently prove KRAKENGUARD universally correct.

## 19. Statistical analysis

Primary unit: program/policy pair.

Primary performance estimator: per-program median of seven measured repetitions.

Report mean, median, min, max, sample standard deviation, CV and 95% confidence intervals where appropriate.

E3: exact binomial confidence intervals for discharge proportions.

E4: paired per-program differences, median ratio, percent savings, 95% CI and paired effect size.

E5: fallback fraction and fallback cost by observed path level.

If fitting a scaling model, inspect the data first. Do not assume the E2 linear-per-path relationship transfers to hybrid fallback.

If multiple confirmatory comparisons are performed, predeclare a correction such as Holm.

No outlier deletion.

## 20. Success criteria

### Correctness

Zero incorrect hybrid final verdicts on the validation corpus.

### Coverage

Measurable abstract discharge with category-specific reporting.

### Performance

A positive result requires lower complete hybrid cost with uncertainty supporting the observed direction. Otherwise report neutral or regressive performance.

### Scalability

Report how fallback fraction and fallback cost change with observed symbolic path complexity. No particular trend is assumed in advance.

## 21. Limitations

1. Initial abstract domain is intentionally small.
2. UNKNOWN is expected outside that domain.
3. KRAKENGUARD is the reference oracle, limiting oracle independence.
4. Corpus is synthetic and policy-directed.
5. E2 reached only 64 paths.
6. Peak memory and solver time may remain unavailable.
7. One host and one frozen verifier revision limit generalization.
8. Abstract-analysis overhead is part of candidate cost.
9. Policy and program complexity can still interact.
10. High discharge coverage does not imply general applicability.
11. Performance gains may disappear after complete pipeline accounting.
12. Agreement with KRAKENGUARD does not independently prove KRAKENGUARD correctness.
13. Production-scale eBPF programs are outside the current protocol.

## 22. Implementation prerequisites

Before performance execution:

1. freeze policy files and hashes;
2. freeze corpus manifest;
3. define exact abstract-domain semantics;
4. define supported BPF instruction subset;
5. define sound transfer functions;
6. define UNKNOWN behavior;
7. freeze category labels and expected outcomes;
8. generate source corpus;
9. compile corpus;
10. validate object hashes and CFG metrics;
11. run a correctness-only pilot against KRAKENGUARD;
12. verify A/C cases are abstractly decidable;
13. verify B/D cases actually produce UNKNOWN before fallback;
14. verify reference verdicts;
15. freeze execution manifest;
16. obtain independent review.

Only then open the performance execution gate.

## 23. Repository artifact plan

Design stage:

~~~text
research/experiments/design/
├── phase5-research-plan.md
└── phase5-execution-gate.json
~~~

Future execution stage:

~~~text
research/experiments/
├── corpus/phase5/
├── scripts/
└── results/
    ├── e3/
    ├── e4/
    └── e5/
~~~

Do not create result files during design. Do not modify Phase 3, E1, E2 or frozen baseline evidence.

## 24. Execution gate

Design conditions are specified, but implementation and independent validation are not complete.

~~~text
execution_approved = false
~~~

Implementation-time gates:

- implementation complete;
- corpus implemented;
- reference verdicts validated;
- abstract soundness reviewed;
- category behavior validated;
- independent review complete.

All must be true before execution approval.

## 25. Research decision

**PHASE 5 DESIGN: READY FOR IMPLEMENTATION — NOT READY FOR EXECUTION**

Correct order:

~~~text
Implement abstract analyzer
        ↓
Build 24-case validation corpus
        ↓
Validate reference verdicts
        ↓
Validate A/C discharge
        ↓
Validate B/D UNKNOWN behavior
        ↓
Freeze corpus + policy + configuration
        ↓
Independent review
        ↓
Open execution gate
        ↓
Run E3/E4
        ↓
Use validated path strata for E5
~~~

No Phase 5 experiment is executed by this document.
