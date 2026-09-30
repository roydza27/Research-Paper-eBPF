# Phase 4 E2 — Controlled Symbolic Branching / Path Scaling

**Status:** DESIGN COMPLETE — EXECUTION NOT APPROVED  
**Design branch:** `phase4-e2-design`  
**Frozen E1 baseline:** PASS WITH QUALIFICATIONS  
**KRAKENGUARD:** `e7bd84005b304c5a10efcdb04914d1882b3cccf7`

## A. Research Question

> **How does KRAKENGUARD verification cost scale as the number of feasible symbolic execution paths increases, while policy, verifier revision, environment, compiler configuration, hook, and program feature family remain controlled?**

The primary independent variable is **empirically observed feasible symbolic path count**, not source-level branch count and not raw instruction count.

## B. Falsifiable Hypothesis

> **H1:** As feasible symbolic path count increases, KRAKENGUARD end-to-end verification cost will eventually depart from the relatively flat regime observed in E1, accompanied by increasing KLEE path exploration and solver activity.

The experiment does not assume linear, superlinear, or exponential scaling. If the observed relationship remains flat, H1 is not supported over the reachable range.

## C. Independent Variable

### Primary

**Observed KLEE explored/completed symbolic paths.**

### Secondary structural variables

- compiled BPF instructions
- CFG-derived basic blocks
- conditional jumps
- unconditional jumps
- helpers
- maps
- loops
- symbolic input source
- source-level predicate count, retained only as descriptive metadata

The authoritative complexity is the **compiled object plus KLEE observation**.

## D. Controlled Variables

Hold fixed:

| Variable | E2 value |
|---|---|
| KRAKENGUARD | `e7bd84005b304c5a10efcdb04914d1882b3cccf7` |
| Policy | `e1_fixed_policy.json` |
| Policy SHA-256 | `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603` |
| Hook | XDP |
| Host | same research host as E1 |
| Kernel | Linux 7.2.3-arch1-2 |
| Architecture | x86_64 |
| CPU | AMD Ryzen 5 5600H, 12 logical cores |
| Compiler | Clang 22.1.8 |
| Target | `-target bpf -mcpu=v1 -D__TARGET_ARCH_x86` |
| Optimization | `-O2 -g` |
| Helpers | exactly one `bpf_ktime_get_ns` call in every candidate |
| Maps | zero |
| Return behavior | common final `XDP_PASS` |
| Timeout | 300 seconds per verification |
| Warmups | 2 per accepted level |
| Measurements | 7 per accepted level |
| Outliers | never removed |
| Failed/timeout runs | preserved; never silently replaced |

The helper family is deliberate: the frozen KRAKENGUARD helper implementation makes `bpf_ktime_get_ns()` return a KLEE-symbolic 64-bit value. This gives E2 a symbolic source without changing maps, policy dimensions, or hook type.

## Critical symbolic-input finding

E2 must **not** use `ctx->ingress_ifindex` as its symbolic driver.

The frozen KRAKENGUARD XDP harness explicitly initializes:

`test.ingress_ifindex = 0`

while packet memory is made symbolic and the KRAKENGUARD `bpf_ktime_get_ns()` stub calls `klee_make_symbolic()` on its returned time value.

Therefore the proposed E2 family uses one symbolic `bpf_ktime_get_ns()` result and branches on independent bits of that value.

## E. Corpus Proposal

The proposed family is:

| Program | Predicates B | Target paths | Fixed helper calls | Maps | Intended role |
|---|---:|---:|---:|---:|---|
| E2-P0 | 0 | 1 | 1 | 0 | symbolic baseline |
| E2-P1 | 1 | 2 | 1 | 0 | first symbolic split |
| E2-P2 | 2 | 4 | 1 | 0 | two independent splits |
| E2-P3 | 3 | 8 | 1 | 0 | three independent splits |
| E2-P4 | 4 | 16 | 1 | 0 | pilot upper gate |
| E2-P5 | 5 | 32 | 1 | 0 | full-matrix level |
| E2-P6 | 6 | 64 | 1 | 0 | full-matrix upper level |

These are **target levels**, not promised results.

### Candidate program pattern

Each candidate will:

1. call `bpf_ktime_get_ns()` exactly once;
2. test one distinct bit of that symbolic 64-bit value per branch;
3. perform an observable volatile state update in both branch arms;
4. continue to the next predicate rather than returning from the branch;
5. return `XDP_PASS` once at the end.

Conceptual form:

```c
__u64 x = bpf_ktime_get_ns();
volatile __u64 sink = 0;

if (x & (1ULL << 0))
    sink = 1;
else
    sink = 2;

if (x & (1ULL << 1))
    sink = 3;
else
    sink = 4;

/* ... additional independent bit predicates ... */

(void)sink;
return XDP_PASS;
```

The final source files are **not accepted merely because they match this template**. They must pass the compiled-object and pilot gates below.

### Why this pattern

A branch that immediately returns can interact with KRAKENGUARD's return-value recording/termination behavior. E1 demonstrated that nominal source branches do not necessarily become observed symbolic paths. E2 therefore keeps all branch arms live and converges to one common final return.

Volatile state is used only to preserve branch side effects through compilation. It is not itself an independent variable and must be verified from the object.

If Clang still lowers any candidate to branchless code, that candidate is rejected rather than relabeled.

## F. Compiler Validation

For every candidate:

### F1 — Source identity

Record:

- source path
- source SHA-256
- compiler command
- compiler version
- target
- optimization flags
- compile stdout/stderr
- exit code

### F2 — Object inspection

Run:

```text
file <object>
readelf -S <object>
llvm-objdump -d <object>
bpftool btf dump file <object> format raw
```

Record the raw outputs.

### F3 — Branch validation

Do not count source `if` statements.

Determine actual conditional jumps from the compiled BPF disassembly and, where practical, derive a real CFG rather than using E1's `1 + branch_count` heuristic.

For level B:

`compiled_conditional_jumps >= B`

must hold.

The exact count is recorded even if it differs from B.

### F4 — Symbolic-source validation

The object must contain the single `bpf_ktime_get_ns` helper call.

The candidate must not read `ctx->ingress_ifindex` as its symbolic source.

The generated KRAKENGUARD harness must retain the helper's symbolic return semantics.

### F5 — Path validation

A candidate is an accepted scaling level only after KRAKENGUARD/KLEE execution demonstrates the actual path count.

No metadata label can establish a path level.

## G. Pilot Experiment

Do **not** launch the full matrix initially.

Pilot candidates:

- E2-P0
- E2-P1
- E2-P2
- E2-P3
- E2-P4

For each candidate:

1. compile once;
2. inspect object once;
3. verify branch structure;
4. verify one symbolic helper call;
5. execute one KRAKENGUARD verification;
6. capture raw stdout/stderr/exit/timing;
7. record KLEE paths and solver queries;
8. inspect verifier and policy result.

### Pilot acceptance

The pilot passes only if:

- P0 produces one path;
- each successive accepted level produces strictly more feasible paths than its predecessor;
- all accepted candidates retain the intended symbolic helper;
- compiled branch count increases as intended;
- no candidate introduces maps, loops, extra helpers, or policy changes;
- all accepted candidates compile and verify without unsupported/error classification;
- the observed sequence reaches at least the 8-path level (P3).

**Important:** exact 2/4/8/16 path values are not mandatory. Strictly increasing empirically observed path levels are mandatory. If, for example, the pilot produces 1, 2, 4, 7, 13, then those observed levels become the factual levels for E2 and the nominal labels remain descriptive only.

### Pilot failure handling

If a candidate:

- loses branches during compilation;
- produces no symbolic split;
- produces no path increase;
- changes helper/map behavior unexpectedly;
- times out;
- is unsupported by the frozen verifier;
- or otherwise fails,

the candidate is rejected and the full matrix is **not** launched.

The cause is documented. The corpus may then be redesigned on the design branch and re-reviewed. It must not be silently substituted during execution.

## H. Full Experiment

The full matrix is launched only after the pilot gate passes.

### Matrix

All empirically validated path levels from the pilot, plus validated P5/P6 levels if reachable.

For each accepted level:

- 2 warmups
- 7 measured repetitions

Thus, if all seven proposed levels survive:

`7 levels × (2 + 7) = 63 executions`

This is intentionally smaller than an uncontrolled 8-program expansion while reaching substantially larger symbolic path counts.

### Execution order

Use deterministic ascending path-level order:

`P0 → P1 → P2 → P3 → P4 → P5 → P6`

and record absolute execution order/run sequence in metadata.

This preserves reproducibility and makes the escalation explicit. No level is repeated solely because it produced an inconvenient timing result.

### Failure handling

Classify each run independently as:

- accepted
- rejected
- unknown
- timeout
- unsupported
- error

Do not convert timeout, unsupported, or environment errors into policy rejection.

Do not rerun failed measurements simply to fill a quota.

A replacement execution, if technically required after a clearly documented environment failure, receives a new run ID and is explicitly marked as a replacement.

## I. Timeout Policy

Use the E1 **300-second timeout** as the initial E2 budget.

Rationale:

- preserves direct comparability with E1;
- is long enough to observe the E1 sub-second regime;
- bounds pathological symbolic search;
- makes timeout itself a meaningful scalability outcome.

If an E2 level reaches the timeout:

> **The verifier exceeded the experimentally permitted verification budget at this observed complexity level.**

The timeout is retained as data.

A timeout is not treated as a failed experiment and does not justify silently reducing the complexity level.

## J. Metrics

Every execution records:

### Identity

- experiment_id
- program_id
- run_id
- warmup/measured
- repetition
- source SHA-256
- object SHA-256
- policy SHA-256
- KRAKENGUARD commit
- host/kernel/architecture
- compiler/version/flags

### Compiled complexity

- source_predicate_count
- compiled_instruction_count
- CFG basic blocks
- conditional jumps
- unconditional jumps
- loops
- helpers
- maps
- symbolic source

### Verification measurements

- wall_time_us
- KLEE explored/completed paths
- KLEE total instructions
- solver_queries
- verifier result
- policy result
- execution status
- exit code
- daemon-reported duration where available

### Explicitly unavailable metrics

- client-process CPU time may be recorded, but must be labeled with its actual `time.process_time()` semantics;
- peak memory = `NOT_REPORTED` unless a real measurement is implemented and validated;
- solver time = `NOT_REPORTED` unless directly measured.

## K. Analysis Plan

### Primary relationship

Analyze:

`observed KLEE paths → wall-clock verification time`

Use per-level median wall time as the primary robust summary.

Retain:

- mean
- median
- minimum
- maximum
- sample standard deviation
- CV

### Secondary relationships

Analyze:

`paths → solver queries`

`compiled instructions → wall time`

`compiled branches → paths`

`paths → daemon duration`

### Scaling characterization

Do not assume exponential behavior.

Inspect the empirical relationship first.

Potential descriptive models:

- approximately constant
- linear
- polynomial/superlinear
- exponential-like
- thresholded/piecewise

Model fitting is secondary to demonstrating the actual observed regime.

If only a few path levels are reachable, report the limitation instead of fitting an ambitious asymptotic model.

### Timeout censoring

Timeout levels are plotted/recorded as budget crossings, not assigned an invented wall time.

No interpolation is used to fabricate a missing runtime.

### Outliers

No outlier removal.

The raw observations remain authoritative.

## L. Threats to Validity

1. **Compiler optimization:** source branches may disappear or be transformed.
2. **Symbolic-helper semantics:** KRAKENGUARD's model of `bpf_ktime_get_ns` is specific to the frozen implementation.
3. **Path feasibility:** syntactic branch count does not guarantee independent feasible paths.
4. **Branch correlation:** multiple predicates can share symbolic constraints.
5. **Fixed pipeline overhead:** end-to-end wall time may remain dominated by startup/lifting/harness costs at low path counts.
6. **KLEE search behavior:** path enumeration depends on the frozen KLEE configuration.
7. **Host effects:** CPU scheduling, I/O, cache state and daemon/container behavior can affect wall time.
8. **Timeout censoring:** high path levels may only establish a budget crossing.
9. **Small corpus:** even 64 observed paths remains far below large production eBPF state spaces.
10. **Helper-model dependence:** using `bpf_ktime_get_ns` isolates symbolic branching without maps, but does not represent every source of symbolic complexity.
11. **Single policy:** conclusions apply to the fixed E1 policy and do not generalize automatically to policy complexity.
12. **Single verifier:** results characterize frozen KRAKENGUARD, not symbolic verification in general.

## M. Acceptance Criteria

E2 design is accepted only when all of the following are true:

- primary variable is feasible symbolic path growth;
- source branch count is explicitly non-authoritative;
- compiled branches are measured;
- symbolic input is explicitly identified;
- the chosen symbolic source is supported by the frozen harness;
- candidate branches must survive compilation;
- feasible paths must be empirically verified;
- policy remains unchanged;
- KRAKENGUARD remains frozen;
- compiler configuration remains fixed;
- XDP remains fixed;
- helpers/maps are controlled;
- no uncontrolled loops or feature changes are introduced;
- warmup/repetition counts are defined;
- timeout is justified;
- outlier handling is defined;
- timeout handling is defined;
- KLEE path terminology is used correctly;
- CPU semantics are not overstated;
- memory/solver time are not fabricated;
- E1's P2/compiler-collapse limitation is explicitly addressed;
- E1's low path-count limitation is directly addressed;
- the pilot gate exists;
- repository artifacts are specified;
- no E1 evidence is modified;
- E2 does not claim to validate the hybrid verifier itself.

## N. Execution Gate

> **DESIGN COMPLETE ≠ EXECUTION APPROVED**

Execution is approved only after the pilot corpus has been compiled and empirically shown to generate controlled, strictly increasing feasible symbolic path levels.

The pilot must be reviewed before the full matrix.

**This branch contains design artifacts only. No E2 execution results are created here.**

## O. Repository Artifact Plan

When execution is eventually approved, use:

```text
research/
└── experiments/
    ├── corpus/
    │   └── e2/
    │       ├── metadata.csv
    │       ├── policies/
    │       │   └── e2_fixed_policy.json
    │       └── programs/
    │           ├── e2_p0.c
    │           ├── e2_p1.c
    │           ├── e2_p2.c
    │           ├── e2_p3.c
    │           ├── e2_p4.c
    │           ├── e2_p5.c
    │           └── e2_p6.c
    ├── scripts/
    │   └── execute-e2-matrix.py
    └── results/
        └── e2/
            ├── README.md
            ├── e2-results.csv
            ├── e2-results.json
            └── raw/
                ├── pilot/
                └── runs/
```

No result files or execution logs belong on the design branch.

## P. Review Decision

**DESIGN DECISION: CONDITIONALLY ACCEPTED FOR PILOT**

The design is scientifically defensible **provided the pilot confirms that the frozen KRAKENGUARD harness actually propagates the symbolic `bpf_ktime_get_ns` value through the compiled branch family and produces increasing KLEE path counts**.

The most important adversarial condition is therefore not whether the C source contains N `if` statements. It is whether the frozen compiled-and-lifted execution actually produces increasing feasible symbolic paths.

If the pilot cannot demonstrate that, E2 must be redesigned before any full matrix execution.
