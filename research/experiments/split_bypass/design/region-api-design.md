# Split–Analyze–Bypass: controlled evaluation and region API design

## 1. Existing baseline inspection

At the current main baseline, `AbstractPolicyAnalyzer` is a whole-program analyzer: construction takes the complete ELF and policy, and analysis owns disassembly, CFG construction, register initialization, branch exploration, and final verdict production. Its supported interface does not accept an independently supplied basic-block region with caller-supplied incoming abstract state. The current runner's `extract_cfg` is descriptive metadata only; its `block_verdict` and `entry_assumptions` fields intentionally remain null.

The current KRAKENGUARD client is invoked with `object_file` and `constraints_file`, i.e. a complete object and policy. No evidence in the current client contract establishes region-scoped symbolic verification. Therefore UNKNOWN fallback must remain whole-program until KRAKENGUARD explicitly supports a region and compatible assumptions.

## 2. Corpus families and hypotheses

Fourteen initial source fixtures are defined in `scripts/prepare_corpus.py` and emitted to `programs/` when the generator is run.

| IDs | Family | Controlled property | Important caveat |
|---|---|---|---|
| A01–A04 | Straight-line | Small/medium arithmetic and a helper call | Compiler optimization changes emitted instruction counts |
| B01–B03 | Branching | Safe alternatives and a policy-sensitive DROP alternative | Actual policy verdict must come from the oracle |
| C01–C03 | Join points | Different values reach a shared continuation | Compiler may transform or eliminate the intended join |
| D01–D02 | UNKNOWN candidates | Helper-derived value and bounded packet access | UNKNOWN is a hypothesis; never assigned in advance |
| E01–E02 | Loop | Bounded loop with unrolling disabled | Emitted loop structure and verifier acceptance must be measured |

The first iteration deliberately avoids asserting semantic labels. For every fixture, the manifest records source hash, compilation command and outcome, object hash when compiled, policy hash, and reference-oracle status. Instruction/branch/BB counts remain null when tools cannot produce a trustworthy count. A successful clang invocation alone does not prove kernel-verifier acceptance or policy correctness.

## 3. Build and reference protocol

1. Freeze the main commit and collect host, compiler, LLVM, Python, kernel, KRAKENGUARD and dependency versions.
2. Generate sources from the committed generator, copy a policy by content hash, and preserve the resulting manifest.
3. Compile each program independently. Record command, exit status, stdout/stderr, timeout, ELF SHA-256, and disassembly/CFG counts.
4. Submit only valid compiled objects to the reference oracle. Preserve raw request and response, tool version, policy hash, and parser output. If an object is rejected before semantic analysis, record that failure separately from a policy violation.
5. Repeat the same source/policy pairs for baseline and experimental pipelines. Use a fixed warmup count and repetitions; use explicit `pair_id` for matched observations.
6. Preserve raw results; summarize copies only. Never overwrite previous manifests or raw data.
7. Report every failed compilation, rejected object, timeout, tool error and unresolved verdict.

## 4. Normalized observation schema

Each raw run should preserve `program_id`, `pipeline`, `run_id`, `pair_id`, `repeat_index`, `seed`, `source_commit`, tool versions, source/object/policy hashes, structural counts, abstract and symbolic verdicts/durations, symbolic invocation flag, final disposition, timeout/error/unresolved flags, reference verdict and raw oracle response path. Use null for not measured. Keep compile-time failure separate from analyzer UNKNOWN.

The summary script reports per-program medians/means, symbolic invocation rate, unresolved counts, oracle agreement and false SAFE/false REJECT counts only when reference labels exist. Paired bootstrap intervals are emitted only for explicitly pair-matched end-to-end measurements. Fewer symbolic calls do not imply better total performance.

## 5. Minimal sound region API

A viable region API must be explicit about scope and assumptions. Suggested interface (conceptual, not implemented in this iteration):

```text
analyze_region(
  program,
  region_bounds,
  incoming_abstract_state,
  predecessor_path_constraints,
  policy_state,
  successor_edges,
  analysis_budget
) -> RegionResult
```

`incoming_abstract_state` must model registers, stack/memory validity and contents, pointer provenance/ranges, map state relevant to policy, and helper effects. `predecessor_path_constraints` must describe the path conditions under which the state reaches the region. `region_bounds` must include entry and exit edges; exceptional exits and helper effects must be explicit. The result must include verdict, outgoing abstract state per successor, proof/reason, unsupported instruction information, state/worklist counts, and resource budget status.

### Transfer and join requirements

- Every supported instruction has a conservative transfer function. Unsupported instructions yield UNKNOWN.
- At joins, incoming states are merged with a sound abstract join or represented as separate path states. A join must not pick one predecessor's constants as if they were universal.
- A successor may be marked discharged only when every reachable incoming state to that successor is covered by a valid region result.
- Loops require a sound fixpoint with widening/narrowing policy and iteration limits. If convergence or soundness is not established, return UNKNOWN.
- Map and helper effects must be modeled or conservatively havoced. An unknown helper side effect cannot be ignored.
- A local violation is reportable only if it is established on a reachable path under valid assumptions. An unreachable violating block does not reject the program.

### Pipeline semantics

- Abstract SAFE: discharge only this region under the supplied assumptions, then propagate its outgoing state to successors.
- Abstract VIOLATION: report a reachable violation only with a supporting path/proof.
- Abstract UNKNOWN: invoke symbolic verification on the same region and assumptions only if the symbolic tool contract supports that scope.
- Symbolic SAFE: discharge that region only; continue through every reachable successor.
- Symbolic violation: record the violating path.
- Timeout/error/UNKNOWN: preserve unresolved; never coerce to SAFE.

Whole-program SAFE requires coverage of every reachable behavior and sound termination. One locally safe region cannot establish a program-level verdict. Since the present KRAKENGUARD interface accepts whole ELF objects, same-region fallback is currently unsupported; the existing whole-program fallback must be labelled as such.

## 6. Correctness and experimental gates

Before performance runs, add deterministic tests for both abstract transfer semantics and orchestration: safe branch alternatives, reachable and unreachable violations, join-state differences, unknown/fallback safe and violating outcomes, unresolved fallback, loops, unsupported instructions, malformed inputs, timeouts, and baseline integrity. Mock the external service for unit tests; run separate integration tests against the frozen service when available. Unit tests are not a proof of soundness.

Report four research questions independently:
1. Verdict agreement against the frozen oracle.
2. Symbolic workload and fallback rate.
3. End-to-end latency including abstract overhead.
4. Scaling with emitted instruction and reachable-block counts.

No quantitative claim is justified by CFG metadata alone. The current iteration does not implement region transfer, does not execute the baseline test suites or oracle, and does not claim any verdict agreement or performance improvement.
