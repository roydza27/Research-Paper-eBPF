# Split–Analyze–Bypass: Evaluation Plan and Evidence Boundary

## Current source state

- Base commit: `6457dacd48d21965b85b52acc55502179718f4ab` (main at experiment creation).
- Existing prototype: `research/experiments/scripts/split_analyze_bypass.py`.
- Existing analyzer: `research/analyzer/abstract_policy_analyzer.py`, blob `ca07c1ad340e4220f227a8051b91a62faa0dce5d`.
- This branch adds a source-first fixture corpus and an opt-in runner. It does not modify the analyzer, baseline wrapper, paper, historical results, or existing prototype.
- No local shell is available through the repository editing connection. Compilation, unit tests, smoke runs, and performance measurements have **not** been executed by this operation.

## What the current implementation actually supports

The prototype runs one whole-program abstract analysis. It extracts the CFG already built by the analyzer and records block addresses, instruction PCs, predecessor/successor metadata, and reachability. These are metadata only: `entry_assumptions` and `block_verdict` remain null. If the whole-program abstract result is UNKNOWN, it invokes the existing KRAKENGUARD whole-program interface. Errors, timeouts, invalid output, and unsupported verdicts remain unresolved.

This is program-level sequential orchestration, not region-level abstract interpretation. It must not be reported as a block-level bypass result or a measured speedup over the existing hybrid pipeline.

## Corpus status

The five source fixtures are controlled hypotheses:
- A: straight-line arithmetic and a context read.
- B: input-dependent branch with two terminal alternatives.
- C: two predecessors assign distinct values before a shared join.
- D: input-dependent branch expected to challenge constant-only reasoning.
- E: bounded loop intended to expose loop/revisit behavior.

Compiler optimization can change or remove the source-level CFG. The manifest therefore leaves object hashes, instruction counts, block counts, branch counts, and reference verdicts empty until measured. A fixture that fails compilation or cannot be handled by the oracle must remain in the run ledger as a failure, not be silently dropped.

## Reproduction steps

From the repository root:

```bash
PYTHONPATH=. python3 -m unittest discover \
  -s research/experiments/tests -p 'test_split_bypass_corpus.py' -v
PYTHONPATH=. python3 -m unittest discover \
  -s research/experiments/tests -p 'test_split_analyze_bypass.py' -v
```

Compile and run the source-first corpus with one warmup and three measured repetitions per successfully compiled fixture:

```bash
python3 research/experiments/split_bypass/run_corpus.py \
  --warmups 1 --repetitions 3 \
  --baseline-dir research/baselines/krakenguard/artifact
```

If KRAKENGUARD is unavailable, omit `--baseline-dir`; the runner will record that symbolic fallback is unavailable and the affected UNKNOWN results will remain unresolved. Do not describe those runs as completed verification.

The harness creates a unique directory under `research/experiments/results/split-bypass-evaluation/<run-id>/`, refuses to overwrite an existing run directory, stores per-run JSON under `raw/`, and writes `summary.json` and `runs.csv`. Inspect compile logs and raw records before calculating rates or medians.

Run the existing baseline tests separately:

```bash
PYTHONPATH=. pytest -v research/tests/
```

Report actual command output, exit codes, compiler/tool versions, commit SHA, policy hash, and whether the daemon was available. These commands are documented but have not been executed here.

## Required region-level design before any block-bypass claim

A region API must be explicit about:
1. Region identity and instruction/block bounds.
2. Incoming abstract register state for every reachable predecessor.
3. Path predicates and branch constraints.
4. Policy-relevant helper, map, packet-memory, and stack state/provenance.
5. Transfer functions and outgoing abstract state.
6. Sound join/widening behavior and loop/fixpoint limits.
7. Successor propagation over all reachable alternatives.
8. A symbolic fallback contract for the **same** region and assumptions. If the symbolic engine only accepts an ELF, fallback must remain whole-program and the report must say so.

A local SAFE result cannot make the whole program SAFE unless all reachable behaviors are covered. A local VIOLATION must be reachable under the tracked path assumptions. Unsupported state joins, loops, memory behavior, and mismatched fallback scope must remain UNKNOWN.

## Performance protocol

Do not compare the new runner's total time with historical E1–E5 values. For a valid comparison, use identical compiled objects, policy hash, machine, toolchain, daemon/container revision, and randomized/interleaved execution order. Keep warmups separate from measured runs. Report end-to-end latency plus abstract/symbolic component times, block counts, fallback counts, definitive verdicts, UNKNOWNs, failures, timeouts, and reference agreement.

Before a region-level implementation exists, any measured difference between the baseline and this wrapper is primarily orchestration/metadata overhead; it is not evidence that region-level bypass improves performance. Do not claim a speedup, scalability, or correctness advantage without a matched dataset and reference verdicts.
