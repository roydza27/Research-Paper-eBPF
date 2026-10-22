# Split–Analyze–Bypass Prototype

## Status and scope

This is an isolated, conservative prototype on branch `experiment/split-analyze-bypass-prototype`. It does **not** modify the existing analyzer, baseline scripts, historical results, or E1/E2 evidence.

Remote source inspected before implementation: `research/analyzer/abstract_policy_analyzer.py` at base commit `7551aec4bf62ca5240ebf55adee3ed57d88b8af9`.

### Critical interface limitation

`AbstractPolicyAnalyzer.analyze()` accepts a complete ELF and policy. It internally disassembles the ELF, builds its CFG, initializes registers at the program entry, explores paths, and returns one whole-program verdict. There is no supported API to provide an extracted block, incoming register state, predecessor path constraints, or memory/map state. The KRAKENGUARD client likewise verifies a complete object and policy.

Therefore, the production adapter emits CFG/block metadata but **does not assign block-level verdicts**. It runs a single program-scope sequential gate: abstract whole-program analysis, then whole-program KRAKENGUARD fallback only for UNKNOWN. This is a safety wrapper and interface-discovery prototype, not yet the requested independent block-level optimization. Claiming per-block abstract passes would be unsound.

## Reproducible commands

From repository root (requires the project's Python dependencies and an existing compiled ELF/policy):

```bash
python3 -m unittest discover -s research/experiments/tests -v
python3 research/experiments/scripts/split_analyze_bypass.py \
  --object research/experiments/corpus/phase5/programs/a1.o \
  --policy research/experiments/corpus/phase5/policies/phase5_policy.json \
  --program-id a1 \
  --baseline-dir research/baselines/krakenguard/artifact \
  --abstract-timeout-seconds 60 \
  --symbolic-timeout-seconds 120 \
  --output /tmp/split-analyze-bypass-a1.json
```

The output path must not already exist. The fallback requires the KRAKENGUARD daemon/socket and the repository's existing verdict parser. Missing dependencies, parser errors, tool errors, and timeouts remain UNKNOWN/unresolved. The command is not a benchmark and makes no performance claims.

## Result format

The JSON output records the program ID, object/policy paths, reachable CFG block metadata, deterministic reverse-postorder traversal, whole-program abstract verdict/reason/duration, whether fallback ran, symbolic verdict/reason/duration, timeout limit, tool versions, errors, and final disposition. Block verdicts are null by design until a sound block API exists.

Raw experimental outputs should be written to a new directory separate from `research/experiments/results/` baseline/history. Do not overwrite historical results.

## Correctness boundary and next step

The generic gate tests cover SAFE, VIOLATION/REJECT, UNKNOWN→symbolic SAFE, UNKNOWN→symbolic violation, persistent UNKNOWN, errors, timeouts, CFG branches, unreachable blocks, joins and loops. They do not establish analyzer soundness or end-to-end integration correctness.

Before true split-analyze-bypass execution can be claimed, add a sound region API to the analyzer: explicit entry abstract state, path predicates, memory/map assumptions, conservative joins, and per-region exit states. It must preserve branch alternatives and carry state into successors. Symbolic fallback must then prove the same region under those constraints; if KRAKENGUARD cannot accept that scope, fallback remains whole-program only.

No E3/E4/E5 or 432-run performance matrix was executed by this implementation task. No benchmark, correctness agreement, scalability or speedup claim is made.
