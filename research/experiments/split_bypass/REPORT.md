# Split–Analyze–Bypass Evaluation Report

**Status: instrumentation and source fixtures added; runtime validation pending.**

## Scope

This branch adds five source-level XDP fixtures (straight-line, branching, join, input-dependent UNKNOWN hypothesis, bounded-loop hypothesis), a manifest that explicitly leaves measured metadata and oracle labels pending, a corpus runner, corpus-integrity tests, and an evaluation protocol.

## No measured results claimed

The GitHub repository connection used for this change can read and commit repository files, but it does not provide a shell in the experiment host. Therefore:

- No fixture was compiled in this operation.
- No object hash, instruction count, basic-block count, or branch count has been measured.
- No abstract analyzer or KRAKENGUARD run was executed.
- No tests were executed.
- No baseline-versus-experiment latency comparison exists.
- No reference verdict, correctness rate, speedup, scalability, or region-level bypass success is claimed.

The null fields in `manifest.json` are intentional. They must be populated only after actual compilation, disassembly, and reference-oracle execution.

## Existing implementation boundary

The current merged prototype performs a single program-level abstract analysis and, for UNKNOWN, whole-program symbolic fallback. CFG information is recorded as metadata. There is no independent basic-block entry-state API, no region-bounded symbolic interface, and no sound inter-block state propagation. This experiment does not alter that behavior.

## Files added on the evaluation branch

- `research/experiments/split_bypass/README.md`
- `research/experiments/split_bypass/EVALUATION_PLAN.md`
- `research/experiments/split_bypass/REPORT.md`
- `research/experiments/split_bypass/manifest.json`
- `research/experiments/split_bypass/family_a_straight.c`
- `research/experiments/split_bypass/family_b_branches.c`
- `research/experiments/split_bypass/family_c_join.c`
- `research/experiments/split_bypass/family_d_unknown.c`
- `research/experiments/split_bypass/family_e_loop.c`
- `research/experiments/split_bypass/run_corpus.py`
- `research/experiments/tests/test_split_bypass_corpus.py`

## Next required validation

1. Run the documented unit tests and the original `research/tests/` suite in a complete checkout.
2. Compile each source fixture; record the actual compiler version, command, exit status, ELF checksum, and disassembly.
3. Check the emitted CFG instead of inferring it from C source.
4. Obtain reference verdicts with provenance; preserve compilation failures and unresolved oracle cases.
5. Run the corpus harness with warmups and measured repetitions, then audit raw JSON before computing metrics.
6. Design and separately test the incoming-state/region API before making any block-level bypass claim.
