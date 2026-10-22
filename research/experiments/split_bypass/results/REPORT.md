# Split–Analyze–Bypass controlled evaluation — status report

**Status: preparation scaffold committed; empirical evaluation pending.** The CI test outcomes below are real and recorded. No successful corpus compilation, live verifier run, oracle agreement, latency result, or scalability result is claimed.

## Repository baseline

- Evaluation branch is based on main at `6457dacd48d21965b85b52acc55502179718f4ab`.
- The prior prototype is merged in main.
- The existing runner calls the whole-program abstract analyzer. Its CFG output is metadata; it does not compute block-local verdicts or incoming states.
- The existing KRAKENGUARD client accepts a complete ELF and policy. Same-region symbolic fallback is not supported by the inspected contract.
- Baseline analyzer and historical E1–E5/workbench artifacts were not modified by this branch's new files.

## New artifacts

- `scripts/prepare_corpus.py`: fourteen deterministic source fixtures across straight-line, branching, join, UNKNOWN-candidate, and bounded-loop families; compiler command/outcome and hashes are recorded in a generated manifest.
- `scripts/analyze_runs.py`: normalized raw-run summary, per-program latency and verdict metrics, explicit-pair bootstrap intervals, false SAFE/false REJECT accounting when oracle labels exist.
- `tests/test_controlled_evaluation.py`: deterministic tests for fixture definitions and summary semantics.
- `design/region-api-design.md`: region API contract, soundness obligations, evaluation protocol.
- `README.md`: commands, raw schema, status vocabulary and separation from historical result directories.

The corpus generator has not been run in this editing environment. No generated ELF files or oracle verdicts are committed. Source code is embedded as deterministic templates and is materialized under `programs/` when the generator is executed. The manifest intentionally leaves semantic verdicts null until an actual reference response is captured.

## Validation log

| Check | Outcome | Evidence |
|---|---|---|
| Main commit inspection | Completed via GitHub repository API | Main HEAD above |
| Initial CI setup attempt | Failed before tests | Run #5: `setup-python` pip cache failed because the repository has no `requirements.txt` or `pyproject.toml`; cache option was removed |
| CI test run | Partial pass; overall job failed | [Run #9](https://github.com/roydza27/Research-Paper-eBPF/actions/runs/39733688861): analyzer, prototype, and new tests passed; audit suite has two missing-object failures |
| Existing analyzer interface inspection | Completed by source inspection | Whole-program constructor/analyze flow |
| Existing abstract analyzer soundness tests | **12 passed** | GitHub Actions run #9, Python 3.12.15; `research/tests/test_phase5_abstract_soundness.py` |
| Existing E3/E4/E5 audit tests | **3 passed, 2 failed** | GitHub Actions run #9; both failures require the absent compiled historical `research/experiments/corpus/phase5/programs/a1.o`. Historical object binaries are not present in the checkout. The test file's other three tests passed. |
| Existing split-and-bypass tests | **18 passed** | GitHub Actions run #9; `research/experiments/tests/test_split_analyze_bypass.py` |
| New controlled evaluation unit tests | **7 passed, 14 subtests passed** | GitHub Actions run #9; `research/experiments/split_bypass/tests/test_controlled_evaluation.py` |
| Corpus generation / compilation | Not executed | No new corpus generator/clang command was run |
| Reference-oracle smoke | Not executed | No live KRAKENGUARD service/socket verified |
| Baseline-vs-experiment measurements | Not executed | No raw runs exist |
| Region-level abstract analysis | Not implemented | Design only; whole-program API remains |
| Region-level symbolic fallback | Not supported by inspected interface | Keep whole-program fallback |

## Before any empirical claim

1. Run the three existing test suites and new unit tests on the target host, preserving stdout/stderr and exit codes.
2. Collect environment and tool versions; run the corpus generator with the frozen policy.
3. Inspect each source/object and compare emitted CFG structure to its intended family. Record compiler and kernel-verifier failures rather than relabeling them.
4. Run the frozen reference oracle and preserve raw request/response provenance before assigning labels.
5. Run paired baseline and experimental measurements with fixed warmup/repetition policy and immutable raw output paths.
6. Review verdict agreement and false SAFE/false REJECT cases before latency interpretation.
7. Implement and prove sound state transfer, joins, loops and successor coverage before describing the pipeline as region-level.

## Conclusion

This is reproducibility infrastructure and a technical design, not an experimental result. No region-level verification, verdict agreement, symbolic workload reduction, latency improvement, or scalability claim is established. Paper claims should remain unchanged pending real evidence and review.
