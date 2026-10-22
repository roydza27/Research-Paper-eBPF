# Controlled Split–Analyze–Bypass evaluation

This experiment is isolated from the historical Phase 5 corpus and result directories. It starts as a reproducibility scaffold: **no compilation, reference verdict, timing, or performance result is asserted by committing these scripts**.

## Current implementation boundary

The existing runner in `research/experiments/scripts/split_analyze_bypass.py` invokes the existing abstract analyzer on a complete ELF. It extracts CFG metadata, but each block's entry assumptions and verdict are null. KRAKENGUARD is also called with the complete ELF and policy. Thus there is currently no region-level abstract discharge or same-region symbolic fallback.

## Quick start

From the repository root, first record the environment and inspect available tools:

```bash
bash research/experiments/environment/collect-environment.sh
clang --version
llvm-objdump --version
python3 --version
```

Generate fourteen deterministic source fixtures and copy the selected policy into this experiment's policy directory. This first pass does not compile:

```bash
python3 research/experiments/split_bypass/scripts/prepare_corpus.py \
  --policy research/experiments/corpus/phase5/policies/phase5_policy.json \
  --manifest-output research/experiments/split_bypass/manifests/corpus-manifest-preflight.json
```

To also compile using the project's established clang convention (`-target bpf -D__TARGET_ARCH_x86 -O2 -g -I/usr/include`), write a separate manifest rather than overwriting the preflight record:

```bash
python3 research/experiments/split_bypass/scripts/prepare_corpus.py \
  --policy research/experiments/corpus/phase5/policies/phase5_policy.json --compile \
  --manifest-output research/experiments/split_bypass/manifests/corpus-manifest-compiled.json
```

Compilation is not kernel verification and is not a reference-oracle verdict. The manifest records each compiler exit status, stderr/stdout, source and ELF SHA-256 where available, and disassembly-derived structural counts where parseable. If counts cannot be reliably parsed, they remain null. The script refuses to overwrite an existing manifest; archive the previous run and use a fresh checkout/run directory before repeating.

Before any semantic comparison, run each compiled ELF against the frozen KRAKENGUARD/reference configuration using the repository's documented client. Save raw responses under `results/raw/`, then manually or programmatically populate oracle verdicts only from those recorded responses. Never infer an expected verdict from a program ID or source hypothesis.

## Layout

- `programs/`: generated C sources and compiled ELF objects; objects are local build products.
- `policies/`: content-addressed copies of the selected policy.
- `manifests/`: corpus manifest with build and oracle provenance.
- `scripts/`: corpus generator and raw-run summarizer.
- `tests/`: deterministic unit tests, independent of a running KRAKENGUARD service.
- `results/raw/`: immutable raw JSON run records and oracle responses.
- `results/summary/`: derived summaries only.
- `design/`: methodology and region-level technical design.

Do not commit host-specific object files, sockets, service logs containing secrets, or measurements from an undocumented environment. Never write into `research/experiments/results/`, E1–E5 evidence, the comparison workbench, or prior experiment result paths.

## Raw-run record schema

Each record should include: `program_id`, `pipeline` (`baseline` or `experimental`), `run_id`, `pair_id`, `repeat_index`, `seed`, source commit, tool versions, input SHA-256 values, instruction/basic-block/branch/reachable-block counts, `abstract_verdict`, `abstract_duration_ms`, `symbolic_invoked`, `symbolic_verdict`, `symbolic_duration_ms`, `end_to_end_duration_ms`, `final_verdict`, `status`, `timeout`, `error`, and `reference_verdict`. Use null for unavailable values; never substitute zero.

The existing runner output can be archived as-is, but baseline and experimental observations should be normalized into the schema above for paired analysis. A `pair_id` must identify matched runs under the same program, policy, host configuration, warmup/repetition position and seed. The summarizer only calculates paired latency differences when an explicit pair ID exists.

## Status vocabulary

- `not_attempted`: command not executed.
- `compiled` / `failed` / `timeout`: actual compiler outcome.
- `not_run`: reference oracle not executed.
- `SAFE`, `VIOLATION`, `UNKNOWN`: semantic verdicts only when produced by a verifier and preserved with provenance.
- `unresolved`: no safe/violation disposition established.
- `metadata_only`: CFG facts, not a block-verification result.

No paper claim should be updated until the source manifest, all raw outputs, test logs, oracle provenance, and analysis script are reviewed.
