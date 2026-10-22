# Experimental report — Split–Analyze–Bypass

**Status:** implementation scaffold / not yet a block-level experiment  
**Base commit:** `7551aec4bf62ca5240ebf55adee3ed57d88b8af9`  
**Branch:** `experiment/split-analyze-bypass-prototype`

## Finding

The current abstract analyzer and KRAKENGUARD integration are both whole-program interfaces. CFG blocks can be recorded after analyzer execution, but that execution has already classified the complete ELF. It is not valid to infer independent block verdicts from the final program verdict or to analyze instruction fragments without incoming abstract state and branch predicates.

## Implemented

- Isolated script records block PCs/ranges, successors, predecessors and reachability.
- Reachable CFG traversal uses deterministic reverse-postorder, including cycles.
- A sequential fail-closed gate: SAFE → abstract pass; VIOLATION/REJECT → violation; UNKNOWN → symbolic fallback; symbolic errors/timeouts/UNKNOWN → unresolved.
- Existing KRAKENGUARD client and existing verdict extraction function are called in an isolated worker with a parent-enforced timeout.
- JSON output refuses to overwrite an existing result path.
- Deterministic unit tests are added for gate transitions and CFG metadata.

## Not established

- Independent per-block abstract verification.
- Preservation of register/memory/map/path state across region boundaries.
- Same-scope block-level symbolic fallback.
- Integration test results on the actual host.
- Any baseline comparison, oracle agreement rate, latency improvement or scalability result.

## Test and benchmark status

Tests have been added but have **not been executed in the remote GitHub editing environment**. E3/E4/E5 and the 432-run performance matrix were not run. No raw benchmark data or invented results are included. Run the documented unit-test command locally, then perform correctness-only integration checks before any benchmark design is considered.
