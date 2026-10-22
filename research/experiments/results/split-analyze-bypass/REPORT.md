# Integrated experiment report — Split–Analyze–Bypass

**Status:** ported to current main; runtime validation pending  
**Integration base:** 9250b53243714f00868f8c73a3c794634cfc5ad2  
**Prototype source:** 0d81b13a03c6294051620c6157b10b8d36922a81  
**Branch:** experiment/split-analyze-bypass-main-integration

## Port and compatibility

The new integration branch is based on current main, not the older experiment branch. The port includes only the experiment runner, its tests, the design document, and this report. The current analyzer's Git blob is ca07c1ad340e4220f227a8051b91a62faa0dce5d, matching the baseline integrity assertion. The current analyzer still builds the CFG and initializes state internally; there is no supported independent block entry-state API. Existing KRAKENGUARD verdict parsing remains fail-closed and returns COMPLIANT or POLICY VIOLATION; the experiment normalizes those at its boundary.

The current-main additions to the manuscript, evidence ledger, comparison workbench, raw comparison records, and audit tests are retained. No baseline implementation or historical results were changed.

## Files on the integration branch

- research/experiments/scripts/split_analyze_bypass.py
- research/experiments/tests/test_split_analyze_bypass.py
- research/experiments/design/split-analyze-bypass-prototype.md
- research/experiments/results/split-analyze-bypass/REPORT.md

Each run record now includes the integration base SHA, prototype source SHA, and timeout/baseline configuration.

## Tests and smoke experiment

**Tests executed in this integration operation: none.** The GitHub connector can inspect and commit repository files but does not provide a shell on the target checkout. Consequently, neither the existing analyzer/audit tests nor the experiment tests were run here. No smoke run was attempted, no raw run output was created, and no symbolic verdict is claimed.

Run the three documented unittest commands in the design document. Only after they pass should the single-program smoke be run. It requires the compiled ELF, policy, Python dependencies, and a live KRAKENGUARD service/socket. The repository file API did not provide the compiled a1.o as a readable text file; local artifact availability has not been established.

## Remaining limitations

This is still program-level orchestration, not block-level verification. CFG blocks are metadata only, block verdicts/incoming states remain unset, and symbolic fallback uses the whole-program interface. Timeout and tool errors remain unresolved. Do not infer speedup, scalability, oracle agreement, or correctness from the integration alone. No E1–E5, workbench, or paper quantitative results were modified.