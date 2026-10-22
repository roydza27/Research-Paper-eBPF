# Split–Analyze–Bypass: main-branch integration

## Integration provenance

- **Integration base (main):** 9250b53243714f00868f8c73a3c794634cfc5ad2 (2026-10-22).
- **Prototype source branch:** experiment/split-analyze-bypass-prototype
- **Prototype source HEAD:** 0d81b13a03c6294051620c6157b10b8d36922a81
- **Common ancestor:** 7551aec4bf62ca5240ebf55adee3ed57d88b8af9
- **Integration branch:** experiment/split-analyze-bypass-main-integration

The integration branch starts at current main; it ports only the four experiment artifacts, not the old branch's commit history. Current main was 12 commits ahead of the prototype at inspection. Its newer manuscript exports, evidence ledger, workbench analysis, raw comparison records, and audit tests are preserved.

## Current-main compatibility review

The current analyzer remains at Git blob ca07c1ad340e4220f227a8051b91a62faa0dce5d. AbstractPolicyAnalyzer still owns disassembly, CFG construction, entry register initialization, branch exploration, and the final three-valued verdict. BasicBlock still carries start_pc, instructions, successors, cond_target, fallthrough, and is_exit; instructions expose pc. The existing KRAKENGUARD verdict parser still emits COMPLIANT or POLICY VIOLATION and fails closed on malformed output. The adapter normalizes these reference labels only at its own boundary.

Current analyzer soundness tests live under research/tests/test_phase5_abstract_soundness.py; audit invariants are under research/tests/test_phase5_e3_e4_e5_audit.py. The prototype's baseline integrity assertion matches the current analyzer blob hash. The new tests remain under research/experiments/tests/.

## Ported files

- research/experiments/scripts/split_analyze_bypass.py
- research/experiments/tests/test_split_analyze_bypass.py
- research/experiments/design/split-analyze-bypass-prototype.md
- research/experiments/results/split-analyze-bypass/REPORT.md

The runner now records both the integration-base commit and prototype-source commit, plus run timeout and baseline configuration. No analyzer, baseline wrapper, existing tests, paper, workbench, or historical result file was modified.

## Run commands

From the repository root:

```bash
python3 -m unittest discover -s research/tests -p 'test_phase5_abstract_soundness.py' -v
python3 -m unittest discover -s research/tests -p 'test_phase5_e3_e4_e5_audit.py' -v
python3 -m unittest discover -s research/experiments/tests -p 'test_split_analyze_bypass.py' -v
```

Smoke invocation, after confirming the ELF is available locally and KRAKENGUARD is ready:

```bash
python3 research/experiments/scripts/split_analyze_bypass.py \
  --object research/experiments/corpus/phase5/programs/a1.o \
  --policy research/experiments/corpus/phase5/policies/phase5_policy.json \
  --program-id a1 \
  --baseline-dir research/baselines/krakenguard/artifact \
  --abstract-timeout-seconds 60 \
  --symbolic-timeout-seconds 120 \
  --output research/experiments/results/split-analyze-bypass-integration/raw/a1-smoke.json
```

Output creation refuses an existing result path. Use a new path for every run. Do not place new outputs in E1–E5, comparison-workbench, or baseline result directories.

## Validation status

The remote GitHub editing interface does not provide a shell on the user's repository checkout. Therefore, this integration operation has not executed Python tests or the smoke command. No tests are reported as passed, and no output file or symbolic verdict is claimed. Run the commands above in a checkout of this branch and attach the real logs before treating the integration as validated. The smoke also requires a locally available compiled a1.o, policy file, Python dependencies, and a live configured KRAKENGUARD service/socket.

## Scope boundary

This remains a **program-level orchestration experiment**, not independent basic-block verification. The adapter records CFG metadata and reachable reverse-postorder, but block verdicts and incoming block assumptions remain unset. It invokes the existing abstract analyzer on the complete ELF; if that verdict is UNKNOWN, symbolic fallback verifies the complete ELF and policy. Tool errors, timeouts, parser failures, and unresolved verdicts remain UNKNOWN/unresolved.

A real region-level implementation requires:
1. A region API accepting entry abstract state, predecessor constraints, and region bounds.
2. Explicit transfer functions for register state and policy-relevant memory/map state.
3. Sound join semantics and loop/fixpoint treatment or conservative UNKNOWN.
4. State and path-condition propagation across all reachable successors.
5. A symbolic fallback contract proving the same region and assumptions; otherwise preserve whole-program fallback.
6. Cross-checking all reachable behaviors against the frozen reference oracle before performance benchmarking.

No paper quantitative claims are updated by this integration. E3/E4/E5 and the 432-run matrix have not been launched as part of this task.