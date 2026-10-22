# Split–Analyze–Bypass Evaluation Corpus

This directory is an isolated, source-first corpus for evaluating the existing split–analyze–bypass prototype and documenting the requirements for genuine region-level verification.

## Evidence status

- These C files are **fixtures to compile and inspect**, not pre-verified eBPF objects.
- No ELF checksum, instruction count, basic-block count, or oracle verdict is asserted until generated and measured on the target toolchain.
- `manifest.json` deliberately records reference verdicts as pending. Populate them only from an actual reference-verifier run with its request/response evidence.
- Do not put outputs in historical E1–E5 or workbench result directories.

## Families

| Family | Source | Intended structural property | Status |
|---|---|---|---|
| A | `family_a_straight.c` | Straight-line XDP entry; compiler output determines actual instruction count | Source fixture; compile pending |
| B | `family_b_branches.c` | Input-dependent branch with two reachable return alternatives | Source fixture; CFG inspection pending |
| C | `family_c_join.c` | Distinct incoming values converge at a join | Source fixture; optimization may change CFG |
| D | `family_d_unknown.c` | Input-dependent load/branch expected to exceed current constant-only branch reasoning | Hypothesis only; analyzer result pending |
| E | `family_e_loop.c` | Bounded loop intended to expose loop/revisit handling | Compiler/verifier support pending |

## Compile and inventory

Run from the repository root on the experiment host, after confirming Clang and libbpf headers are installed:

```bash
mkdir -p research/experiments/split_bypass/build
for src in research/experiments/split_bypass/family_*.c; do
  name="$(basename "$src" .c)"
  clang -target bpf -mcpu=v1 -D__TARGET_ARCH_x86 -O2 -g -I/usr/include \
    -c "$src" -o "research/experiments/split_bypass/build/$name.o" || exit 1
done
sha256sum research/experiments/split_bypass/build/*.o
llvm-objdump -d --no-show-raw-insn research/experiments/split_bypass/build/*.o
```

Compilation is not evidence of policy correctness. Record compiler version/flags, object hash, disassembly-derived instruction/CFG counts, policy hash, and the reference verifier's actual verdict independently.

## Current pipeline boundary

The merged runner `research/experiments/scripts/split_analyze_bypass.py` uses the existing analyzer on the **whole ELF program**. It extracts CFG metadata but intentionally does not emit per-block verdicts or propagate entry states. Its UNKNOWN fallback also verifies the whole ELF. Consequently, this corpus can currently evaluate program-level orchestration and identify region-analysis requirements; it cannot establish the benefit or correctness of independent block-level bypass.

## Recommended experiment sequence

1. Compile the fixtures and capture immutable hashes.
2. Inspect each object with `llvm-readelf` and `llvm-objdump`; record actual instruction and CFG counts rather than source-level estimates.
3. Run the original analyzer and reference oracle with the frozen policy; preserve raw stdout/stderr and exit codes.
4. Run the existing prototype separately, with a unique output filename for each run.
5. Reconcile definitive verdicts, UNKNOWNs, errors, and timeouts. Never count UNKNOWN as agreement.
6. Compare end-to-end latency only after identical warmup/repetition protocols and matching inputs are established.
7. Do not call the experiment block-level until an API accepts region bounds, incoming abstract state, path constraints, and outgoing state, and all reachable alternatives are accounted for.
