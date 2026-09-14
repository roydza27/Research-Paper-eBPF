# Phase 3 — Baseline Reproduction & Experimental Infrastructure

This directory contains the reproducibility infrastructure for the Phase 3 research gate. The goal is to establish a trustworthy baseline before implementing any new verification technique.

## Research questions

- RQ1: Can the strongest relevant eBPF policy-verification baseline be reproduced reliably?
- RQ2: How does verification cost change with program complexity?
- RQ3: How does verification cost change with policy complexity?
- RQ4: Where does symbolic/state-space complexity become a practical bottleneck?
- RQ5: How accurately are compliant and violating programs distinguished?
- RQ6: How do systems behave under multi-constraint policies?
- RQ7: What limitations remain after BPF Token and vBPF?
- RQ8: Does ProcessScope provide useful experimental infrastructure?
- RQ9: Is the proposed Phase 4 direction still justified?

## Structure

```text
research/experiments/
├── environment/
│   ├── collect-environment.sh
│   └── README.md
├── corpus/
│   ├── programs/
│   ├── policies/
│   ├── metadata.csv
│   └── README.md
├── configs/
│   └── benchmark-manifest.json
├── scripts/
│   ├── build-corpus.sh
│   ├── run-baseline.sh
│   ├── collect-results.sh
│   └── analyze-results.py
├── results/
│   ├── raw/
│   ├── processed/
│   ├── figures/
│   ├── tables/
│   └── metadata/
└── README.md
```

Generated results are intentionally not committed until they are produced on a documented experimental host. The repository must never contain fabricated benchmark numbers.

## Baseline policy

KRAKENGUARD is the primary reproduction target because Phase 2 identified it as the strongest directly relevant fine-grained policy-verification baseline. Its public repository describes a pipeline based on eBPF bytecode lifting, LLVM transformations, policy harness generation and KLEE symbolic execution, with policy checks covering memory, helper, map and return-value behavior. Source: https://github.com/krakenguard-ebpf/krakenguard

BCF is the secondary verifier-assurance baseline. Its public artifact contains kernel patches, proof tooling, eBPF programs and evaluation scripts, and documents a Debian Bookworm/QEMU/KVM environment. Source: https://github.com/SunHao-0/BCF

Veritas/SpecCheck is a differential verifier-testing baseline rather than a direct policy-engine equivalent. Its public artifact contains the specification, modified syzkaller and a VM-based evaluation workflow. Source: https://github.com/rs3lab/veritas

## Execution discipline

1. Run `environment/collect-environment.sh` first.
2. Freeze the resulting environment manifest with baseline commit identifiers.
3. Build the corpus without changing benchmark source after measurements begin.
4. Run one baseline at a time and preserve raw logs.
5. Record failures instead of substituting another experiment.
6. Repeat measurements where timing is reported.
7. Analyze raw machine-readable output only; screenshots are supplementary evidence.
8. Do not implement hybrid verification in Phase 3.

## Status

The infrastructure in this branch is **prepared but not experimentally executed**. A Phase 3 result must remain marked `pending`, `reproduced`, `partial`, or `failed` until an actual experimental host produces evidence.