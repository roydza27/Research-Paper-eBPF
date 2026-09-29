# BCF XDP Applicability Control — Program E

Date: 2026-09-30
Frozen BCF commit: 821ecc14809648cbf0a7866668bb0f776d77e779
Program: e_adversarial_helper.o
Program SHA256: c7c7fb9cb9283a3bdd0430da10118ef187d78d9a91fb16d4bf16e0babf71095b

## Observed execution

BCF VM recognized the object as an XDP program.
Kernel verifier processed 9 instructions.
Total states: 1.
Peak states: 1.
Verification time: 2112 usec.
The program was successfully loaded and pinned at /sys/fs/bpf/bcf-e-adversarial.
No proof-generation or refinement output was observed for this execution.

## Interpretation

This establishes that the frozen BCF environment can load the Phase 3 XDP object.
This execution does not exercise BCF's proof-guided continuation path because the verifier completed the program without requiring a refinement proof.
Therefore this result is an applicability/control result, not a direct policy-verification comparison with KRAKENGUARD.

## Boundary

BCF execution does not establish compliance with the KRAKENGUARD helper policy P2.
The unauthorized-helper policy question remains specific to the higher-level policy-analysis layer.

## Status

BCF XDP applicability: experimentally validated.
BCF representative proof-path reproduction: previously validated with unreachable_arsh.
Direct BCF-vs-KRAKENGUARD policy comparison: not established.
