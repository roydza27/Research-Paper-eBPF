# Linux Verifier Differential Control — Program E

Date: 2026-09-30
Object: e_adversarial_helper.o
Object SHA256: c7c7fb9cb9283a3bdd0430da10118ef187d78d9a91fb16d4bf16e0babf71095b

## Kernel verifier result

Program accepted by the Linux kernel BPF verifier.
Verification time: 227 usec
Instructions processed: 9
Total states: 1
Peak states: 1
BPF token creation returned -95 and was skipped as optional.

## Differential comparison

The same frozen program object was previously analyzed by KRAKENGUARD under p2-helper-only.json.
KRAKENGUARD recorded bpf_ktime_get_ns but, for the symbolic-return case, did not capture the return value and skipped conditional-policy evaluation.
The Linux verifier independently accepted the program as kernel-valid.

## Status

Control execution completed.
No kernel-verifier rejection was observed.
