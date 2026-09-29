# BCF Representative Reproduction

## Status

EXECUTED AND LOCALLY VALIDATED

## Repository

BCF upstream: SunHao-0/BCF

Frozen commit:
821ecc14809648cbf0a7866668bb0f776d77e779

## Host

Architecture: x86_64
QEMU/KVM: used
virtiofsd: used
Host VM memory setting: VM_MEM=2G
Guest observed memory: approximately 1.5 GiB
Guest CPUs: 12

## Guest

Kernel:
6.18.0-rc4-g126a57df1519

BCF-enabled bpftool:
v7.7.0

libbpf:
v1.7

cvc5:
1.3.1-dev.80.383808e59

## Program

examples/unreachable_arsh.bpf.o

## Execution

BCF bpftool was executed from:
/root/bcf

Command:

~/bpftool -d -P /usr/bin/cvc5 \
  prog load ./examples/unreachable_arsh.bpf.o \
  /sys/fs/bpf/bcf-example

## Observed Evidence

- BCF selected /usr/bin/cvc5 as prover.
- Path-condition query returned unsat.
- Proof generated: 715 steps, 17244 bytes.
- BCF proof checker accepted the proof.
- Kernel verifier continued after refinement.
- Verification time reported: 35010 usec.
- Processed instructions: 10.
- Total states: 1.
- Program was pinned at /sys/fs/bpf/bcf-example.

## Non-failure observations

The log contains an optional BPF-token creation attempt returning -95 and being skipped. This did not prevent the BCF verification flow from continuing.

## Evidence Artifact

output/bcf-unreachable-arsh-20260929.log

## Interpretation Boundary

This is one representative local BCF reproduction. It demonstrates the observed proof-guided refinement/proof-checking path for this example.

It does not establish general BCF performance, correctness across workloads, or superiority over KRAKENGUARD.

## Research Role

Secondary baseline / comparison evidence.

BCF is not being expanded into a large independent benchmark under the reduced time-constrained research scope.
