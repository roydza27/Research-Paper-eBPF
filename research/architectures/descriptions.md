# System Architectures of eBPF Isolation

This document outlines standard architectural design layouts for isolating tenant eBPF programs.

## Layout 1: Software Fault Isolation (SFI) via Binary Rewriting
```
                  ┌──────────────────────┐
                  │ Userspace: BPF Code  │
                  └──────────┬───────────┘
                             │ Load syscall
                             ▼
                  ┌──────────────────────┐
                  │ Kernel: JIT Compiler │
                  └──────────┬───────────┘
                             │ Native instructions
                             ▼
    ┌──────────────────────────────────────────────────┐
    │ SandBPF Rewriter                                 │
    │  - Inspect instruction list                      │
    │  - Insert masking logic (LD/ST operands)         │
    │  - Replace calls: call -> call trampoline        │
    └────────────────────────┬─────────────────────────┘
                             │
                             ▼
                      [Execution Run]
```

## Layout 2: Hardware-Assisted Partitioning (HIVE)
* **Design:**
  * Runs BPF execution under normal EL1 mode but marks the BPF program pages as "user page permissions".
  * Emits special unprivileged instructions `LDTR`/`STTR` to access dedicated BPF Space.
  * Exploits ARM PAC to seal kernel callback points, verifying integrity via cryptography keys.
