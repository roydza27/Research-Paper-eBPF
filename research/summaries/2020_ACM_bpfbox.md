# Paper Summary: bpfbox: Simple Precise Process Confinement with eBPF

## Metadata
* **Title:** bpfbox: Simple Precise Process Confinement with eBPF
* **Authors:** William Findlay, Anil Somayaji, David Barrera
* **Year:** 2020
* **Venue:** ACM CCSW
* **URL:** https://arxiv.org/abs/2009.09635
* **Relevance Score:** 8.5/10
* **Tags:** eBPF, Runtime Security, Process Confinement, LSM, Linux

## Summary

### Research Problem
Traditional process confinement frameworks on Linux (SELinux, AppArmor, seccomp) are complex and inflexible. They are built around static unix DAC or primitive virtualizations (namespaces, mount namespaces), making them difficult to customize dynamically or to trace fine-grained kernel hook paths accurately.

### Motivation
Cloud infrastructure and host containers require security enforcement policies that are container-aware and lightweight. There is a need for fine-grained process confinement that covers userspace functions, syscalls, and LSM callbacks dynamically without the administrative configuration sprawl of SELinux policies or the coarse-grained system filters of seccomp.

### Proposed Solution
The authors propose **bpfbox**, a lightweight, eBPF-driven process confinement engine (~2k LoC of kernelspace code) that integrates with Linux Security Module (LSM) hooks and uses a clean policy compilation framework to enforce runtime execution parameters.

### Methodology
* **Kernel hook integration:** Enforces policies using eBPF programs attached directly to KRSI / BPFLSM helper locations.
* **State lookup:** Leverages eBPF BPF-Maps to store dynamic rule sets on allowed file paths, networking parameters, and processes.
* **Context verification:** Confines processes at the boundary of system calls, LSM hooks, and user-space libraries by tracking origin execution symbols inside BPF metadata lookup tables. 

### Experimental Setup
* Evaluated against standard host isolation utilities.
* Evaluated throughput and connection latency impacts using Apache and Netperf stress tests on a standard Linux distribution.
* Implemented policies confining an Nginx web-daemon container instance.

### Results
* Slows down web servers by around 8.4% when inspecting all process operations, which is comparable to or slightly lower than AppArmor's overhead.
* The kernel component occupies under 2,000 lines of safe code, dramatically lowering host attack surface compared to standard kernel modules.

### Limitations
* Does not secure the eBPF runtime environment itself: if the verifier is compromised, bpfbox's own BPF code could be bypassed or altered.
* Policy compilation lacks standard package management for distributed deployment setups.

### Future Work
* Extend the bpfbox architecture to natively recognize container namespace boundaries (leads to BPFContain).
* Improve rule resolution rates inside BPF-Maps.