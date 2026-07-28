# Paper Summary: eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation

## Metadata
* **Title:** eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation using eBPF in Containerized and Virtualized Environments
* **Authors:** Sangam Ghimire, Nirjal Bhurtel, Roshan Sahani, Sudan Jha
* **Year:** 2025
* **Venue:** arXiv Preprint
* **URL:** https://arxiv.org/abs/2511.18155
* **Relevance Score:** 8.0/10
* **Tags:** eBPF, Runtime Security, Kubernetes, Containers, Cloud, Observability

## Summary

### Research Problem
Traditional container monitor tools (like seccomp filters or syscall listeners) fall short in cloud-native Kubernetes grids because they lack runtime context-awareness. They cannot inspect syscall arguments dynamically, resolve PID spaces, or adapt policies at runtime, making it difficult to stop sophisticated exploits like reverse shells and container jailbreaks.

### Motivation
Multi-tenant Kubernetes clusters require runtime security monitoring that can identify overreach violations (e.g., accessing unauthorized kernel directories/pids) with minimal memory footprint and host CPU overhead under high workload densities.

### Proposed Solution
The authors propose **eBPF-PATROL**, an extensible, lightweight runtime security agent that intercepts system calls and applies context-aware user-defined policies.

### Methodology
* **Syscall Interception:** Attaches eBPF krprobes/tracepoints to sensitive syscall entries (e.g., `execve`, `pwrite`, `chroot`).
* **Context Resolution:** Reconstructs container names, namespaces, and userspace arguments in kernelspace before policy matching.
* **Dynamic Ring Buffers:** Signals security alerts to a user-space daemon using low-overhead BPF ring buffers.

### Experimental Setup
* Tested on a Kubernetes node running containerized services.
* Evaluated against real exploit scripts (reverse shells, privilege escalations, and namespace breakouts).

### Results
* Successfully intercepted and blocked targeted container escapes.
* Maintained very low CPU overhead (<2.5%) during active threat tracking.

### Limitations
* Policies must be predefined: it cannot detect zero-day attacks without custom signatures.
* Intercepting syscall arguments is prone to TOCTOU attacks if memory buffers are altered post-inspection but pre-syscall completion.

### Future Work
* Integrating distributed monitoring grids across large-scale Kubernetes topologies.