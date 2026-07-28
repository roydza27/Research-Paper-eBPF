# Research Gaps Candidates: eBPF in Multi-Tenant Environments

This document tracks identified recurring open problems and challenges in Linux-based eBPF systems security.

---

## Gap 1: Safe Verification of Dynamic, Runtime-Generated eBPF Code
* **Problem:** Currently, BPF verification is a *one-shot, load-time* process. If a cloud application needs to update policies, it must unload and reload programs, which introduces performance hiccups and verifier workload peaks.
* **Open Queries:** How can we construct a JIT-compiler runtime that dynamically verifies small delta policy changes in-kernel without full program re-auditing?
* **Research Priority:** High
* **References:** Validating the eBPF Verifier (OSDI '24), The eBPF Runtime in the Linux Kernel (2024).

## Gap 2: eBPF Namespace Isolation (BPF-NS)
* **Problem:** In multi-tenant Kubernetes grids, BPF-Maps and BPF links reside in shared kernel spaces. A container with basic permissions can list maps, interfere with network rules, or eavesdrop. The Linux kernel misses namespace divisions (similar to MNT, PID, NET) for namespace-aware BPF isolation.
* **Current Solutions:** BPFContain attempts to hook BPF link generation via LSM to check calling container namespaces, but this is a policy patch rather than a kernel native separation.
* **Gaps:** Native kernel implementation of BPF namespaces to cleanly isolate maps.
* **References:** BPFContain (2021), Cross Container Attacks (USENIX Security '23).

## Gap 3: Time-of-Check to Time-of-Use (TOCTOU) in Helper Call Probes
* **Problem:** When eBPF security tools monitor system call arguments (e.g. file paths in `execve`), it reads pointers from user space memory. A concurrent process can swap this memory after eBPF reads it but before the system call consumes it, bypassing security policies.
* **Gaps:** Complete containment of volatile registers and user memory mapping checks inside the BPF helper framework without affecting page tables.
* **References:** eBPF-PATROL (2025).