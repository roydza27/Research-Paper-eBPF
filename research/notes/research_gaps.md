# Research Gaps: eBPF Securing in Multi-Tenant Environments

This document tracks identified open research gaps in the literature.

## Gap 1: CPU Architecture Portability of Hardware-Assisted eBPF Isolation (MTE vs MPK)
* **Problem:** HIVE and SafeBPF target ARM's MTE and PAC. Currently, x86_64 has no exact equal, meaning these hardware isolation models are locked to ARM architectures.
* **Existing Solutions:** Software Fault Isolation (slow, ~10% overhead) or ARM MTE/PAC. Intel MPK (Memory Protection Keys) has been used in other contexts but not extensively explored for dynamic eBPF context switches.
* **Limitations:** CPU-dependent instructions prevent standard cloud deployments (which typically run mixed x86_64 nodes).
* **Open Questions:** Can Intel MPK or AMD equivalent features (like SEV, or Page Table Isolation) achieve under 5% overhead for eBPF JIT runtime isolation?
* **Difficulty:** Medium-High (requires kernel changes on x86_64 page tables).

## Gap 2: Fine-Grained Multitenancy in Shared eBPF Maps
* **Problem:** Tenant BPF programs share the same system memory or map structures. A malicious tenant could read/write to a shared map of another tenant.
* **Existing Solutions:** Isolating BPF programs into separate processes (bpfbox), but maps are globally registered in BPF filesystem pin paths.
* **Limitations:** The kernel lacks namespace isolation for the BPF directory or maps natively until recently.
* **Opportunity:** Proposing a namespaces isolation model for eBPF objects (BPF-NS) that mirrors pid/net namespaces.
* **References:** LF eBPF Threat Model (Recommendation on Map namespacing).

## Gap 3: Concurrency Bypasses of Static Verifiers (Time-of-Check to Time-of-Use - TOCTOU)
* **Problem:** Verifiers audit the code blocks at compile/load time, but during host runtime, concurrent kernel-context modification of double-checked pointers can lead to policy bypasses.
* **Existing Solution:** Static bounds checks or copying volatile memory fields.
* **Limitations:** Copy overhead is high for large telemetry context structs.
* **References:** Validating the eBPF Verifier (USENIX OSDI '24).
