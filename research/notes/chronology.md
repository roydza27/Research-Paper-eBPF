# Chronological Timeline of Publications

This timeline traces the progression of software-based Linux eBPF security, isolation, verification and multi-tenancy research. The September 2026 additions below update the earlier historical record rather than replacing it.

## 2020

* *bpfbox: Simple Precise Process Confinement with eBPF* (ACM CCSW)
  * Early host confinement using eBPF/LSM policy.

## 2021

* *BPFContain: Fixing the Soft Underbelly of Container Security*
  * Container-aware eBPF/LSM confinement.

## 2023

* *Cross Container Attacks: The Bewildered eBPF on Clouds* (USENIX Security)
  * Demonstrates offensive eBPF attack paths across cloud/container boundaries.
* *Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing* (SandBPF)
  * Software-fault-isolation approach for safer unprivileged eBPF execution.

## 2024

* *Validating the eBPF Verifier via State Embedding* (OSDI)
  * Systematic verifier testing and state-based bug discovery.
* *The eBPF Runtime in the Linux Kernel*
  * Detailed analysis of the verifier/runtime safety model.
* *eBPF Security Threat Model*
  * Threat taxonomy for eBPF security.
* **BPF Token enters upstream development**
  * Delegated BPF operations tied to user-namespace-owned BPF filesystem instances.

## 2025

* *Prove It to the Kernel: Precise Extension Analysis via Proof-Guided Abstraction Refinement* (SOSP 2025)
  * Proof-guided verifier refinement; materially changes the old dynamic-verification gap.
* *Approximation Enforced Execution of Untrusted Linux Kernel Extensions* (USENIX Security 2025)
  * Runtime enforcement designed to reduce trust in verifier state approximation.
* *eBPF Misbehavior Detection: Fuzzing with a Specification-Based Oracle* (SOSP 2025)
  * Specification-based verifier fuzzing; reports 15 verifier bugs.
* **ePass research project**
  * Verifier-cooperative runtime transformation and enforcement.
* **SeaBee research/implementation**
  * Protects eBPF security tools from privileged policy/map tampering.

## 2026

* *KRAKENGUARD: Towards Fine-Grained eBPF Isolation* (NSDI 2026)
  * Fine-grained policy analysis for helper, memory, map and program interference; multi-tenant XDP use case.
  * Important unresolved issue: symbolic path/expression explosion; paper identifies hybrid abstract/symbolic analysis as future work.
* *Virtualizing eBPF with Late-Binding* (OSDI 2026)
  * Multi-tenant hook virtualization, tenant attribution and state isolation.
* *PeeR: First-Class Scheduling for Latency-Critical eBPF Applications* (OSDI 2026)
  * Preemptive/resource-aware execution model for latency-critical eBPF.
* **CVE-2026-63864**
  * Verifier-related Linux kernel security issue; reinforces that verifier correctness remains an active security problem.

## Research-state transition

```text
bpfbox/BPFContain
      ↓
attack discovery + SandBPF
      ↓
verifier testing / runtime analysis
      ↓
BCF + AEE + Veritas
      ↓
BPF Token + SeaBee
      ↓
KRAKENGUARD + vBPF + PeeR
      ↓
2026 opportunity: composition and scalable fine-grained policy verification
```
