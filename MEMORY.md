# Project Memory Log (MEMORY.md)

> Persistent project context for AI agents and researchers.

---

## 1. Research Identity

* **Research Title:** Scalable Fine-Grained eBPF Isolation and Multi-Tenant Policy Verification
* **Research Domain:** Linux Kernel Security, eBPF, Container Virtualization, Cloud-Native Systems
* **Research Focus:** Fine-grained security policies for untrusted or multi-tenant eBPF programs, with emphasis on scalable policy analysis and software-only isolation.
* **Research Objective:** Determine whether hybrid abstract-interpretation and symbolic-execution techniques can make fine-grained eBPF isolation practical without weakening conservative security decisions.
* **Historical Direction:** eBPF-based multi-tenant container confinement and BPF-LSM policy enforcement.
* **2026 Direction:** Move from a generic "BPF namespace / dynamic LSM" proposal toward a narrowly testable policy-verification problem grounded in KRAKENGUARD's published scalability limitation.

---

## 2. Research Constraints

### In scope

* Linux kernel security.
* eBPF verifier and policy analysis.
* BPF-LSM and fine-grained security policy.
* Container/multi-tenant workload identity.
* Software-only isolation and analysis.
* Reproducible Linux experiments.

### Out of scope

* Hardware-assisted isolation: TEEs, SGX, SEV, TrustZone, MTE/PAC/MPK.
* Hypervisor or microkernel security.
* Speculative side-channel research.
* Generic observability-only systems.
* Generic BPF namespace proposals without a concrete unresolved property.

---

## 3. 2025–2026 State-of-the-Art Anchors

* **BCF (SOSP 2025):** proof-guided abstraction refinement for verifier precision.
* **AEE (USENIX Security 2025):** runtime approximation enforcement to reduce verifier trust assumptions.
* **Veritas/SpecCheck (SOSP 2025):** specification-based verifier fuzzing.
* **BPF Token:** upstream delegated BPF operations within user-namespace-bound BPF FS.
* **SeaBee:** protection of eBPF security tools from privileged tampering.
* **KRAKENGUARD (NSDI 2026):** fine-grained eBPF policy analysis and cross-program interference checking.
* **vBPF (OSDI 2026):** multi-tenant eBPF virtualization and state isolation.
* **PeeR (OSDI 2026):** execution scheduling and resource isolation for eBPF.

---

## 4. Current Research Questions

1. Can abstract-interpretation-guided symbolic execution reduce KRAKENGUARD-style policy-analysis path explosion while preserving security decisions?
2. Can delegated BPF authority be revoked with bounded stale-object lifetime across maps, links, pins and policy state?
3. What security invariant is required when fine-grained authorization and eBPF execution/resource isolation are composed?

Primary question: **#1**.

---

## 5. Current Gaps

### Primary

**Scalable fine-grained policy verification.** KRAKENGUARD's symbolic analysis can encounter path/expression explosion; its paper identifies hybrid abstract interpretation + symbolic execution as future work.

### Secondary

**Revocable tenant delegation/object lifecycle.** BPF Token, BPF-LSM and existing policy systems cover pieces, but an end-to-end revocation contract across the BPF object graph remains to be investigated.

**Security/resource composition.** vBPF and PeeR cover separate dimensions; a meaningful thesis contribution would require a new invariant, not a simple integration.

---

## 6. Important Research Discipline

* Do not claim generic dynamic verification is an untouched gap.
* Do not claim BPF namespaces are unsolved without discussing BPF Token and vBPF.
* Do not claim generic verifier-independent isolation is novel; compare against AEE/ePass/SandBPF.
* Do not claim generic BPF-LSM container enforcement is novel; compare against BPFContain, KubeArmor and Tetragon.
* Do not manufacture CVEs, benchmark numbers or novelty claims.
* Re-check 2026/2027 literature immediately before thesis proposal/submission.
