# eBPF-Based Multi-Tenant Cloud Security Research Workspace

> **Research Workspace for Master's Thesis and Cloud-Native Kernel Protection Systems**

---

## 1. Project Overview & Motivation

This repository is the central research workspace for **eBPF-Based Multi-Tenant Cloud Security**. eBPF enables programmable kernel extensions for networking, tracing, observability and security, but multi-tenant use introduces a broader problem than simple verifier safety: tenants may require different authorities, kernel hooks, object state and resource budgets while sharing one Linux kernel.

The project remains focused on **software-only Linux security** and deliberately excludes hardware enclaves, speculative side channels and hypervisor security.

---

## 2. Research Problem & Scope

The historical project framing focused on container confinement, BPF-LSM policy and eBPF verifier correctness. The September 2026 research update refines the question:

> **Can fine-grained eBPF isolation policies be checked with predictable cost by combining inexpensive abstract analysis with selective symbolic execution?**

This direction is grounded in the 2026 KRAKENGUARD result and its stated symbolic-analysis scalability limitation.

### Scope

* **IN-SCOPE:** Linux kernel security, eBPF verifier behavior, fine-grained BPF policy analysis, BPF-LSM, container/multi-tenant isolation, software-only enforcement, reproducible performance/security experiments.
* **OUT-OF-SCOPE:** TEEs, SGX, SEV, TrustZone, MTE/PAC/MPK, microarchitectural side channels, hypervisor security, secure boot and hardware security.

---

## 3. Current State of the Research

The 2025–2026 literature materially changes several earlier assumptions:

* **BCF:** proof-guided verifier refinement.
* **AEE:** verifier-resilient runtime enforcement.
* **Veritas/SpecCheck:** specification-based verifier fuzzing.
* **BPF Token:** delegated BPF operations in user-namespace-bound BPF filesystems.
* **SeaBee:** protection of security-critical eBPF tools against privileged tampering.
* **KRAKENGUARD:** fine-grained eBPF policy analysis and cross-program interference checks.
* **vBPF:** multi-tenant eBPF virtualization and state isolation.
* **PeeR:** eBPF execution scheduling/resource isolation.

Therefore, generic proposals for "BPF namespaces", "another BPF-LSM policy engine", "generic verifier-independent SFI" or "generic cross-container detection" are no longer strong primary research directions.

See [`research/reports/2026-09-research-update.md`](research/reports/2026-09-research-update.md) for the complete evidence-based analysis.

---

## 4. Primary 2026 Research Direction

### Scalable Fine-Grained eBPF Policy Verification

**Working title:** *Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification*

The proposed system keeps the Linux verifier as the safety gate and adds a fine-grained security-policy analysis layer. Abstract analysis should cheaply summarize/prune policy-irrelevant paths; symbolic execution should handle only unresolved policy-relevant cases.

The immediate goal is **not** to claim a new verifier or a new BPF namespace. The first milestone is to reproduce KRAKENGUARD and measure its scalability before designing the hybrid analysis.

---

## 5. Research Artifacts

```text
research/
├── reports/
│   └── 2026-09-research-update.md
├── metadata/
│   └── 2026-papers.csv
├── notes/
│   ├── research_gaps.md                 # historical baseline + status
│   ├── updated-research-gaps.md         # current gaps
│   └── chronology.md                    # extended through 2026
├── architectures/
│   ├── descriptions.md                  # historical architectures
│   └── candidate-directions.md           # 2026 candidate designs
└── docs/
    └── research-roadmap.md               # updated thesis roadmap
```

---

## 6. Technology Stack

* **Host:** Linux; use a modern stable kernel appropriate for the reproduced artifact.
* **eBPF tooling:** libbpf, bpftool, LLVM/Clang.
* **Container tooling:** Docker/containerd; Kubernetes only after single-node experiments are stable.
* **Analysis:** SMT solver(s) required by the selected baseline plus the proposed abstract-analysis component.
* **Implementation:** C/C++/Rust as required by the baseline artifact; do not force Aya where the research mechanism requires direct integration with existing analyzers.

---

## 7. Research Workflow

```text
[Primary paper / official kernel source]
        ↓
[Verify metadata + threat model + results]
        ↓
[Compare with repository baseline]
        ↓
[Classify solved / partial / open]
        ↓
[Reproduce baseline where possible]
        ↓
[Define precise research question]
        ↓
[Prototype]
        ↓
[Security + performance evaluation]
        ↓
[Final novelty sweep]
```

---

## 8. Current Milestones

* [x] Repository structure audit/refactor.
* [x] Original software-only literature baseline.
* [x] 2025–2026 state-of-the-art update.
* [x] Reassessment of the original research gaps.
* [x] Primary/fallback research directions identified.
* [ ] Reproduce KRAKENGUARD.
* [ ] Build benchmark corpus.
* [ ] Prototype hybrid policy analysis.
* [ ] Security evaluation.
* [ ] Performance/scalability evaluation.
* [ ] Final novelty review.

---

## 9. Research Discipline

* Prefer original peer-reviewed papers and official kernel/project sources.
* Do not manufacture benchmark numbers, vulnerabilities, CVEs or novelty claims.
* Distinguish academic research, current kernel engineering and production security practice.
* Preserve historical research even when conclusions change.
* Treat "evidence not verified" explicitly when primary evidence is unavailable.

---

## 10. Key References

* KRAKENGUARD — https://www.usenix.org/conference/nsdi26/presentation/patel
* vBPF — https://www.usenix.org/conference/osdi26/presentation/zhang-jing
* PeeR — https://www.usenix.org/conference/osdi26/presentation/carin
* BCF — https://doi.org/10.1145/3731569.3764796
* AEE — https://www.usenix.org/conference/usenixsecurity25/presentation/sun-hao
* BPF Token — https://docs.kernel.org/userspace-api/ebpf/syscall.html
* SeaBee — https://github.com/NationalSecurityAgency/seabee

---

## 11. License & Guidelines

Contributions to this workspace follow standard academic publishing guidelines. All source code is restricted to GPLv2 licensing.
