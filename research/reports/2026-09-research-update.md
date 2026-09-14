# eBPF Multi-Tenant Security & Isolation — 2025–2026 Research Update

**Status:** research update / evidence-backed gap analysis  
**Date:** 2026-09  
**Baseline:** repository state at `f1fb18afa91909458b6e62831c451d2a28ecc001`  
**Scope:** software-only Linux/eBPF security, isolation, verification, containers and multi-tenancy

> This report updates the repository rather than replacing its historical literature. New claims are separated from the prior baseline and are marked as verified from primary papers, official kernel documentation, or official project repositories where possible.

## Executive Summary

The repository's original thesis direction was **eBPF-based multi-tenant container confinement and LSM policy enforcement**. That remains a legitimate problem, but several of the repository's strongest candidate gaps have materially changed since the 2024–2025 baseline.

The most important change is that the 2025–2026 literature now directly covers several previously proposed directions:

- **Fine-grained eBPF isolation:** KRAKENGUARD (NSDI 2026) provides load-time symbolic policy checking, helper/memory/map restrictions, cross-program interference analysis and an XDP-as-a-Service multi-tenant use case.
- **Native-ish multi-tenant virtualization:** vBPF (OSDI 2026) virtualizes eBPF hooks using late binding, tenant attribution, O(1) dispatch and compiler-assisted state isolation.
- **eBPF resource isolation:** PeeR (OSDI 2026) makes latency-critical eBPF preemptable and schedulable with explicit budgets.
- **Verifier-failure defense:** AEE (USENIX Security 2025) adds runtime approximation enforcement to reduce the verifier's trusted-code-base assumptions; ePass independently develops verifier-cooperative runtime enforcement.
- **Verifier precision:** BCF (SOSP 2025) uses proof-guided abstraction refinement to improve verifier precision while keeping complex reasoning in user space.
- **Verifier testing:** Veritas/SpecCheck (SOSP 2025) uses a specification-based oracle and reports 15 verifier bugs.
- **Delegation:** BPF Token is now an upstream kernel mechanism for delegated BPF operations within a user-namespace-bound BPF filesystem.
- **Policy/tool hardening:** SeaBee provides signed, access-controlled protection against privileged tampering with security-critical eBPF tools and their maps.

Therefore, the repository should **not** continue to treat "dynamic verifier", "BPF namespace", "generic verifier-independent isolation", or "basic cross-container detection" as untouched research gaps.

### Strongest current opportunity

The strongest Master's-scale direction identified in this update is:

> **Scalable policy verification for fine-grained eBPF isolation: combine the precision of symbolic execution with the scalability of abstract interpretation, then evaluate whether policy verification can remain practical for complex multi-tenant eBPF workloads.**

This is grounded in a concrete limitation stated by KRAKENGUARD itself: its symbolic execution can encounter path/expression explosion, while the authors explicitly identify hybrid abstract-interpretation/symbolic-execution techniques as future work. This is a more defensible research gap than simply proposing another namespace or LSM policy mechanism.

A second promising direction is **revocable, transactionally safe tenant delegation and object lifecycle isolation**, combining BPF Token, BPF-LSM, map/link lifecycle, identity-aware policy and policy rollback. Evidence is currently weaker for a claim of novelty, so it should be framed as an open systems problem rather than a guaranteed novel contribution.

A third direction is **security/resource isolation composition**, studying how tenant access control interacts with eBPF execution budgets and hook virtualization. vBPF and PeeR already solve major pieces separately, so a contribution must demonstrate a new invariant or measurable composition benefit rather than simply integrating the two.

---

## 1. Existing Research Baseline

The repository establishes the following research identity:

- Linux kernel security and cloud-native container isolation.
- Software-only confinement.
- eBPF verifier correctness/security.
- BPF maps and namespace-related isolation.
- BPF-LSM and dynamic policy enforcement.
- Kubernetes/Docker as evaluation environments.

The baseline literature is centered on bpfbox, BPFContain, Cross Container Attacks, SandBPF, State Embedding, the eBPF Runtime overview, the eBPF Security Threat Model and eBPF-PATROL.

The baseline research gaps were:

1. dynamic/incremental verification;
2. native BPF namespace isolation;
3. syscall-argument TOCTOU problems.

These remain useful historical hypotheses, but they are no longer sufficient as the primary 2026 thesis framing.

### Baseline assessment

| Baseline area | 2026 assessment |
|---|---|
| Verifier security | Still highly active; new bugs and new verification/testing approaches continue to appear. |
| Runtime SFI | Active, but substantially advanced by AEE/ePass and the isolated-execution research program. |
| Container isolation | Mature enough that a new generic BPF-LSM container policy engine is unlikely to be sufficiently novel. |
| BPF namespaces | The original motivation remains relevant, but BPF Token/user namespaces and vBPF change the design space. |
| BPFLSM | Production systems already perform workload-aware enforcement. |
| Runtime observability | Mature; Tetragon, KubeArmor, Tracee and similar systems should be treated as baselines, not novel contributions. |
| Multi-tenancy | Still open, but now includes access control, execution virtualization, state isolation and resource scheduling as separate dimensions. |

---

## 2. 2025–2026 Research Developments

### 2.1 BCF — proof-guided verifier refinement

**Paper:** Hao Sun and Zhendong Su, *Prove It to the Kernel: Precise Extension Analysis via Proof-Guided Abstraction Refinement*, SOSP 2025.

BCF moves expensive reasoning into user space. When the kernel verifier encounters an imprecision, it requests a refinement; user space generates a formal proof and the kernel performs a compact proof check. The published evaluation reports acceptance of 403/512 real-world programs that were previously rejected erroneously.

**Implication for this repository:** the old "dynamic/incremental verification" gap is no longer a clean blank space. The verifier itself now has a concrete proof-guided refinement direction and an open-source implementation.

Primary source: https://doi.org/10.1145/3731569.3764796
Artifact: https://github.com/SunHao-0/BCF

### 2.2 AEE — verifier-independent runtime defense

**Paper:** Hao Sun and Zhendong Su, *Approximation Enforced Execution of Untrusted Linux Kernel Extensions*, USENIX Security 2025.

AEE instruments execution so runtime behavior remains within the verifier's approximated state. It is explicitly designed to remain safe despite potential verifier soundness bugs. The paper reports a 4.5x trusted-code-base reduction, 1.2% average runtime overhead and 4.8% average binary-size increase for its prototype.

**Implication:** a thesis simply proposing "SFI as a second line of defense against verifier bugs" would substantially duplicate existing work.

Primary source: https://www.usenix.org/conference/usenixsecurity25/presentation/sun-hao

### 2.3 ePass — verifier-cooperative transformation

The eBPF Foundation's 2026 research update describes ePass as a user-space cooperative transformation framework. Its verifier remains the authority; a small kernel recorder exposes verifier information, while user-space transformation passes insert runtime checks or repair rejected programs. The 2026 update reports 14 passes and mitigation coverage for 19 analyzed 2020–2024 eBPF CVEs, with five public PoCs experimentally tested.

**Implication:** runtime enforcement and verifier cooperation are active research areas with substantial current work. A new project needs a clearly narrower invariant or new deployment problem.

Primary source: https://ebpf.foundation/research-update-verifier-cooperative-runtime-enforcement-for-ebpf/

### 2.4 Veritas / SpecCheck — specification-based verifier fuzzing

**Paper:** Tao Lyu et al., *eBPF Misbehavior Detection: Fuzzing with a Specification-Based Oracle*, SOSP 2025.

Veritas/SpecCheck encodes eBPF instruction semantics and safety properties as a specification and uses SMT reasoning as a fuzzing oracle. The published project reports 15 verifier bugs, including serious security bugs and usability bugs.

**Implication:** a generic "build an eBPF verifier fuzzer" thesis is not a strong new direction. A new testing contribution needs a new oracle, new coverage dimension, concurrency/lifecycle semantics, or a new security property.

Primary source: https://doi.org/10.1145/3731569.3764797
Artifact: https://github.com/rs3lab/veritas

### 2.5 KRAKENGUARD — fine-grained eBPF isolation

**Paper:** Jainil Patel et al., *KRAKENGUARD: Towards Fine-Grained eBPF Isolation*, NSDI 2026.

KRAKENGUARD addresses the coarse capability model by using symbolic execution to enforce policies over helper usage, memory access, return values and cross-program interference. It demonstrates multi-tenant XDP-as-a-Service on a shared host.

The paper's most useful research gap is not its headline mechanism but its **scalability limitation**: symbolic execution can experience path/expression explosion. The authors explicitly point to combining abstract interpretation with symbolic execution as future work and conservatively reject programs when analysis does not terminate within a time limit.

Primary source: https://www.usenix.org/conference/nsdi26/presentation/patel
Artifact organization: https://github.com/krakenguard-ebpf

### 2.6 vBPF — eBPF virtualization for multiple tenants

**Paper:** Jing Zhang et al., *Virtualizing eBPF with Late-Binding*, OSDI 2026.

vBPF identifies static binding of BPF programs to physical hooks as a root cause of multi-tenant contention. It introduces tenant attribution, O(1) dispatch and compiler-assisted state isolation. The implementation is based on Linux 6.12 and reports up to 3.9x lower lmbench latency and 29% higher PostgreSQL throughput than native contention in its evaluation.

**Implication:** "create an eBPF namespace/virtualization layer" is no longer a sufficiently novel thesis statement.

Primary source: https://www.usenix.org/conference/osdi26/presentation/zhang-jing
Artifact: https://github.com/vbpf-osdi-2026

### 2.7 PeeR — execution/resource isolation

**Paper:** Jeremy Carin et al., *PeeR: First-Class Scheduling for Latency-Critical eBPF Applications*, OSDI 2026.

PeeR introduces cooperative preemption at helper-call boundaries, budget checks, continuations and scheduling integration through sched_ext. It targets the resource-isolation problem caused by eBPF execution in non-preemptable contexts.

**Implication:** CPU/resource isolation is now a separate established axis of the multi-tenant problem. A thesis must not rediscover it as generic "eBPF resource isolation".

Primary source: https://www.usenix.org/conference/osdi26/presentation/carin
Artifact: https://github.com/hipersys-team/PeeR

### 2.8 BPF Token — delegated BPF permissions

BPF Token was introduced upstream to delegate selected BPF subsystem operations from a privileged process to trusted unprivileged processes in a user-namespace-bound BPF filesystem. Delegation can be constrained by BPF commands, map types, program types and attach types. The kernel associates a token with the owning user namespace of its BPF filesystem.

**Implication:** a thesis based on the premise that BPF permissions cannot be delegated into user namespaces is obsolete. The current question is how to compose delegation with stronger policy, revocation, object lifecycle and tenant isolation semantics.

Primary sources:
- https://docs.kernel.org/userspace-api/ebpf/syscall.html
- https://github.com/torvalds/linux/blob/master/kernel/bpf/token.c

### 2.9 SeaBee — protection of security-critical eBPF tools

SeaBee is an NSA open-source framework that protects eBPF security tools from privileged tampering. It uses policy-controlled access to BPF tools/maps, signed policy updates and BPF-LSM enforcement.

**Implication:** "privileged users can overwrite security-tool BPF maps" is now an implemented security problem with a concrete mitigation. Future work should study limitations, composition and measurable guarantees rather than rediscover the basic attack.

Primary source: https://github.com/NationalSecurityAgency/seabee

### 2.10 Current kernel security evolution

Current kernel documentation confirms BPF Token support and BPF-LSM hooks. The current Linux tree also contains BPF token self-tests and continuing verifier changes. A 2026 kernel CVE affecting `kernel/bpf/verifier.c` demonstrates that verifier correctness remains an active security concern.

Primary sources:
- https://docs.kernel.org/bpf/verifier.html
- https://docs.kernel.org/bpf/prog_lsm.html
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h
- https://lists.openwall.net/linux-cve-announce/2026/07/19/109

---

## 3. Updated State of the Art

The field is best understood as six distinct layers:

1. **Admission / delegation:** capabilities, BPF Token, signatures and LSM checks.
2. **Program safety:** verifier, BCF, formal verification, fuzzing and specification-based testing.
3. **Fine-grained authority:** KRAKENGUARD-style policy analysis over helpers, memory, maps and effects.
4. **Execution isolation:** AEE, ePass and isolated-execution/SFI approaches.
5. **Tenant virtualization:** vBPF and state-isolation mechanisms.
6. **Runtime/resource control:** BPF-LSM policy engines, Tetragon/KubeArmor, and PeeR-style scheduling.

The research challenge is increasingly **composition across layers**, not the invention of another isolated enforcement hook.

---

## 4. Literature Matrix

| Work | Year | Venue | Problem | Threat model | Technique | Isolation level | Enforcement | Container aware | Verifier dependency | Overhead/result | Main limitation |
|---|---:|---|---|---|---|---|---|---|---|---|---|
| bpfbox | 2020 | ACM CCSW | Process confinement | Host/process attacker | eBPF + LSM policy | Process | LSM | Limited | High | Policy enforcement | Early design |
| BPFContain | 2021 | arXiv/CCSW | Container escape/confinement | Container attacker | BPF-LSM/cgroup policy | Container | LSM | Yes | High | Policy enforcement | Not native namespace isolation |
| Cross Container Attacks | 2023 | USENIX Security | eBPF cloud/container attacks | Malicious container | Offensive analysis | Cross-container | Attack surface | Yes | Exploit dependent | Attack demonstrations | Defensive follow-up needed |
| SandBPF | 2023 | SIGCOMM workshop | Safe unprivileged BPF | Untrusted BPF | Post-JIT SFI | Program | Runtime | No | Reduced | Runtime masking | Scope/performance tradeoffs |
| State Embedding | 2024 | OSDI | Verifier bugs | Malicious BPF | State-embedding testing | Verifier | Testing | No | Direct | Bug discovery | Testing rather than isolation |
| eBPF Runtime | 2024 | arXiv | Runtime/verifier taxonomy | General | System analysis | N/A | N/A | N/A | Direct | Survey | Not a new mechanism |
| eBPF-PATROL | 2025 | arXiv | Runtime threat detection | Container attacker | eBPF monitoring/enforcement | Workload | Syscall/runtime | Yes | High | <2.5% reported | Research maturity/publication status |
| BCF | 2025 | SOSP | Verifier imprecision | Safe but complex BPF | Proof-guided refinement | Verifier | Load-time | No | Reuses verifier | 403/512 prior rejects accepted | Proof/toolchain complexity |
| AEE | 2025 | USENIX Security | Verifier soundness failures | Untrusted extension | Runtime approximation enforcement | Program | Runtime | General | Reduced trust | 1.2% avg overhead | Narrower safety scope |
| Veritas/SpecCheck | 2025 | SOSP | Verifier bugs | Malicious/buggy BPF | Specification oracle + fuzzing | Verifier | Testing | No | Tests verifier | 15 bugs reported | Fuzzing/oracle scope |
| BPF Token | 2024+ | Linux kernel | BPF delegation | Trusted delegated app | Userns-bound token | Permission | Syscall | Yes | Independent | Kernel feature | Trust establishment is external |
| SeaBee | 2025–26 | Open source | Privileged tampering | Privileged attacker | Signed policy + BPF-LSM | Tool/object | LSM | Indirect | High | Practical hardening | Active project; API evolving |
| KRAKENGUARD | 2026 | NSDI | Fine-grained BPF authority | Untrusted tenant | Symbolic policy analysis | Program/co-location | Loader | Yes | Uses accepted BPF | Multi-tenant XDP case | Symbolic path explosion |
| vBPF | 2026 | OSDI | Multi-tenant hook sharing | Multiple tenants | Late binding + state isolation | Tenant | Virtualization | Yes | Kernel BPF | 3.9x latency, 29% throughput improvements in reported cases | Custom kernel/runtime |
| PeeR | 2026 | OSDI | BPF resource contention | Co-located workloads | Preemption + scheduling | Resource | Runtime | General | Uses verifier boundaries | 3–19.8x p99 improvement reported | Runtime/kernel changes |

---

## 5. Technology / Implementation Landscape

### Kernel

- Linux BPF verifier: active, evolving and security-critical.
- BPF Token: available in modern kernels and associated with user namespaces/BPF FS.
- BPF-LSM: upstream mechanism for security hooks.
- BPF links and pinned objects: lifecycle and ownership remain important to policy design.

### Production systems

- **Tetragon:** Kubernetes-aware runtime observability and enforcement; tracing policies can be loaded/unloaded at runtime and are domain-sharded.
- **KubeArmor:** workload-aware runtime enforcement through AppArmor, SELinux or BPF-LSM; BPF maps organize policy by workload identity.
- **SeaBee:** protects eBPF security tools against privileged tampering.

### Research prototypes

- **KRAKENGUARD:** fine-grained symbolic policy analysis.
- **vBPF:** tenant virtualization and state isolation.
- **PeeR:** execution scheduling/resource isolation.
- **BCF:** proof-guided verifier refinement.
- **AEE/ePass:** verifier-resilient or verifier-cooperative runtime enforcement.
- **Veritas:** specification-based verifier fuzzing.

---

## 6. Research Gap Analysis

### Gap A — Scalable fine-grained policy verification

**Existing work:** KRAKENGUARD verifies helper usage, memory access, return behavior and interference using symbolic execution.

**What it solves:** fine-grained constraints beyond coarse CAP_BPF permissions.

**What it does not solve:** symbolic execution can encounter path/expression explosion. The paper reports a real case where analysis did not terminate within minutes and identifies hybrid abstract-interpretation/symbolic-execution techniques as future work.

**Why it matters:** without predictable analysis time, a fine-grained multi-tenant admission controller can become a deployment bottleneck or conservatively reject programs that would otherwise be safe.

**Research question:** Can an abstract-interpretation-guided symbolic policy checker preserve KRAKENGUARD-level policy precision while reducing path explosion and providing predictable analysis bounds?

**Hypothesis:** A staged analysis that uses inexpensive abstract summaries to prune/refine symbolic paths can reduce policy-checking time and memory substantially while preserving sound policy decisions.

**Possible contribution:** a hybrid checker or analysis pipeline, a benchmark corpus, and evidence about the security/precision/performance tradeoff.

**Evaluation:** KRAKENGUARD baseline; real-world XDP/security BPF programs; malicious/CVE programs; path count; solver time; peak memory; accepted/rejected programs; false accept/reject rate; analysis timeout rate.

**Novelty assessment:** **promising but not guaranteed novel.** KRAKENGUARD explicitly identifies this as future work; BCF already demonstrates proof-guided abstraction refinement in the verifier. The contribution must therefore be specifically about *policy-property checking*, not generic verifier refinement.

### Gap B — Revocable, tenant-scoped BPF delegation and object lifecycle

**Existing work:** BPF Token delegates selected operations; BPF-LSM can enforce policy; SeaBee protects security tools; KubeArmor/Tetragon provide workload-aware policy; vBPF provides tenant virtualization.

**What remains unclear:** there is no single, upstream, end-to-end semantic contract covering tenant creation, delegated BPF permissions, object ownership, map/link sharing, policy update, revocation and teardown across the full BPF object graph.

**Why it matters:** changing the authority of a tenant is not equivalent to proving that all previously created BPF objects, links, pins, map references and cached policy state have ceased to provide the old authority.

**Research question:** Can a tenant-scoped BPF control plane provide explicit, testable revocation semantics across delegated BPF objects and policy state?

**Hypothesis:** Capability epochs plus object ownership metadata and fail-closed teardown can bound the lifetime of revoked BPF authority without requiring a new BPF namespace.

**Evaluation:** create/update/revoke tenant lifecycle; pinned objects; inherited FDs; map references; links; concurrent policy events; container restart; node restart; Kubernetes churn. Measure revocation latency, stale-authority windows, CPU/memory overhead and failure behavior.

**Novelty assessment:** **evidence not sufficient for a strong novelty claim.** Treat as an exploratory systems gap until a dedicated prior-work search confirms the exact object-lifecycle semantics.

### Gap C — Security/resource isolation composition

**Existing work:** vBPF addresses tenant virtualization and state isolation; PeeR addresses CPU scheduling and execution budgets.

**What it does not establish:** a unified security model showing that a tenant's authorization policy and execution budget compose without allowing resource starvation, policy bypass, or interference during attachment/detachment and overload.

**Research question:** What security invariants are required when fine-grained BPF authorization, tenant virtualization and BPF execution scheduling are composed?

**Hypothesis:** Explicit per-tenant authority and resource contracts can prevent both unauthorized effects and resource starvation under adversarial co-location.

**Novelty assessment:** **partially explored.** A pure integration project is engineering; a new formal invariant plus measurable implementation/evaluation would be the research contribution.

---

## 7. Candidate Research Questions

1. Can symbolic policy analysis for eBPF isolation be made predictable using abstract interpretation without weakening security guarantees?
2. Can delegated BPF authority be revoked with a bounded stale-object window across maps, links, pins and policy state?
3. What invariants are required to compose BPF authorization with execution/resource scheduling?
4. Can BPF-LSM policy updates provide transaction-like consistency under concurrent security events?
5. Can runtime enforcement selectively protect only verifier-sensitive operations while minimizing overhead?

Questions 4 and 5 are useful secondary investigations but have stronger prior-art overlap and should not be the primary thesis unless experiments reveal a concrete missing guarantee.

---

## 8. Ten Candidate Directions — 2026 Reassessment

| Direction | 2026 status | Assessment | Master's fit |
|---|---|---|---|
| 1. Dynamic/incremental verification | Partially solved/active | BCF and ePass materially change the space | 5/10 |
| 2. Native eBPF namespace isolation | Partially addressed by token/userns/vBPF | Generic proposal is no longer novel | 4/10 |
| 3. Container-aware map/link isolation | Partially addressed by KRAKENGUARD, KubeArmor, SeaBee, vBPF | Need a sharper lifecycle problem | 6/10 |
| 4. TOCTOU-resistant enforcement | Established techniques and systems exist | Still useful as a narrow evaluation topic | 5/10 |
| 5. Fine-grained BPFLSM multi-tenant policy | Strong production/research coverage | Generic policy engine is insufficient | 3/10 |
| 6. Runtime defense against verifier failures | AEE/ePass/isolated-execution work | Too close to active published work | 3/10 |
| 7. Verifier-independent software isolation | Active and substantially explored | Need a new isolation invariant or optimization | 4/10 |
| 8. Capability-aware eBPF delegation | BPF Token exists upstream | Delegation alone is solved | 3/10 |
| 9. Dynamic policy updates with safety guarantees | Partially explored | Potentially viable if framed around revocation/consistency | 7/10 |
| 10. Cross-container attack detection/prevention | Mature production ecosystem | Generic detector is weak novelty | 3/10 |

**New Direction 11:** scalable hybrid policy verification for fine-grained eBPF isolation — **8.8/10 preliminary fit**.

---

## 9. Novelty Assessment

Do not claim that the selected direction has "never been researched".

The defensible claim is:

> The searched literature contains direct work on fine-grained eBPF isolation (KRAKENGUARD) and direct work on abstract interpretation/proof-guided verifier refinement (BCF), but I found no directly equivalent published system in the searched sources that specifically applies a hybrid abstract-interpretation/symbolic-execution strategy to KRAKENGUARD-style *security policy checking* for multi-tenant eBPF admission. KRAKENGUARD itself identifies hybrid analysis as a future scalability direction.

This is a **research opportunity**, not yet a proven publication-level novelty claim.

A formal novelty claim requires a deeper search of 2026 workshop/preprint literature immediately before thesis proposal submission.

---

## 10. Master's Feasibility Assessment

### Scoring model

Weights follow the repository task:

- Research novelty: 25%
- Technical significance: 20%
- Feasibility: 20%
- Experimental measurability: 15%
- Implementation accessibility: 10%
- Publication potential: 10%

| Direction | Novelty | Significance | Feasibility | Measurability | Access | Publication | Weighted score |
|---|---:|---:|---:|---:|---:|---:|---:|
| Hybrid policy verification | 9 | 9 | 7 | 9 | 7 | 9 | **8.55** |
| Revocable BPF delegation/object lifecycle | 8 | 9 | 7 | 9 | 8 | 8 | **8.15** |
| Security/resource isolation composition | 7 | 9 | 5 | 9 | 6 | 8 | **7.25** |
| Dynamic policy consistency | 6 | 8 | 8 | 9 | 9 | 7 | **7.55** |
| Runtime verifier defense | 3 | 9 | 5 | 9 | 5 | 5 | **5.70** |
| Native BPF namespace | 4 | 9 | 3 | 6 | 3 | 6 | **4.95** |

Scores are research-planning judgments, not empirical measurements.

---

## 11. Top 3 Recommended Research Directions

### #1 — Hybrid Fine-Grained eBPF Policy Verification

**Proposed title:** *Scalable Fine-Grained eBPF Isolation through Hybrid Abstract and Symbolic Policy Verification*

**Research question:** Can abstract-interpretation-guided symbolic execution provide KRAKENGUARD-level security policy precision with lower and more predictable analysis cost?

**Architecture:**

```text
Tenant BPF program
       |
       v
Kernel verifier
       |
       v
Policy admission controller
       |
       +--> abstract summary / cheap pruning
       |
       +--> symbolic policy analysis for unresolved paths
       |
       +--> cross-program effect summary
       |
       v
ALLOW / DENY / ANALYSIS-TIMEOUT
       |
       v
BPF hook attachment
```

**Components:** KRAKENGUARD artifact, SMT solver, abstract domain, policy language, benchmark corpus, loader/admission controller.

**Difficulty:** medium-high.

**Experiment:** compare vanilla KRAKENGUARD, symbolic-only, hybrid, and conservative fallback.

**Metrics:** analysis time, peak memory, solver calls, path count, timeout rate, policy precision, false accepts/rejects, program-load latency.

**Security tests:** helper restrictions, unauthorized map access, packet modification, malicious CVEs already supported by KRAKENGUARD, cross-program interference.

**Risk:** implementation may become too close to a compiler/SMT research project.

**Fallback:** implement a narrow hybrid path-pruning optimization for a selected policy class rather than a full replacement checker.

### #2 — Revocable Tenant BPF Delegation

**Proposed title:** *Revocation-Safe Delegated eBPF for Multi-Tenant Linux Workloads*

Focus on lifecycle semantics rather than inventing another namespace.

**Core contribution:** define and implement a tenant authority epoch that spans BPF Token delegation, object creation, map/link/pin ownership and policy state; prove experimentally how quickly revoked authority disappears.

**Risk:** novelty may be weaker than expected because production projects and recent research already address pieces of this problem.

**Fallback:** restrict scope to map/link/pin lifecycle under BPF Token + BPF-LSM.

### #3 — Composed Security and Resource Isolation

**Proposed title:** *Security-Aware Resource Isolation for Multi-Tenant eBPF Execution*

Combine the security authority model of KRAKENGUARD with the tenant virtualization/resource-control model of vBPF/PeeR.

**Core contribution:** demonstrate a concrete invariant such as: a tenant cannot exceed either its security authority or execution budget even when multiple tenants share the same physical hook and workload is adversarial.

**Risk:** requires kernel changes and a larger evaluation platform.

**Fallback:** build an experimental composition layer on one hook class (XDP or cgroup) rather than a general runtime.

---

## 12. Recommended Primary Research Direction

Select **Direction #1** for the next thesis-design phase.

The reason is not that it is guaranteed novel. The reason is that it sits at the intersection of:

- a newly demonstrated real deployment problem (fine-grained eBPF isolation);
- a concrete published scalability limitation (symbolic path explosion);
- mature theoretical tools (abstract interpretation);
- an existing artifact that can serve as a baseline;
- measurable security and performance properties;
- a Master's-sized implementation boundary.

It also avoids rebuilding an entire Linux security subsystem.

### Proposed thesis hypothesis

> A staged policy checker that combines inexpensive abstract interpretation with selective symbolic execution can preserve the security precision required for fine-grained eBPF isolation while reducing worst-case analysis cost and timeout frequency compared with symbolic-only checking.

### Important boundary

The thesis should **not** claim to improve the Linux verifier itself unless the implementation actually changes verifier behavior. The initial system should be a policy-analysis layer evaluated against the Linux verifier and KRAKENGUARD.

---

## 13. Proposed Experimental Methodology

### Environment

- Linux 6.12+ for compatibility with vBPF-era systems; test the newest stable kernel available at implementation time.
- x86-64 primary platform.
- LLVM/Clang + libbpf + bpftool.
- Docker/containerd for container tests.
- Kubernetes only after the single-node experiment is stable.
- KVM/QEMU for kernel-patched experiments if required.
- SMT solver used by the selected baseline.

### Baselines

1. Vanilla KRAKENGUARD symbolic analysis.
2. Proposed hybrid analyzer.
3. Conservative timeout/reject fallback.
4. Where relevant, BCF as a verifier-precision comparison, not a direct policy-checking baseline.
5. Production systems such as KubeArmor/Tetragon only for policy/deployment context, not as direct analyzer-performance baselines.

### Security experiments

- Unauthorized helper usage.
- Unauthorized map access.
- Invalid packet modification.
- Cross-program interference.
- Known vulnerable eBPF programs/CVEs used by KRAKENGUARD where reproducible.
- Container-to-host policy violations.

Do not invent exploits. Reproduce documented vulnerabilities or controlled policy-violation programs.

### Performance experiments

Measure:

- analysis latency;
- peak memory;
- number of symbolic paths;
- solver invocation count;
- timeout frequency;
- accepted safe programs;
- rejected unsafe programs;
- false accept/reject cases;
- load/attach latency;
- policy-check scalability as program size and branch count increase.

### Ablation study

- symbolic only;
- abstract only;
- hybrid with cheap pruning;
- hybrid with policy-aware refinement;
- hybrid without cross-program analysis.

---

## 14. Threat Model

Primary attacker:

- untrusted tenant capable of supplying eBPF bytecode;
- tenant may deliberately construct complex programs to trigger analysis worst cases;
- tenant may attempt to access unauthorized helpers/maps or interfere with another tenant's program;
- tenant does not initially possess kernel compromise.

Out of scope:

- physical attacks;
- TEEs/hardware memory isolation;
- hypervisor compromise;
- speculative side channels;
- full kernel compromise before policy admission.

---

## 15. What Should NOT Be Researched as the Primary Thesis

### Reject: generic BPF namespace proposal

Reason: BPF Token/user-namespace support and vBPF materially change the landscape; a generic namespace proposal risks duplicating recent work.

### Reject: generic BPF-LSM container policy engine

Reason: BPFContain, KubeArmor, Tetragon and related systems already cover this capability.

### Reject: generic verifier-independent SFI

Reason: SandBPF, AEE, ePass and the isolated-execution research program already cover the core concept.

### Reject: generic eBPF verifier fuzzer

Reason: State Embedding, Veritas/SpecCheck and other testing projects already provide strong baselines.

### Reject: BPF capability delegation alone

Reason: BPF Token is now an upstream kernel mechanism.

### Reject: cross-container attack detector alone

Reason: the ecosystem has moved from academic detection prototypes to production systems with Kubernetes-aware enforcement.

### Reject: hardware-assisted isolation

Reason: outside the established project scope and not necessary for the strongest software-only research question.

---

## 16. Updated Research Roadmap

```text
Existing repository literature
        |
        v
2025-2026 state of the art
        |
        +--> BCF / Veritas / AEE / ePass
        +--> BPF Token / SeaBee
        +--> KRAKENGUARD / vBPF / PeeR
        |
        v
Discard obsolete generic gaps
        |
        v
Focused remaining problems
        |
        +--> scalable policy verification  <--- PRIMARY
        +--> revocable delegation/lifecycle
        +--> security/resource composition
        |
        v
Select primary RQ
        |
        v
Reproduce KRAKENGUARD baseline
        |
        v
Build hybrid policy analyzer
        |
        v
Security + scalability evaluation
        |
        v
Threats to validity / novelty review
        |
        v
Thesis contribution
```

### Phase 1 — Baseline reproduction

- Obtain KRAKENGUARD artifact.
- Build supported environment.
- Reproduce at least a subset of its policy-analysis experiments.
- Record exact versions and deviations.

### Phase 2 — Workload corpus

- Collect representative XDP, TC, cgroup and security BPF programs.
- Separate benign, complex and malicious samples.
- Record program size, branches, loops, helpers, map usage and analysis time.

### Phase 3 — Hybrid analysis prototype

- Build an abstract summary pass.
- Use summaries to prune obviously equivalent/safe symbolic states.
- Fall back to symbolic execution for policy-relevant uncertainty.
- Preserve conservative behavior on timeout.

### Phase 4 — Evaluation

- Security correctness.
- Analysis scalability.
- Memory consumption.
- Load-time impact.
- Failure/timeout behavior.

### Phase 5 — Novelty re-check

Before thesis proposal/submission, repeat searches for 2026/2027 papers and artifacts. Novelty must be evaluated against the latest literature, not this report alone.

---

## 17. Repository Material to Preserve / Revise

### Preserve

- bpfbox/BPFContain historical material.
- Cross Container Attacks.
- SandBPF.
- State Embedding.
- eBPF Runtime and Threat Model.
- Existing chronology and citation relationships.

### Revise

- `research/notes/research_gaps.md`: mark original gaps as historical and link to the updated analysis.
- `research/docs/research-roadmap.md`: replace the old generic namespace/verifier plan with the staged 2026 roadmap.
- `MEMORY.md`: record that the thesis direction has moved from generic namespace/LSM design toward fine-grained policy verification.

### Add

- this report;
- 2026 literature metadata;
- candidate architecture document;
- updated gap document.

### Do not do yet

- Do not add unverified PDFs as if they were locally archived.
- Do not claim benchmark reproduction before running the artifact.
- Do not claim the proposed hybrid analyzer is novel until a final literature sweep.

---

## 18. Evidence Quality / Caveats

- Primary conference pages/papers were preferred for KRAKENGUARD, vBPF, PeeR, AEE and BCF.
- Official Linux documentation/source was used for BPF Token, verifier and BPF-LSM behavior.
- Official project repositories were used for implementation availability where possible.
- eBPF Foundation research updates were treated as research-project evidence rather than peer-reviewed papers.
- Current CVE information was treated as evidence that verifier security remains active, not as evidence for the proposed thesis itself.
- Some current implementation projects are actively evolving; version and API details must be re-checked before experimental reproduction.

Where the literature does not establish a direct equivalent, this report says **"evidence not sufficient for a strong novelty claim"** rather than asserting that no prior work exists.

---

## 19. References

1. Sun, H.; Su, Z. *Prove It to the Kernel: Precise Extension Analysis via Proof-Guided Abstraction Refinement.* SOSP 2025. https://doi.org/10.1145/3731569.3764796
2. Sun, H.; Su, Z. *Approximation Enforced Execution of Untrusted Linux Kernel Extensions.* USENIX Security 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/sun-hao
3. Lyu, T.; Dwivedi, K. K.; Bourgeat, T.; Payer, M.; Xu, M.; Kashyap, S. *eBPF Misbehavior Detection: Fuzzing with a Specification-Based Oracle.* SOSP 2025. https://doi.org/10.1145/3731569.3764797
4. Patel, J.; Buhl-Nielsen, L. G.; Ghosn, A.; Kogias, M. *KRAKENGUARD: Towards Fine-Grained eBPF Isolation.* NSDI 2026. https://www.usenix.org/conference/nsdi26/presentation/patel
5. Zhang, J.; Song, X.; Du, D.; Xia, Y.; Zang, B.; Chen, H. *Virtualizing eBPF with Late-Binding.* OSDI 2026. https://www.usenix.org/conference/osdi26/presentation/zhang-jing
6. Carin, J.; Holmes, B.; Wang, W.; Bhardwaj, A.; Ghobadi, M. *PeeR: First-Class Scheduling for Latency-Critical eBPF Applications.* OSDI 2026. https://www.usenix.org/conference/osdi26/presentation/carin
7. Linux kernel documentation. *eBPF syscall / BPF Token.* https://docs.kernel.org/userspace-api/ebpf/syscall.html
8. Linux kernel documentation. *eBPF verifier.* https://docs.kernel.org/bpf/verifier.html
9. Linux kernel documentation. *LSM BPF Programs.* https://docs.kernel.org/bpf/prog_lsm.html
10. National Security Agency. *SeaBee.* https://github.com/NationalSecurityAgency/seabee
11. eBPF Foundation. *Research Update: Verifier-Cooperative Runtime Enforcement for eBPF.* https://ebpf.foundation/research-update-verifier-cooperative-runtime-enforcement-for-ebpf/
12. eBPF Foundation. *Research Update: Isolated Execution Environment for eBPF.* https://ebpf.foundation/research-update-isolated-execution-environment-for-ebpf/
13. Cilium. *Tetragon.* https://tetragon.io/docs/
14. KubeArmor. *KubeArmor documentation.* https://docs.kubearmor.io/kubearmor
15. Linux CVE announcement. *CVE-2026-63864: bpf: Propagate error from visit_tailcall_insn.* https://lists.openwall.net/linux-cve-announce/2026/07/19/109

---

## 20. Final Conclusion

The research problem remains valuable, but the thesis must move from **"eBPF needs isolation"** to a precise unanswered systems question.

The strongest defensible next step is to reproduce KRAKENGUARD, characterize its policy-analysis scalability, and investigate whether hybrid abstract interpretation can make fine-grained eBPF isolation practical without weakening its security decision.

That direction preserves the repository's software-only multi-tenant security identity while incorporating the major 2025–2026 advances instead of repeating them.
