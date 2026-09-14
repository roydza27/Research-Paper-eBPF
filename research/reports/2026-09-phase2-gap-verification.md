# Phase 2 — eBPF Research Gap Verification

> Status: literature and implementation verification completed for the Phase 2 claims. Experimental reproduction is still required before treating any surviving direction as validated.

## 1. Executive Summary

This report tests, rather than assumes, the repository's current Phase 2 conclusions about dynamic verification, BPF namespaces/object isolation, TOCTOU, and scalable fine-grained policy verification.

The main result is that the original broad gaps are no longer defensible as broad thesis statements. Recent work materially changes the boundary:

- **Dynamic/incremental verification:** partially addressed by proof-guided refinement (BCF), but this does not establish a general incremental policy-verification system. The remaining problem is better framed around policy-level deltas, compositionality, and cost guarantees rather than generic "dynamic verification".
- **BPF namespace:** substantially reframed, not solved by a native namespace abstraction. BPF Token provides capability delegation scoped through a BPF filesystem/user namespace, while vBPF virtualizes execution and late binding. Neither is equivalent to complete tenant-scoped lifecycle semantics for every BPF object and attachment.
- **TOCTOU:** generic race detection/enforcement is not an untouched gap. The remaining defensible question is narrower: whether policy decisions over mutable kernel/user objects can receive atomic or verifier-backed security guarantees for a specified threat model.
- **Fine-grained policy verification:** KRAKENGUARD is a major 2026 baseline and invalidates any claim that fine-grained helper/memory/map policy analysis is unexplored. A remaining research opportunity exists only if it is differentiated from KRAKENGUARD by a precise property such as analysis scalability, incremental updates, compositional reasoning, or stronger guarantees.
- **Verifier assurance:** BCF, AEE, and Veritas/SpecCheck make verifier precision and soundness an active, crowded research area. A new project should not simply build another symbolic verifier or another verifier fuzzer.
- **Resource isolation:** PeeR demonstrates that eBPF can bypass conventional scheduler/resource-control assumptions. This opens a different class of multi-tenant isolation questions around CPU/time budgets and policy composition.

The strongest defensible Master's boundary after this review is therefore not "invent fine-grained eBPF isolation." It is:

> **Can a tenant-scoped eBPF security policy be incrementally re-verified and enforced with bounded analysis cost while preserving explicit safety and isolation invariants across programs, maps, links, and delegated capabilities?**

This should remain a research hypothesis until KRAKENGUARD and BCF artifacts are reproduced and compared experimentally.

---

## 2. Existing Repository Baseline

The repository defines the research identity as eBPF-based multi-tenant container confinement and LSM policy enforcement, with Linux-kernel-only and software-only constraints. The existing roadmap moves from literature aggregation toward local verifier checks, BPF map namespace isolation, dynamic LSM confinement, and benchmarking.

The previous repository gap document identified three candidates: dynamic/runtime-generated eBPF verification, BPF namespace isolation, and syscall-argument TOCTOU. The previous roadmap subsequently acknowledged that the first two had been materially reframed by newer work and that generic TOCTOU was an established area.

This report preserves those terms and explicitly tests them instead of silently replacing them.

### Evidence boundary

Repository findings are treated as prior hypotheses. External primary-source findings are treated as new evidence. Where only an abstract, project page, or documentation page was available, this report does not claim full-paper verification.

---

## 3. Research Claims Being Tested

1. Can eBPF program/policy changes be verified incrementally without repeating expensive whole-program analysis?
2. Is a generic BPF namespace still an open systems problem after BPF Token and vBPF?
3. Is generic eBPF TOCTOU enforcement still an open problem?
4. Does fine-grained eBPF policy verification remain sufficiently open after KRAKENGUARD, BCF, AEE, Veritas/SpecCheck and related work?
5. Which remaining problem is technically precise, measurable, experimentally accessible, and distinct enough for a Master's thesis?

---

## 4. 2025–2026 Literature Update

### KRAKENGUARD — NSDI 2026

KRAKENGUARD is the critical baseline for this phase. It provides a trusted user-space manager for fine-grained, policy-driven eBPF bytecode constraints. Its symbolic execution checks program paths for helper usage, memory accesses, and return values; it also addresses safe delegation and cross-program interference, with an XDP-as-a-Service use case.

This directly invalidates the broad thesis claim that fine-grained helper/memory/map policy verification is missing.

Source: https://www.usenix.org/conference/nsdi26/presentation/patel

### BCF — eBPF Certificate Framework / SOSP 2025

BCF uses proof-guided abstraction refinement. The kernel performs lightweight tracking while user space supplies a refinement proof that is checked in the kernel. The design targets verifier precision while keeping kernel complexity bounded.

BCF is especially important because it attacks the same general precision/scalability boundary that a hybrid static/symbolic thesis would otherwise target.

Sources:
- https://github.com/SunHao-0/BCF
- https://www.spinics.net/lists/kernel/msg5914909.html

### AEE — USENIX Security 2025

Approximation-Enforced Execution reduces trust in the verifier by enforcing the verifier's approximations at runtime. Its prototype targets spatial memory safety and reports a 4.5x TCB reduction, 1.2% average runtime overhead, and 4.8% average binary-size increase.

AEE is not a policy-analysis framework equivalent to KRAKENGUARD, but it materially covers the alternative direction of compensating for verifier soundness failures through runtime enforcement.

Source: https://www.usenix.org/conference/usenixsecurity25/presentation/sun-hao

### Veritas / SpecCheck — SOSP 2025

Veritas combines fuzzing with SpecCheck, a specification-based oracle that encodes eBPF instruction semantics and safety properties and uses SMT reasoning to compare expected safety with Linux verifier decisions. The paper reports 15 new bugs, including security-impacting issues, with 12 acknowledged and eight fixed at the time of the paper.

This makes another generic "improve verifier testing with symbolic/specification analysis" contribution difficult to distinguish.

Sources:
- https://lvtao-sec.github.io/papers/Veritas.pdf
- https://github.com/rs3lab/veritas

### BPF Token — Linux 6.9+

BPF Token provides scoped delegation of BPF subsystem functionality to an unprivileged process. A token carries allowed commands, map types, program types, and attach types and is associated with the user namespace of the BPF filesystem from which it is derived.

The Linux implementation also exposes BPF-token-specific LSM hooks. This means capability delegation is now a first-class kernel mechanism rather than a purely external policy framework.

Sources:
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h
- https://github.com/torvalds/linux/blob/master/kernel/bpf/token.c

### vBPF — OSDI 2026

vBPF virtualizes eBPF execution using late binding. Its stated goal is multi-tenant execution by decoupling tenant context from physical kernel hooks and providing tenant attribution, scalable dispatch, and state isolation.

vBPF is therefore highly relevant to tenant isolation, but it should not be described as equivalent to a native Linux BPF namespace. It is a virtualization architecture with a different abstraction boundary.

Source: https://www.usenix.org/conference/osdi26/technical-sessions

### SeaBee

SeaBee addresses a different but important multi-tenant/security-control problem: privileged users can otherwise manipulate BPF maps and interfere with eBPF security tools. SeaBee adds policy-based access control to harden eBPF security tooling against such intervention.

Source: https://github.com/NationalSecurityAgency/seabee

### PeeR — OSDI 2026

PeeR makes latency-critical eBPF programs preemptable and schedulable, using helper-call boundaries as natural preemption points and integrating with kernel worker threads and sched_ext. Its motivation explicitly identifies eBPF execution as a resource-isolation problem because latency-critical hooks can otherwise run in non-preemptable contexts invisible to the scheduler.

PeeR does not solve security-policy verification, but it demonstrates that multi-tenant eBPF isolation must include resource semantics, not only authorization and memory safety.

Source: https://www.usenix.org/conference/osdi26/presentation/carin

---

## 5. Dynamic Verification Verdict

### Original Claim

Can eBPF security policies or program changes be verified incrementally without repeatedly performing expensive full-program analysis?

### Evidence Supporting It

BCF demonstrates on-demand refinement: the kernel can request additional reasoning from user space and validate a proof. This is materially different from blindly re-running a monolithic verifier.

### Evidence Against a Broad Gap

BCF already covers a major form of incremental/on-demand precision refinement. KRAKENGUARD also establishes a separate policy-analysis path. Therefore "incremental verification" by itself is not sufficient novelty.

### Current State

**PARTIALLY SOLVED / ACTIVE RESEARCH**

### Remaining Technical Problem

A narrower gap remains around **policy-delta verification**: when only a policy changes, can the system reuse prior program/security state and verify only affected policy constraints? This is not equivalent to BCF's abstraction refinement and should not be assumed to be solved by it.

Relevant cost dimensions include:

- affected-path discovery;
- solver state reuse;
- policy dependency graphs;
- cache invalidation;
- compositional guarantees;
- worst-case analysis time;
- behavior when the delta invalidates previously established assumptions.

### Research Question

Can policy-delta analysis reuse verified program/object state to reduce re-analysis cost while preserving the same security decision as full policy analysis?

### Feasibility

**Medium–High**, provided the scope is restricted to a small policy language and measurable kernel/eBPF object classes.

### Novelty Confidence

**Medium**, pending direct comparison against KRAKENGUARD and BCF artifacts.

---

## 6. BPF Namespace / Object Isolation Verdict

### Original Claim

The Linux kernel lacks a namespace boundary for BPF comparable to PID/NET/MNT namespaces.

### Evidence Supporting It

Linux still exposes BPF objects through a complex combination of file descriptors, bpffs pinning, references, maps, programs and links rather than a single general-purpose tenant namespace. BPF Token delegates capabilities but does not create a universal object-lifecycle namespace.

### Evidence Against the Broad Claim

BPF Token provides explicit delegation boundaries, and vBPF provides a tenant virtualization model with state isolation. These substantially weaken a generic "there is no isolation mechanism" claim.

### Current State

**SUBSTANTIALLY REFRAMED**

### Remaining Technical Problem

The defensible problem is:

> **tenant-scoped lifecycle and isolation semantics for BPF programs, maps, links, pins and delegated capabilities when references cross or outlive tenant boundaries.**

Linux already provides important lifetime mechanisms: file descriptors, links, references and explicit bind operations. The research question must therefore target cross-object policy semantics rather than inventing another namespace wrapper.

### Research Question

Can a tenant-scoped BPF object model guarantee that delegated programs, maps and links cannot outlive, escape, or acquire capabilities beyond the tenant policy that created them?

### Feasibility

**Medium**.

### Novelty Confidence

**Medium**, because vBPF, BPF Token and SeaBee create significant overlap.

---

## 7. TOCTOU Verdict

### Original Claim

Generic TOCTOU in eBPF monitoring/enforcement remains a major open gap.

### Evidence Supporting a Narrow Gap

Security decisions may depend on mutable objects, identities, paths, credentials, user memory, or process state. A monitoring agent that observes one state and enforces later can have a race window.

### Evidence Against the Broad Claim

TOCTOU is a long-established kernel/security problem and production eBPF systems already move enforcement into kernel hooks for many cases. Tetragon, for example, supports in-kernel filtering and enforcement and explicitly scopes policies to Kubernetes identities.

Source: https://tetragon.io/docs/getting-started/enforcement/

### Current State

**PARTIALLY SOLVED / ACTIVE RESEARCH**

### Remaining Technical Problem

A defensible eBPF-specific question would need a precise atomicity boundary, such as:

> Can a verifier-backed policy guarantee that a decision about a mutable object remains valid between observation and enforcement under a defined kernel concurrency model?

This is substantially narrower than "solve TOCTOU."

### Feasibility

**Medium–Low** for a Master's project unless the threat model is tightly constrained.

### Novelty Confidence

**Low–Medium** without a concrete invariant and proof model.

---

## 8. Fine-Grained Policy Verification Verdict

### Original Claim

Fine-grained eBPF policy verification is the primary open research opportunity.

### Evidence Supporting It

KRAKENGUARD demonstrates that fine-grained policy analysis is technically feasible but creates a new baseline whose scalability, policy expressiveness, and integration boundaries can be measured. It checks helper usage, memory accesses, return values, and cross-program interference.

### Evidence Against It

The central capability itself is no longer novel. BCF additionally provides proof-guided precision refinement, while AEE and Veritas/SpecCheck address other verifier-assurance dimensions.

### Current State

**ACTIVE RESEARCH**

### Remaining Technical Problem

The remaining problem must be expressed as a measurable systems limitation, not as a missing feature:

- analysis cost as program/path count grows;
- policy-state explosion;
- repeated analysis after policy changes;
- compositional verification across interacting programs/maps/links;
- predictable timeout/unknown behavior;
- policy expressiveness without sacrificing decidability or bounded cost.

### Research Question

Can a restricted fine-grained policy language be verified compositionally and incrementally with substantially lower analysis cost than whole-program symbolic execution while preserving equivalent security decisions?

### Feasibility

**Medium–High** if restricted to a policy language and a reproducible benchmark corpus.

### Novelty Confidence

**Medium**, and only after an artifact-level comparison with KRAKENGUARD.

---

## 9. KRAKENGUARD Deep Analysis

### What it solves

- Fine-grained helper restrictions.
- Memory-access restrictions.
- Map-access restrictions.
- Return-value restrictions.
- Safe delegation of program loading.
- Cross-program interference analysis.
- Multi-tenant XDP-as-a-Service use case.

### What it does not automatically establish

The public conference description does not establish a universal solution for:

- arbitrary dynamic policy deltas;
- all BPF object lifecycle transitions;
- all BPF program/link/map interactions across every program type;
- formal equivalence between policy revisions;
- bounded worst-case solver cost;
- scheduler/resource isolation;
- complete kernel-verifier correctness.

These are **open questions**, not claims that KRAKENGUARD fails.

### Scalability bottleneck

The architectural concern is symbolic path/state growth. The exact acceptable scaling boundary must be established from the paper's artifact and benchmark reproduction before making quantitative claims. This report therefore does not invent a speedup target or reproduce unpublished numbers.

### Reproducibility

KRAKENGUARD is a 2026 NSDI paper with a public conference page. Artifact availability and reproducibility should be checked directly before building a thesis dependency on its implementation.

### Thesis implication

A Master's project should **extend or experimentally challenge a specific KRAKENGUARD limitation**, not reimplement KRAKENGUARD under different names.

---

## 10. Linux Security Model Update

Current Linux BPF already provides several layers relevant to this research:

1. **Verifier:** validates control flow and tracks register/stack state across execution paths.
2. **Capabilities:** CAP_BPF and other capability checks divide privilege by BPF operation and subsystem requirements.
3. **BPF Token:** delegates selected BPF commands, map types, program types and attach types.
4. **User namespaces:** provide capability scopes used by BPF Token.
5. **BPF links:** represent attachment relationships and participate in object lifetime.
6. **BPF maps:** are reference-counted kernel objects accessible through FDs and, where pinned, filesystem paths.
7. **bpffs:** provides persistent/pinned object access and therefore becomes part of lifecycle/security policy.
8. **BPF LSM:** exposes security hooks around BPF operations and BPF-token operations.
9. **BPF signing:** current kernel documentation describes signed-program provenance as orthogonal to verifier/capability checks.

Primary sources:
- https://docs.kernel.org/bpf/verifier.html
- https://github.com/torvalds/linux/blob/master/kernel/bpf/token.c
- https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h
- https://www.kernel.org/doc/html/latest/bpf/signing.html

A new thesis must therefore demonstrate that its mechanism adds a security property not already guaranteed by some combination of these primitives.

---

## 11. Production-System Comparison

| System | Observation | Enforcement | Tenant identity | Main relevance | Gap implication |
|---|---|---|---|---|---|
| Tetragon | eBPF kernel events | In-kernel filtering + actions | Kubernetes-aware | Runtime policy enforcement | Invalidates broad "no kernel enforcement" claims |
| Cilium | Network/security telemetry | eBPF datapath/policy | Kubernetes/workload identity | Production-scale eBPF | Shows scalability requires specialized architecture |
| Falco | Runtime events | Detection/response | Container/process context | Mature security monitoring | TOCTOU/monitoring is established engineering area |
| Tracee | eBPF runtime tracing | Detection/response | Container/process context | Security observability | Reinforces mature runtime monitoring baseline |
| KubeArmor | LSM/eBPF policy | Workload policy enforcement | Kubernetes identity | Host/container controls | Generic container policy gap is not untouched |

The production systems do not invalidate research into verifier-level policy analysis, but they narrow the contribution: the research must improve a concrete analysis or guarantee rather than merely adding another runtime enforcement agent.

---

## 12. Gap Verification Matrix

| Candidate Gap | Older Work | 2024 Work | 2025 Work | 2026 Work | Current Status | Evidence |
|---|---|---|---|---|---|---|
| Dynamic verification | Runtime verification literature | eBPF runtime studies | BCF/AEE | KRAKENGUARD/vBPF | PARTIALLY SOLVED | BCF, AEE, KRAKENGUARD |
| BPF namespace | BPFContain / container work | BPF threat models | BPF Token | vBPF | SUBSTANTIALLY REFRAMED | Kernel + vBPF |
| BPF object isolation | FD/pinning mechanisms | threat-model work | SeaBee/BPF Token | vBPF | ACTIVE RESEARCH | Kernel object model + newer systems |
| TOCTOU | Established security problem | eBPF monitoring | runtime enforcement work | production systems | PARTIALLY SOLVED | Tetragon + prior literature |
| Fine-grained policy verification | Early isolation systems | verifier studies | BCF | KRAKENGUARD | ACTIVE RESEARCH | KRAKENGUARD |
| Symbolic scalability | symbolic/fuzzing work | state embedding | Veritas/SpecCheck | KRAKENGUARD | ACTIVE RESEARCH | Path/state complexity remains relevant |
| Dynamic policy verification | runtime policy systems | policy engines | BCF | KRAKENGUARD/vBPF | OPEN / UNCLEAR | Needs artifact-level comparison |
| Delegated BPF security | capability-based systems | CAP_BPF | BPF Token | vBPF/SeaBee | SUBSTANTIALLY SOLVED for core delegation | Linux BPF Token |
| Multi-tenant policy enforcement | BPFContain | container security systems | AEE/BCF | KRAKENGUARD/vBPF/PeeR | ACTIVE RESEARCH | Multiple independent dimensions remain |

---

## 13. Candidate Research Directions

### A — Scalable Fine-Grained eBPF Policy Verification

**Status:** ACTIVE RESEARCH

Potential contribution: benchmark and optimize analysis cost using a restricted policy language and state reuse.

Novelty: Medium.

Feasibility: High if scoped tightly.

### B — Hybrid Static + Symbolic eBPF Policy Analysis

**Status:** ACTIVE RESEARCH, but heavily overlaps KRAKENGUARD/BCF.

Potential contribution: only defensible if the hybrid decomposition yields a measurable and reproducible reduction in solver work without weakening the policy semantics.

Novelty: Low–Medium until demonstrated.

### C — Incremental / Delta-Based eBPF Policy Verification

**Status:** OPEN / UNCLEAR.

Potential contribution: dependency-aware policy delta analysis with cacheable verified state.

Novelty: Medium–High pending literature/artifact confirmation.

Feasibility: High if limited to one or two program types and a declarative policy subset.

### D — Tenant-Scoped BPF Object Lifecycle Isolation

**Status:** ACTIVE RESEARCH.

Potential contribution: formal lifecycle invariants over program/map/link/pin relationships.

Novelty: Medium.

Feasibility: Medium.

### E — Revocable BPF Capability Delegation

**Status:** SUBSTANTIALLY ADDRESSED at the basic delegation level by BPF Token.

Potential remaining contribution: revocation and transitive capability lifecycle semantics.

Novelty: Medium.

Feasibility: Medium.

### F — Verifier-Assisted Multi-Tenant eBPF Isolation

**Status:** ACTIVE RESEARCH but broad.

Potential contribution: composition of verifier guarantees, policy constraints, and tenant identity.

Novelty: Low–Medium unless narrowed.

### G — Policy-Aware BPF Map/Link Isolation

**Status:** ACTIVE RESEARCH.

Potential contribution: object graph policy that prevents unsafe cross-tenant references and lifecycle escape.

Novelty: Medium.

Feasibility: Medium.

### H — TOCTOU-Resistant Kernel-Resident eBPF Enforcement

**Status:** UNCLEAR / PARTIALLY SOLVED.

Potential contribution: formally specified atomic decision boundary for one concrete object/identity class.

Novelty: Medium only with a precise proof obligation.

Feasibility: Low–Medium.

---

## 14. Ranking

Weights: novelty 25%, significance 20%, Master's feasibility 20%, experimental measurability 15%, implementation accessibility 10%, publication potential 10%.

| Direction | Novelty | Significance | Feasibility | Measurement | Access | Publication | Weighted Score |
|---|---:|---:|---:|---:|---:|---:|---:|
| C — Incremental / Delta Verification | 8 | 8 | 8 | 9 | 8 | 8 | **8.15** |
| G — Policy-Aware Map/Link Isolation | 7 | 8 | 7 | 8 | 8 | 8 | **7.55** |
| A — Scalable Fine-Grained Policy Verification | 6 | 9 | 8 | 9 | 8 | 8 | **7.75** |
| D — Tenant-Scoped Object Lifecycle | 7 | 8 | 7 | 8 | 7 | 8 | **7.45** |
| B — Hybrid Static + Symbolic Analysis | 5 | 8 | 7 | 8 | 8 | 7 | **6.90** |
| E — Revocable Delegation | 6 | 8 | 6 | 7 | 7 | 7 | **6.75** |
| H — TOCTOU-Resistant Enforcement | 6 | 8 | 5 | 6 | 6 | 7 | **6.35** |
| F — Generic Verifier-Assisted Isolation | 4 | 9 | 6 | 7 | 7 | 7 | **6.25** |

These are **researcher scores**, not measured results. The ranking should be revisited after artifact reproduction.

---

## 15. Novelty Assessment

The current proposed thesis title, **Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification**, is too broad and overlaps materially with KRAKENGUARD and BCF.

It should not be used as the final thesis statement without narrowing.

A more defensible boundary is:

> **Incremental Policy Verification for Tenant-Scoped eBPF Security**

with the research question:

> **Can a policy-delta verifier reuse previously established eBPF security facts to reduce verification cost while preserving the security decision of full analysis for a defined tenant-policy model?**

This does not claim that the problem is proven novel. It identifies the smallest hypothesis that survives the current literature review.

---

## 16. Feasibility Assessment

A Master's implementation should avoid modifying the full Linux verifier initially.

Recommended prototype boundary:

1. Define a restricted policy language over helper calls, map access, selected memory effects, and selected attach types.
2. Build a reference whole-program policy checker.
3. Build a dependency graph connecting policy predicates to program/object state.
4. Implement policy-delta invalidation and state reuse.
5. Compare full verification against delta verification.
6. Measure analysis latency, solver calls, memory, false accept/reject decisions, and timeout/unknown behavior.
7. Only then consider kernel integration.

This produces a publishable experimental question even if the final result is negative.

---

## 17. ProcessScope Relevance

ProcessScope should **not automatically become the thesis**.

The most useful role is an **evaluation harness/supporting component** if it already exposes:

- eBPF telemetry;
- Rust userspace processing;
- process/container identity;
- event correlation;
- policy evaluation;
- benchmarking hooks.

It can generate realistic policy workloads, collect execution traces, and provide container identities for experiments. It should not be used to justify a verifier-level novelty claim unless the implementation actually exercises the relevant kernel mechanism.

Decision: **supporting component / evaluation harness**, not the core research contribution.

---

## 18. Final Research Boundary

```text
What the literature already solves
        ↓
Basic BPF privilege delegation → BPF Token
Basic fine-grained policy isolation → KRAKENGUARD
Verifier precision refinement → BCF
Verifier soundness hardening → AEE
Verifier bug discovery → Veritas / SpecCheck
Tenant virtualization → vBPF
Runtime enforcement → mature production systems
Resource scheduling → PeeR
        ↓
What remains partially solved
        ↓
Policy scalability, policy updates, object-lifecycle composition,
and cross-layer isolation guarantees
        ↓
What remains genuinely open
        ↓
Whether policy-delta verification can reuse established security facts
without changing the security decision or creating unsound cache state
        ↓
What is feasible for a Master's thesis
        ↓
Restricted policy language + reference verifier + incremental verifier
+ reproducible corpus + cost/precision evaluation
        ↓
What ProcessScope can contribute
        ↓
Realistic policy workloads, identity/telemetry, event correlation,
and evaluation harnesses
        ↓
Final research problem
        ↓
Can incremental, tenant-scoped eBPF policy verification reduce
re-analysis cost while preserving the security result of full analysis?
```

---

## 19. Proposed Contribution

A technically defensible contribution would consist of:

1. A small formal policy model for tenant-scoped eBPF operations.
2. A dependency-aware analysis identifying which verified facts a policy change can invalidate.
3. A delta-verification algorithm that rechecks only affected portions.
4. A reference implementation independent of the Linux verifier.
5. An experimental corpus containing real and synthetic eBPF programs.
6. A comparison against full analysis and, where reproducible, KRAKENGUARD/BCF baselines.
7. Security-preservation tests demonstrating equivalence of allow/deny decisions.
8. Measurements of analysis latency, solver work, memory, and cache hit/invalidation behavior.

The contribution is **not** "a faster eBPF verifier" unless the experiments establish that claim.

---

## 20. Risks and Unknowns

1. KRAKENGUARD may already contain a mechanism close enough to policy-delta analysis to invalidate Direction C.
2. BCF may provide a more general proof/refinement architecture than expected.
3. Artifact availability may limit a fair implementation-level comparison.
4. A delta verifier may have poor worst-case behavior when policies affect broad portions of the dependency graph.
5. Cache invalidation can become the dominant cost.
6. A restricted policy language may reduce practical significance.
7. Kernel integration may expose object-lifecycle semantics that are difficult to model faithfully in a userspace prototype.

These are reasons to run reproduction experiments before committing the thesis proposal, not reasons to manufacture novelty.

---

## 21. Next Experimental Steps

### Experiment 1 — KRAKENGUARD reproduction

- Obtain the artifact.
- Build the documented environment.
- Run the provided benchmark suite.
- Record program sizes, policy sizes, solver time, total analysis time, memory, and failure/timeout cases.

### Experiment 2 — Policy-delta workload

Construct policy revisions that change:

- one helper permission;
- one map permission;
- one memory predicate;
- one attach constraint;
- one tenant identity predicate.

Measure how much of the original analysis becomes invalid.

### Experiment 3 — Dependency graph

Measure the number of affected program paths/states per policy delta.

### Experiment 4 — Incremental checker

Implement cached state reuse and compare against full re-analysis.

### Experiment 5 — Security equivalence

For every delta, compare the incremental decision against full analysis. Any disagreement is treated as a correctness failure.

### Experiment 6 — Stress tests

Vary:

- program instruction count;
- branching factor;
- helper-call count;
- map count;
- policy predicate count;
- number of tenants;
- number of policy revisions.

### Experiment 7 — ProcessScope integration

Only after the core algorithm works, use ProcessScope to generate/collect realistic tenant workloads and identity information.

---

## 22. References

### Primary / authoritative

1. Patel et al., **KRAKENGUARD: Towards Fine-Grained eBPF Isolation**, NSDI 2026.
   https://www.usenix.org/conference/nsdi26/presentation/patel

2. Sun and Su, **Approximation Enforced Execution of Untrusted Linux Kernel Extensions**, USENIX Security 2025.
   https://www.usenix.org/conference/usenixsecurity25/presentation/sun-hao

3. Lyu et al., **eBPF Misbehavior Detection: Fuzzing with a Specification-Based Oracle**, SOSP 2025.
   https://lvtao-sec.github.io/papers/Veritas.pdf

4. Sun and Su, **Prove It to the Kernel: Precise Extension Analysis via Proof-Guided Abstraction Refinement**, SOSP 2025 / BCF.
   https://github.com/SunHao-0/BCF

5. Linux kernel BPF Token implementation.
   https://github.com/torvalds/linux/blob/master/kernel/bpf/token.c

6. Linux BPF UAPI / BPF_TOKEN_CREATE.
   https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h

7. Zhang et al., **Virtualizing eBPF with Late-Binding**, OSDI 2026.
   https://www.usenix.org/conference/osdi26/technical-sessions

8. Carin et al., **PeeR: First-Class Scheduling for Latency-Critical eBPF Applications**, OSDI 2026.
   https://www.usenix.org/conference/osdi26/presentation/carin

9. NSA, **SeaBee — Security Enhanced Architecture for eBPF**.
   https://github.com/NationalSecurityAgency/seabee

10. Linux kernel eBPF verifier documentation.
    https://docs.kernel.org/bpf/verifier.html

11. Linux kernel BPF signing documentation.
    https://www.kernel.org/doc/html/latest/bpf/signing.html

12. Tetragon enforcement documentation.
    https://tetragon.io/docs/getting-started/enforcement/

### Research caution

The existence of a paper, project, or RFC is evidence that a technique has been proposed or implemented; it is not evidence that every claimed property is solved universally. Final thesis novelty should therefore be based on artifact-level comparison and experiments rather than paper titles alone.

---

## Final Verdict

The repository's previous Phase 2 conclusions are **directionally correct but too broad**.

- Generic dynamic verification is **not a clean gap**.
- Generic BPF namespaces are **not a clean gap**.
- Generic TOCTOU is **not a clean gap**.
- Generic fine-grained policy verification is **not a clean gap** because KRAKENGUARD now establishes a strong baseline.
- The remaining opportunity is the **composition and scalability boundary** between policy changes, verified program/object state, tenant identity, and repeated analysis.

The recommended next step is therefore **artifact reproduction first, thesis commitment second**.

If incremental/delta verification survives direct comparison with KRAKENGUARD and BCF, it is the strongest current Master's-scale direction identified by this Phase 2 review. If it does not, the next candidate should be tenant-scoped BPF object lifecycle/policy isolation rather than reverting to a generic BPF namespace proposal.
