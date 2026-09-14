# Updated Research Gaps — September 2026

This document supersedes the *priority* of the original gaps without deleting their historical record in `research/notes/research_gaps.md`.

## Historical gaps and current status

### Gap 1 — Dynamic/incremental eBPF verification
**Status:** partially addressed / heavily researched.

BCF (SOSP 2025) provides proof-guided abstraction refinement and ePass provides verifier-cooperative transformation/runtime enforcement. A thesis based only on incremental verification would now have substantial prior art.

### Gap 2 — Native BPF namespace isolation
**Status:** substantially reframed.

BPF Token provides user-namespace-bound delegated permissions, while vBPF provides explicit multi-tenant virtualization and state isolation. A generic proposal for "BPF-NS" is therefore too broad and risks duplication.

### Gap 3 — Syscall argument TOCTOU
**Status:** known problem with established mitigation techniques.

Prior programmable syscall-security work, BPF-LSM and production runtime-security systems already address important portions of this space. A new thesis must define a precise remaining race or lifecycle guarantee.

---

## Current Gap A — Scalable fine-grained policy verification

**Existing work:** KRAKENGUARD uses symbolic execution for helper, memory, return-value and interference policies.

**Unresolved issue:** symbolic path/expression explosion can make admission checking slow or non-terminating. The KRAKENGUARD paper explicitly identifies hybrid abstract interpretation + symbolic execution as future work.

**Research question:**

> Can a staged abstract-interpretation/symbolic-execution checker preserve fine-grained eBPF security-policy precision while reducing path explosion, peak memory and timeout frequency?

**Hypothesis:** inexpensive abstract summaries can eliminate or merge policy-equivalent paths, leaving symbolic execution only for policy-relevant uncertainty.

**Master's scope:** one policy language, one or two hook classes, KRAKENGUARD as baseline, one hybrid analysis strategy.

**Evidence status:** strong direct evidence for the gap; publication-level novelty still requires a final search immediately before proposal/submission.

---

## Current Gap B — Revocable tenant BPF delegation and object lifecycle

**Existing work:** BPF Token, BPF-LSM, SeaBee, KubeArmor, Tetragon and vBPF each cover parts of permission, policy, object or tenant isolation.

**Unresolved question:** whether a revoked tenant can retain authority through existing maps, links, pinned objects, inherited descriptors or stale policy state is not captured by a single upstream end-to-end lifecycle contract.

**Research question:**

> Can tenant authority be represented by an epoch or capability generation so that revocation has a measurable and bounded stale-object window across the BPF object graph?

**Evidence status:** promising systems gap; novelty not yet established strongly enough to claim.

---

## Current Gap C — Security/resource isolation composition

**Existing work:** vBPF addresses tenant virtualization and state isolation; PeeR addresses execution scheduling and CPU budgets.

**Unresolved question:** what security invariant holds when authorization and resource scheduling are composed under adversarial workloads?

**Research question:**

> Can a tenant's security authority and execution budget be enforced simultaneously without allowing policy bypass, cross-tenant interference or starvation?

**Evidence status:** partially explored; only pursue if a concrete invariant and measurable mechanism are identified.

---

## Recommended priority

1. **Current Gap A:** scalable fine-grained policy verification.
2. **Current Gap B:** revocable tenant delegation/object lifecycle.
3. **Current Gap C:** security/resource composition.

## Research discipline

Do not use "novel", "first", or "never done" for these gaps without another literature sweep. Use "promising", "appears partially explored", or "I found no directly equivalent work in the searched sources" as appropriate.
