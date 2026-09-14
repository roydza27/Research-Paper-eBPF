# Research Gaps Candidates: eBPF in Multi-Tenant Environments

> **Historical baseline — September 2026 note:** The three gaps below were the repository's pre-2026 hypotheses. They are preserved for historical traceability but should not be treated as the current thesis gaps. See [`updated-research-gaps.md`](./updated-research-gaps.md) and [`research/reports/2026-09-research-update.md`](../reports/2026-09-research-update.md).

---

## Gap 1: Safe Verification of Dynamic, Runtime-Generated eBPF Code

* **Historical problem:** BPF verification was treated as a one-shot, load-time process and dynamic policy changes were expected to require reload/reverification.
* **2026 status:** **Partially addressed / heavily researched.** BCF (SOSP 2025) provides proof-guided abstraction refinement, while ePass provides verifier-cooperative transformation and runtime enforcement.
* **Current interpretation:** Do not use generic incremental verification as the primary thesis question without identifying a new property not addressed by BCF/ePass.

## Gap 2: eBPF Namespace Isolation (BPF-NS)

* **Historical problem:** BPF maps and links were treated as globally shared kernel assets without namespace-aware separation.
* **2026 status:** **Substantially reframed.** BPF Token now supports user-namespace-bound delegation, and vBPF (OSDI 2026) provides explicit multi-tenant virtualization and state isolation.
* **Current interpretation:** A generic native BPF namespace proposal is too broad and risks duplicating current work. Focus instead on object lifecycle, revocation, or another precisely measurable property.

## Gap 3: Time-of-Check to Time-of-Use (TOCTOU) in Helper Call Probes

* **Historical problem:** eBPF security tools reading user-space syscall arguments can observe data that changes before the kernel consumes it.
* **2026 status:** **Known problem with established mitigation techniques.** Programmable syscall-security research, BPF-LSM and production runtime-security systems address important parts of the problem.
* **Current interpretation:** TOCTOU remains a valid experimental concern, but it is not an untouched research gap. A thesis must specify a concrete remaining race or lifecycle guarantee.

---

## Current gaps

See [`updated-research-gaps.md`](./updated-research-gaps.md) for the September 2026 research direction:

1. **Scalable fine-grained policy verification** — primary.
2. **Revocable tenant BPF delegation and object lifecycle** — secondary.
3. **Security/resource isolation composition** — exploratory.
