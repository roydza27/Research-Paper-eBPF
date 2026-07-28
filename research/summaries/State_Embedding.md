# Paper Summary: Validating the eBPF Verifier via State Embedding

## Metadata
* **Title:** Validating the eBPF Verifier via State Embedding
* **Authors:** Hao Sun (ETH Zurich), Zhendong Su (ETH Zurich)
* **Year:** 2024
* **Venue:** 18th USENIX Symposium on Operating Systems Design and Implementation (OSDI '24)
* **URL:** https://www.usenix.org/system/files/osdi24-sun-hao.pdf
* **Relevance Score:** 8.5/10

## Abstract
This paper introduces state embedding, a novel and highly effective technique for validating the correctness of the eBPF verifier, a critical component for Linux kernel security. To check safety, the verifier tracks over-approximated states. Our key insight is that we can detect logic bugs in the verifier by embedding a program with certain approximation-correctness checks expected to be validated by the verifier. Using our tool, we uncovered 15 previously unknown logic bugs in the verifier.

## Research Problem
The eBPF verifier uses abstract interpretation to verify kernel safety properties. However, its abstract domains (like three-state numbers, range bounds, and pointer types) have complex transition rules. Bugs in these rules lead to verifier-runtime state divergence, allowing unsafe programs to load.

## Methodology
1. **Verification-state divergence detection:** Generates programs and embeds assertions that check the verifier's own state representation (e.g., checking if the verifier believes register $r1 has range [0, 50] while the actual concrete execution can yield 100).
2. **State-Embedding Loop:**
   * Generate an eBPF program with conditional branches.
   * Embed specific instructions ("state checking probes").
   * Feed the program to the verifier.
   * If the verifier incorrectly permits or rejects, it reveals an abstract domain bug.

## Architecture
```
[Dynamic Program Generator] ──> [Embed State Checking Probes]
                                         │
                                         ▼
                              [Evaluate on eBPF Verifier]
                                         │
                 ┌───────────────────────┴───────────────────────┐
           [Accepted]                                       [Rejected]
                 │                                               │
        [Run in Kernel]                                    [Fix Generator]
                 │
  [Mismatch with Concrete State?] ──> [LOGIC BUG COMMITTED]
```

## Threat Model
* Relates to verification bypasses. An attacker uses a fuzzer or compiler bypass to find ranges where the verifier over-approximates incorrectly, allowing an out-of-bounds array dump or local privilege escalation.

## Results
* Discovered **15 critical bugs** in the Linux kernel verifier.
* Enabled developer fixes in mainline kernels (e.g. CVE-2023-2163 and others).

## Strengths
* Highlights the fragility of the verifier's math operations.
* Practical and highly automated bug finding.

## Weaknesses
* Does not offer active protection; only helps fix the verifier post-facto.
* Cannot guarantee finding all bugs.

## Key Quotes
* *"Any concrete state not contained in the tracked approximation may invalidate the verifier’s conclusion."*
* *"State embedding successfully exposes verification gaps by forcing the verifier to state its assumptions."*

## Relation to Current Research
* Demonstrates why the verifier CANNOT be trusted as the sole line of defense in tenant-shared kernels, highlighting the need for active isolation mechanisms (like HIVE, SandBPF, or SafeBPF).