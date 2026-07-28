# eBPF-Based Multi-Tenant Cloud Security Research Workspace

> **Research Workspace for Master's Thesis and Cloud-Native Kernel Protection Systems**

---

## 1. Project Overview & Motivation

This repository serves as the central hub for academic research on **eBPF-Based Multi-Tenant Cloud Security**. 

eBPF (extended Berkeley Packet Filter) has evolved from a simple packet-filtering tool into a highly performant virtual machine execution runtime integrated directly into the Linux kernel. It enables userspace processes to inject custom bytecode at dynamically instrumented host hooks (e.g. system calls, cgroups boundary transitions, network drivers via XDP, and Linux Security Modules - LSM).

While eBPF provides unparalleled advantages for networking, tracing, and container auditing, it runs directly in the kernel space. As cloud infrastructures scale up and workloads from multiple tenants are co-scheduled on shared physical hardware running a single shared Linux kernel, executing unprivileged or over-privileged BPF bytecode introduces critical vulnerabilities. This research evaluates how eBPF can be safely deployed and isolated in multi-tenant environments.

---

## 2. Research Problem & Scope

### The Problem Statement
Cloud-native container engines partition user processes using generic control primitives (`cgroups`, namespaces, capabilities). However, the underlying kernel remains shared. If a containerized sidecar or tenant process compromises or exploits mathematical range tracker verification bugs in the kernel verifier:
1. It bypasses load-time validation routines entirely.
2. It can execute malicious pointer arithmetic to read out-of-bounds kernel memory or write to general system regions.
3. Because eBPF lacks native namespace boundaries matching PID or NET architectures, maps and hooks remain global assets, exposing systems to **container escape** vectors and cross-tenant eavesdropping.

### Scope limits
* **IN-SCOPE:** Linux systems security, container isolation architectures (cgroups, PID/MNT namespaces), eBPF verifier correctness, software-only SFI bounds checks, dynamic BPFLSM policy engines.
* **OUT-OF-SCOPE:** Hardware-assisted isolated enclaves (Intel SGX, AMD SEV, ARM TrustZone/MTE/PAC), microarchitectural side-channels (Spectre, Meltdown), hypervisor/VM design, hardware secure boot, cryptoprocessors (TPM).

---

## 3. Repository Structure

This workspace is designed to scale to hundreds of papers and maintain absolute reproducibility.

```text
eBPF/
│
├── README.md                 # Primary index, overview, and workflow guide
├── MEMORY.md                 # Persistent context cache for AI agents
│
└── research/
    ├── papers/               # Categorized reference PDFs sorted by venue
    │   ├── usenix/
    │   ├── acm/
    │   ├── ieee/
    │   ├── arxiv/
    │   ├── springer/
    │   ├── ndss/
    │   ├── osdi/
    │   └── nsdi/
    ├── metadata/             # Structured search matrices and bib databases
    │   ├── papers.json
    │   ├── papers.csv
    │   └── bibtex/
    ├── summaries/            # Markdown summaries of key literature papers
    ├── notes/                # Research timelines, relationship graphs, gaps
    ├── reading-list/         # Priority lists and "Must Read First" Top 20
    ├── references/           # Consolidated references.bib database
    ├── docs/                 # Detailed methodology and conventions
    ├── datasets/             # Directory for experimental outputs
    ├── experiments/          # Testing benches and profiling scripts
    ├── implementations/      # Reference prototype code
    ├── reports/              # Weekly logs and milestone checklists
    └── assets/               # System design diagrams and flowcharts
```

---

## 4. Research Workflow & Selection Criteria

All incoming literature is processed according to a structured pipeline to ensure quality and prevent duplication:

```
[New Paper Discovered]
        │
        ▼
[Perform First Pass Screen] (Meets Selection Criteria?)
        │
        ├── Yes ──> [Download PDF / Save to papers/<venue>/]
        │           [Name file: YYYY_<Venue>_<ShortTitle>.pdf]
        │
        └── No ───> [Discard Paper]
        │
        ▼
[Extract Metadata] ──> [Append entry to metadata/papers.json & papers.csv]
        │
        ▼
[Generate Citation] ──> [Create metadata/bibtex/key.bib & append to references.bib]
        │
        ▼
[Draft Summary] ──> [Write summaries/YYYY_<Venue>_<ShortTitle>.md]
        │
        ▼
[Analyze Gaps] ──> [Update notes/research_gaps.md]
```

### Selection Criteria
1. **Source Integrity:** Peer-reviewed publications in top systems conferences (USENIX ATC/Security, SOSP, OSDI, CCSW, NSDI).
2. **eBPF-Centricity:** eBPF must be a primary contribution or target of study.
3. **No Hardware Security:** Papers relying on TEE, CPU cache modification, or secure elements are discarded.

---

## 5. Technology Stack & Tools Used

To maintain lightweight development and verifiability, this project leverages:
* **Programming Languages:** Rust (via the `Aya` eBPF compiler framework for user/kernel space modules).
* **Scripting & Automation:** Python (with standard statistical libraries for parsing CSV indexes and system logs).
* **Host Platform:** Linux Kernel 5.10+ (supporting BPFLSM hook registration).
* **Tracing/Validation Tooling:** `bpftool`, `bpftrace`, and standard `perf` tooling.

---

## 6. Current Progress & Milestones

* [x] **Milestone 1:** Repository structure audit and refactor.
* [x] **Milestone 2:** Collection & mapping of 8 core literature elements.
* [ ] **Milestone 3:** Local kernel verifier state verification and testing.
* [ ] **Milestone 4:** Prototype design of dynamic namespace filters.

---

## 7. References & Timeline

See detailed indices under `research/indexes/index.md` or check chronology notes at `research/notes/chronology.md` for historical development trends.

---

## 8. License & Guidelines
Contributions to this workspace follow standard academic publishing guidelines. All source code is restricted to GPLv2 licensing.
