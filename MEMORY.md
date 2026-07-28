# Project Memory Log (MEMORY.md)

> **Persistent Project Context for AI Agents & Researchers**

---

## 1. Research Identity

* **Research Title:** eBPF-Based Multi-Tenant Container Confinement and LSM Policy Enforcement
* **Research Domain:** Linux Kernel Security, Container Virtualization, Cloud-Native Systems
* **Research Focus:** Restricting unprivileged and over-privileged eBPF execution spaces in shared infrastructure nodes to prevent cross-container escapes and resource eavesdropping.
* **Research Objectives:**
  1. Identify container escape paths utilizing BPF helper interfaces.
  2. Evaluate existing verifier security limitations and compile-time logic gaps.
  3. Design a dynamic, namespace-aware LSM hook runtime policy manager using Rust.
* **Supervisor Discussion Summary:** Supervisor recommended focusing strictly on software isolation constraints within the Linux kernel and avoiding hardware-assisted models. Highlighted that porting solutions across Kubernetes nodes requires general platform availability.
* **Current Direction:** Transitioning from literature aggregation to local kernel tracing checks of target system call parameters in isolated cgroups.

---

## 2. Research Constraints

### What this project IS:
* **Linux Kernel Only:** Systems-level hooks and configuration parameters.
* **eBPF-Centric:** Focuses strictly on BPF verifier testing, maps namespacing, and LSM monitoring.
* **Software-Only Confinement:** Software Fault Isolation (SFI) and bytecode rewriting patterns.
* **Cloud-Native Scope:** Evaluated inside Kubernetes pods and Docker runtimes.

### What this project IS NOT:
* **No Hardware Security:** Out-of-scope: Trusted Execution Environments (TEEs), Intel SGX, AMD SEV, ARM TrustZone, TPMs, and CPU secure elements.
* **No Side-Channel/Cache Analysis:** Out-of-scope: Speculative execution bugs (Spectre, Meltdown), power usage audits, and differential analysis.
* **No Hypervisor/Microkernel Research:** Focuses strictly on monolithic shared Linux host kernels.

---

## 3. Research Vocabulary

* **eBPF:** Extended Berkeley Packet Filter (in-kernel virtual machine).
* **XDP:** eXpress Data Path (early packet processing hot-path in network drivers).
* **LSM:** Linux Security Modules (kernel callbacks for hooking security actions).
* **Tracepoints / Kprobes / Uprobes:** Target instrumentation entry points.
* **Cgroups / Namespaces / Capabilities:** Core Linux virtualization partitioning tools.
* **Verifier:** In-kernel abstract interpreter auditing BPF bytecode safety.
* **Maps:** Key-value data stores shared between user space and kernel eBPF modules.
* **Aya:** A purely Rust-based compilation and loader framework for eBPF.

---

## 4. Research Questions

1. How can runtime security agents identify when a BPF program is attempting container escapes via helper call arguments?
2. What are the performance costs of running software address-masking SFI checks compared to standard VM filters like seccomp?
3. Can we implement namespace boundaries for BPF-Maps without modifications to the upstream Linux page allocator?

---

## 5. Active Reading List

### Currently Reading
* *Validating the eBPF Verifier via State Embedding* (OSDI '24)

### Completed (Metadata Cataloged)
* *BPFContain: Fixing the Soft Underbelly of Container Security* (2021)
* *Cross Container Attacks: The Bewildered eBPF on Clouds* (USENIX Security '23)
* *Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing* (SandBPF - 2023)
* *bpfbox: Simple Precise Process Confinement with eBPF* (2020)
* *eBPF-PATROL: Protective Agent for Threat Recognition* (2025)
* *eBPF Security Threat Model* (2024)
* *The eBPF Runtime in the Linux Kernel* (2024)

### Must Revisit / High Priority
* *BPFContain* (For implementation cues on cgroup identification).
* *Cross Container Attacks* (To study specific escape sequences).

---

## 6. Curated List of Important Papers

1. **BPFContain (2021):** The premier blueprint showing LSM-based container isolation policies.
2. **Cross Container Attacks (USENIX Security '23):** Explains exactly what could go wrong if BPF is unconfined.
3. **SandBPF (2023):** Essential reference for SFI bytecode instruction rewrite techniques.

---

## 7. Evolving Research Gaps

* **Verifier State Mismatch Bypasses:** Register mathematical range calculation mismatches inside the verifier that cannot be caught at load time.
* **BPF filesystem Map Leakages:** Global namespace availability of pinned BPF objects across different pods.
* **Syscall Argument TOCTOU:** Time-of-check to time-of-use exploits on memory buffers during tracing execution.

---

## 8. Ideas

* Construct a dynamic namespaces controller for BPF filesystem endpoints virtualizing the `/sys/fs/bpf` hierarchy per container PID space.
* Leverage Rust macros in the Aya pipeline to automate bounds validations on helper array structures before JIT compilation.

---

## 9. Future Tasks

* [ ] Program a test script triggering basic pointer validation checks using Aya.
* [ ] Verify container network namespace isolation constraints inside a minikube grid.
* [ ] Write the first draft of Chapter 2 (Literature Review) for the Master's thesis.

---

## 10. Repository Rules & Agent Instructions

### Adding New Papers
1. **Naming Template:** `papers/<venue>/YYYY_<Venue>_<ShortTitle>.pdf`
2. **Summary Template:** `summaries/YYYY_<Venue>_<ShortTitle>.md`
3. **BibTeX Placement:** Write individual `.bib` entries in `metadata/bibtex/key.bib` and append to `references/references.bib` automatically.
4. **Metadata Update:** Add the entry to `metadata/papers.json` and `metadata/papers.csv`.

### AI Agent Directives
* **Strict Filter:** Reject and delete any paper relating to Hardware Security, TEEs, SGX, or CPU side-channels.
* **Authority First:** Prioritize USENIX, OSDI, NSDI, and ACM CCSW publications.
* **Consistency Check:** Ensure summary filenames match corresponding PDF names exactly. Always synchronize datasets and Indexes after audits.
* **No Duplication:** Never create duplicate entries or redundant markdown draft files.
