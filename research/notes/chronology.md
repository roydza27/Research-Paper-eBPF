# Chronological Timeline of Publications

This timeline traces the progression of purely software-based, Linux systems eBPF security, isolation, and verification papers.

* **2020**
  * *bpfbox: Simple Precise Process Confinement with eBPF* (ACM CCSW)
    * `papers/acm/2020_ACM_bpfbox.pdf`
    * Summary: `summaries/2020_ACM_bpfbox.md`
    * Establishes early host confinement using BPF-Maps and LSM hook filters.

* **2021**
  * *BPFContain: Fixing the Soft Underbelly of Container Security* (arXiv preprint)
    * `papers/arxiv/2021_arXiv_BPFContain.pdf`
    * Summary: `summaries/2021_arXiv_BPFContain.md`
    * Evolves bpfbox into a container-aware isolation mechanism incorporating cgroups mapping.

* **2023**
  * *Cross Container Attacks: The Bewildered eBPF on Clouds* (USENIX Security)
    * `papers/usenix/2023_USENIX_CrossContainerAttacks.pdf`
    * Summary: `summaries/2023_USENIX_CrossContainerAttacks.md`
    * Exposes critical security vulnerabilities where malicious containerized eBPF bypasses boundaries to host systems.
  * *Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing* (SandBPF - SIGCOMM Workshop)
    * `papers/arxiv/2023_arXiv_SandBPF.pdf`
    * Summary: `summaries/2023_arXiv_SandBPF.md`
    * Devises runtime post-JIT bytecode instrumentation (SFI address masking) for safe unprivileged eBPF execution.

* **2024**
  * *Validating the eBPF Verifier via State Embedding* (USENIX OSDI)
    * `papers/osdi/2024_OSDI_StateEmbedding.pdf`
    * Summary: `summaries/2024_OSDI_StateEmbedding.md`
    * Demonstrates that the verifier's mathematical bounds assertions contain critical logic bugs.
  * *The eBPF Runtime in the Linux Kernel* (arXiv preprint)
    * `papers/arxiv/2024_arXiv_eBPFRuntimeLinux.pdf`
    * Summary: `summaries/2024_arXiv_eBPFRuntimeLinux.md`
    * Formulates the first comprehensive description of BPF verification passes and safety models up to core 6.7.
  * *eBPF Security Threat Model* (Linux Foundation Whitepaper)
    * `papers/arxiv/2024_LF_eBPFThreatModel.pdf`
    * Summary: `summaries/2024_LF_eBPFThreatModel.md`
    * Sets standard definitions for threat risks and mitigating operators.

* **2025**
  * *eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation* (arXiv preprint)
    * `papers/arxiv/2025_arXiv_eBPFPatrol.pdf`
    * Summary: `summaries/2025_arXiv_eBPFPatrol.md`
    * Explores runtime container monitoring loops matching arguments to host-level security profiles.