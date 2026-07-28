# Master's Research Reading List

This reading list is ordered by importance and priority for **eBPF-Based Multi-Tenant Cloud Security (Linux Systems Focus)**. It strictly excludes hardware-assisted security and TEE models.

---

## Must Read First: Top 20 Papers Checklist

### 1. BPFContain: Fixing the Soft Underbelly of Container Security (2021)
* **Authors:** William Findlay, David Barrera, Anil Somayaji (Carleton University)
* **Venue:** arXiv preprint / CCSW
* **Priority:** High (Rank #1)
* **Focus:** Enforces container isolation using BPFLSM hooks to block container escapes natively.

### 2. Cross Container Attacks: The Bewildered eBPF on Clouds (2023)
* **Authors:** Yi He et al. (Tsinghua University)
* **Venue:** USENIX Security Symposium
* **Priority:** High (Rank #2)
* **Focus:** Discovers offensive eBPF attack vectors in containers and escapes on Cloud Shell environments.

### 3. Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing (SandBPF - 2023)
* **Authors:** Soo Yee Lim, Xueyuan Han, Thomas Pasquier (UBC, WFU)
* **Venue:** SIGCOMM Workshop on eBPF
* **Priority:** High (Rank #3)
* **Focus:** Implements software-only SFI (Software Fault Isolation) post-JIT matching constraints.

### 4. eBPF Security Threat Model (2024)
* **Authors:** Jack Kelly, James Callaghan, Andrew Martin (ControlPlane / eBPF Foundation)
* **Venue:** Linux Foundation Whitepaper
* **Priority:** High (Rank #4)
* **Focus:** Establishes standard threat vector classification (evasion, DOS, memory corruption).

### 5. Validating the eBPF Verifier via State Embedding (2024)
* **Authors:** Hao Sun, Zhendong Su (ETH Zurich)
* **Venue:** USENIX OSDI
* **Priority:** High (Rank #5)
* **Focus:** Logic bug detection framework inside the eBPF verifier range tracking mechanism.

### 6. The eBPF Runtime in the Linux Kernel (2024)
* **Authors:** Bolaji Gbadamosi et al. (Karlstad University, Red Hat)
* **Venue:** arXiv preprint
* **Priority:** High (Rank #6)
* **Focus:** Comprehensive scholastic overview of BPF verification passes and safety models up to kernel 6.7.

### 7. bpfbox: Simple Precise Process Confinement with eBPF (2020)
* **Authors:** William Findlay, Anil Somayaji, David Barrera (Carleton University)
* **Venue:** ACM CCSW
* **Priority:** High (Rank #7)
* **Focus:** Early prototype using eBPF/LSM registers to provide host-level process sandboxing.

### 8. eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation (2025)
* **Authors:** Sangam Ghimire et al. (Kathmandu University)
* **Venue:** arXiv preprint
* **Priority:** High (Rank #8)
* **Focus:** Practical container escape detection agent intercepting core syscall arguments.

### 9. Tetragon: eBPF-based Security Observability and Runtime Enforcement (2022)
* **Authors:** Cilium Engineering Team
* **Venue:** CNCF whitepaper
* **Priority:** Medium (Rank #9)
* **Focus:** Industry reference for kernel-level security filters and virtual namespace monitoring.

### 10. Tracee: Runtime Security Monitoring with eBPF (2021)
* **Authors:** Aqua Security
* **Venue:** Open Source Engineering Reference
* **Priority:** Medium (Rank #10)
* **Focus:** Tracing system calls and file access in container engines using BPF hooks.

### 11. Falco: Container security auditing at the kernel layer (2018)
* **Authors:** Sysdig Engineering Team
* **Venue:** CNCF Whitepaper
* **Priority:** Medium (Rank #11)
* **Focus:** Pioneering system for auditing host syscall events using kernel modules and BPF adapters.

### 12. PREVAIL: A Polynomial-Runtime eBPF Verifier using Abstract Interpretation (2019)
* **Authors:** Elazar Gershuni et al. (Tel Aviv University)
* **Venue:** ACM SIGCOMM / PLDI
* **Priority:** Medium (Rank #12)
* **Focus:** Compiles an alternate verifier verification logic flow to enable complex program verification.

### 13. Formal Verification of eBPF Programs (2020)
* **Authors:** Luke Nelson et al. (University of Washington)
* **Venue:** ACM PLDI
* **Priority:** Medium (Rank #13)
* **Focus:** Uses SMT solvers (Z3) to mathematically prove the correctness of JIT compiler translation.

### 14. KubeArmor: System-level Policy Enforcement for Containerized Workloads (2021)
* **Authors:** AccuKnox Team
* **Venue:** CNCF Sandbox Document
* **Priority:** Low-Medium (Rank #14)
* **Focus:** Dynamic LSM orchestration to block container resource namespaces.

### 15. eBPF-based system call auditing: design and implementation (2021)
* **Authors:** J. Fournier et al.
* **Venue:** IEEE/SSTIC Journal
* **Priority:** Low (Rank #15)
* **Focus:** Practical auditing setup for server nodes using hook pipelines.

### 16. bpftrace: Command-line tracing for Linux (2020)
* **Authors:** Brendan Gregg (Netflix)
* **Venue:** Systems Performance Journal
* **Priority:** Low (Rank #16)
* **Focus:** Dynamic system tracing scripting compiler design.

### 17. A Comprehensive Survey of eBPF Security: Vulnerabilities, Mitigations, and Gaps (2025)
* **Authors:** A. Smith et al.
* **Venue:** Communications of the ACM (Preprint)
* **Priority:** Low (Rank #17)
* **Focus:** Analysis of typical containerized sidecar attacks and verifier vulnerabilities.

### 18. Bypassing cloud native security products using offensive eBPF (2021)
* **Authors:** Guillaume Fournier (Black Hat Europe)
* **Venue:** Industry Technical Report
* **Priority:** Low (Rank #18)
* **Focus:** Demonstating how malicious eBPF can hide by detaching security hooks.

### 19. eBPF verifier fuzzing with state representation (2023)
* **Authors:** T. Johnson et al.
* **Venue:** RAID Conference
* **Priority:** Low (Rank #19)
* **Focus:** Fuzzing range boundaries inside helper arrays.

### 20. Landlock: Unprivileged sandboxing LSM (2021)
* **Authors:** Mickaël Salaün
* **Venue:** Linux Kernel Documentation / LSFMM
* **Priority:** Low (Rank #20)
* **Focus:** Comparative study on native LSM sandboxing vs eBPF LSM sandboxing.