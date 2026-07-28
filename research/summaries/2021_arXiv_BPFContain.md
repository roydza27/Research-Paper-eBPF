# Paper Summary: BPFContain: Fixing the Soft Underbelly of Container Security

## Metadata
* **Title:** BPFContain: Fixing the Soft Underbelly of Container Security
* **Authors:** William Findlay, David Barrera, Anil Somayaji
* **Year:** 2021
* **Venue:** arXiv Preprint
* **URL:** https://arxiv.org/abs/2102.06972
* **Relevance Score:** 9.5/10
* **Tags:** eBPF, Runtime Security, Container Isolation, LSM, Linux, Multi-Tenant

## Summary

### Research Problem
Linux container runtimes (Docker, LXC, Kubernetes pods) fail to isolate systems completely because container security boundaries rely on a patchwork of coarse rules (default namespaces, seccomp filters, AppArmor/SELinux profiles). This makes it difficult to specify container-specific least-privilege policies, paving the way for container escape exploits or cross-tenant interference.

### Motivation
Traditional system filters (like seccomp-bpf) operate at the syscall layer without context awareness (e.g. they cannot inspect file path strings because pointers are dereferenced inside the kernel, leading to TOCTOU bugs). We need a mechanism that is container-aware, integrates with modern container runtimes (e.g., Docker daemon), and enforces context-driven security rules inside the kernel.

### Proposed Solution
The authors introduce **BPFContain**, a container-aware security enforcement engine. It leverages eBPF programs attached to Linux Security Module (LSM) hooks to restrict containerized execution contexts dynamically.

### Methodology
* **Container Namespace Awareness:** BPFContain reads container ID namespace structures (`cgroups` and pid mappings) directly. When an LSM hook is triggered, BPFContain checks the task context back to a container policy map.
* **YAML-Based Policy Engine:** Compiles high-level container policies into BPF map rules.
* **Least-Privilege Enforcement:** Prevents raw socket accesses, limits mount namespaces, restricts path access, and blocks sysfs manipulation from within containers.
* **Rust Control Daemon:** Implements user-space agent and CLI integration in Rust.

### Experimental Setup
* Tested on standard Linux installations running containerized environments (Docker).
* Benchmarked performance impact using Phoronix, Netperf, and Apache workloads.
* Confirmed containment capability by attempting 5 different container-escape exploits and CVE models.

### Results
* **Security:** Successfully blocked all escape vectors and privilege escalations.
* **Performance:** Negligible impact on typical workloads (<1-3% overhead) and significantly less memory overhead compared to traditional MAC policies like SELinux.

### Limitations
* Relies on the host operating system having `BPFLSM` support enabled (requires Linux kernel 5.7+).
* Cannot easily intercept namespace structures that are created dynamically inside child virtual networks.

### Future Work
* Integrating BPFContain with Kubernetes CNI plugins and OCI runtimes (like `containerd` or `cri-o`).
* Handling distributed container clusters.