# Paper Summary: eBPF Security Threat Model

## Metadata
* **Title:** eBPF Security Threat Model
* **Authors:** Jack Kelly, James Callaghan, Andrew Martin
* **Year:** 2024
* **Venue:** Linux Foundation Whitepaper
* **URL:** https://github.com/ebpffoundation/publications/blob/main/2024/ControlPlane_eBPF_Security_Threat_Model.pdf
* **Relevance Score:** 9.0/10
* **Tags:** eBPF, Threat Model, Kubernetes, Cloud-Native, Container Security, Linux

## Summary

### Research Problem
Adopting eBPF-based tools (for monitoring, networking, or security) in enterprise cloud structures introduces new risks. As eBPF programs execute in kernel context, they present a high-value target for attackers hoping to escape containers, bypass security agents, or capture kernel secrets.

### Motivation
No standardized, comprehensive taxonomy existed mapping out the threat landscape of in-kernel eBPF deployments. Security teams and cloud architects needed a practical threat model to design secure container grids.

### Proposed Solution
A formalized **eBPF Threat Model** using Shostack’s four-question approach, mapping attacker capabilities, target assets, and mitigating controls.

### Methodology
* **Asset Identification:** Classifies crucial eBPF system links (BPF Maps, helper pathways, pin spaces).
* **Attacker Vectors Mapping:** Creates detailed attack trees focusing on:
  1. Confidentiality/Integrity (retrieving maps keys, side-channel dumps).
  2. Availability (CPU starvation, map exhaustion).
  3. Security Evasion (unlinking BPF probes, overwriting map values).
* **Control Formulation:** Maps kernel configuration options (e.g. disabling unprivileged BPF, namespace protection, LSM controls) to threat mitigations.

### Experimental Setup
* Qualitative security analysis based on historical BPF exploits, kernel configurations, and architectural deployments.

### Results
* Developed a security control list for system operators (e.g. pinning configurations, disabling unprivileged BPF via `/proc/sys/kernel/unprivileged_bpf_disabled`).
* Outlined the impact of the `CAP_BPF` flag introduced in Linux 5.8.

### Limitations
* Lacks code models or executable performance benchmarks.
* The rapid pace of kernel changes may make specific control identifiers outdated.

### Future Work
* Standardizing eBPF audit logs across container orchestration platforms.