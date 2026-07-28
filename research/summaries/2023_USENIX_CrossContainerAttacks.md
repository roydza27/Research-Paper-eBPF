# Paper Summary: Cross Container Attacks: The Bewildered eBPF on Clouds

## Metadata
* **Title:** Cross Container Attacks: The Bewildered eBPF on Clouds
* **Authors:** Yi He, Roland Guo, Yunlong Xing, Xijia Che, Kun Sun, Zhuotao Liu, Ke Xu, Qi Li
* **Year:** 2023
* **Venue:** USENIX Security Symposium
* **URL:** https://www.usenix.org/conference/usenixsecurity23/presentation/he
* **Relevance Score:** 9.5/10
* **Tags:** eBPF, Container Escape, Multi-Tenant, Kubernetes, Cloud Security, Offensive Security

## Summary

### Research Problem
eBPF's powerful features have been widely leveraged for securing cloud-native containers. However, under-privileged or over-privileged containerized environments can exploit eBPF tools to bypass container boundaries, leading to multi-tenant host compromises, data thefts, and cross-node cluster takeover.

### Motivation
Current container platforms allow containers to load or interact with tracepoints/kprobes under certain network configurations. While offensive eBPF has been studied on raw hosts, there was no systematic evaluation of how containerized environments run eBPF tracing vectors to mount escape and cross-container attacks.

### Proposed Solution
The authors conduct a thorough security assessment of eBPF-based container escapes (Cross Container Attacks) and present a revised eBPF permission model to restrict access in multi-tenant environments.

### Methodology
* **Exploit Vector Mapping:** Evaluates vulnerabilities where containerized processes access eBPF features. For example, if a container has `CAP_SYS_ADMIN` or `CAP_BPF` (often granted to monitoring sidecars), it can read raw host memory via `bpf_probe_read`.
* **Cross-Container Exploit Construction:**
  - *Data Theft:* Intercepting system calls of other target containers.
  - *Evasion:* Hijacking security tool monitoring hooks.
  - *Escape:* Overwriting user-space execution blocks/files on the host.
* **Exploitation Trials:** Tested on six online interactive shell services and GCP Cloud Shell.
* **Proposed Defense:** Highlights a custom LSM policy engine restricting BPF probe registrations based on individual container cgroups.

### Experimental Setup
* Replicated attack models in standard Kubernetes grids managed by major cloud vendors (Alibaba, Google Cloud, AWS).

### Results
* Successfully compromised GCP Cloud Shell and escaped containers on five other interactive hosting environments.
* Demonstrated a cross-node cluster takeover by hijacking over-privileged cloud logging sidecars.
* Highlighted that modern IDSs fail to notice in-kernel BPF escapes.

### Limitations
* The described escape routes require specific capabilities (`CAP_SYS_ADMIN` or `CAP_BPF`/`CAP_PERFMON`).
* The proposed LSM containment model increases policy maintenance overhead.

### Future Work
* Integrating fine-grained runtime boundaries for tracing helper functions within container namespaces.