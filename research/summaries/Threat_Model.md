# Paper Summary: eBPF Security Threat Model

## Metadata
* **Title:** eBPF Security Threat Model
* **Authors:** Jack Kelly, James Callaghan, Andrew Martin (ControlPlane / eBPF Foundation)
* **Year:** 2024
* **Venue:** Linux Foundation Publish
* **URL:** https://github.com/ebpffoundation/publications/blob/main/2024/ControlPlane_eBPF_Security_Threat_Model.pdf
* **Relevance Score:** 9.0/10

## Abstract
This document provides threat intelligence and recommendations for enterprises using eBPF. A threat modeling approach outlines eBPF’s defenses through an attacker’s lens, looking at confidentiality, integrity, availability, evasion, and mitigations.

## Scope of Threats
* **Unauthorized Kernel Reads/Writes:** Exploits that trick verification.
* **Denial of Service (DoS):** Infinite loop bypasses, shared Map exhaustion, CPU hogging.
* **Security Tool Evasion:** Tampering with BPF maps, detaching hooks, or overriding policies.

## Key Recommendations
1. **Limit CAP_BPF / CAP_SYS_ADMIN:** Never provide these capabilities to containerized workloads.
2. **Namespace BPF maps:** Clean up maps when namespaces terminate.
3. **Use LSM security policies:** Secure BPF object creation using LSM hooks.

## Relevance to Research
* Provides the standard taxonomy and threat definitions for eBPF security that this research addresses.