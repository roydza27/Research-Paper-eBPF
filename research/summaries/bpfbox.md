# Paper Summary: bpfbox: Simple Precise Process Confinement with eBPF

## Metadata
* **Title:** bpfbox: Simple Precise Process Confinement with eBPF
* **Authors:** William Findlay (Carleton University), Anil Somayaji, David Barrera
* **Year:** 2020
* **Venue:** ACM Cloud Computing Security Workshop (CCSW '20)
* **URL:** https://www.cisl.carleton.ca/~will/written/conference/bpfbox-ccsw2020.pdf
* **Relevance Score:** 8.0/10

## Abstract
Process confinement is key in cloud security. Existing mechanisms like SELinux, AppArmor, seccomp, etc., are complex. We present bpfbox, which uses under 2,000 lines of kernel code to allow confinement at the userspace function, syscall, LSM, and kernelspace boundaries. Its simple policy language enables developers to restrict untrusted processes with modest overhead (~8.4%).

## Research Problem
Standard confinement tools are either too coarse (seccomp restricts calls entirely but can't filter complex arguments) or too complex (SELinux/AppArmor policy definition is notoriously difficult and prone to misconfiguration).

## Architecture
```
 [User Process] ─────> [Syscall/LSM Hook]
                              │
                              ▼
                     [bpfbox Engine (eBPF)] ─────> [Policy Rules (BPF Maps)]
                              │
                     [Permit or Deny]
```
* **LSM & eBPF integration:** Uses eBPF programs attached to Linux Security Module (LSM) hooks to inspect parameters and execution contexts.
* **Dynamic rules:** Uses BPF maps to lookup permissions dynamically.

## Evaluation
* Under 8.4% overhead on Apache throughput benchmarks, outperforming or matching standard AppArmor.

## Relevance to Research
* Demonstrates how eBPF can enforce tenant confinement at the host level. Useful for designing policy managers for Kubernetes workloads.