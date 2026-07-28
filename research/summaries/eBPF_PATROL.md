# Paper Summary: eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation

## Metadata
* **Title:** eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation in Containerized Environments
* **Authors:** Sangam Ghimire, Nirjal Bhurtel, Roshan Sahani, Sudan Jha (Kathmandu University)
* **Year:** 2025
* **Venue:** Department of Computer Science Preprint (arXiv '25)
* **URL:** https://arxiv.org/abs/2511.18155
* **Relevance Score:** 8.0/10

## Abstract
eBPF-PATROL is an extensible, lightweight runtime security agent utilizing eBPF to monitor and enforce policies in containerized environments. By intercepting system calls, analyzing execution context, and applying rules, eBPF-PATROL detects and prevents boundary violations (e.g., reverse shell, privilege escalation, container escapes) with low overhead (<2.5%).

## Architecture
* **eBPF Probes & Hook Points:** Attached to syscall entry/exit points (e.g., `sys_enter_execve`).
* **Runtime Core:** Reads events, performs policy matching, and signals user space.
* **Argument Filtering:** Inspects raw pointer variables to enforce policy arguments.

## Relevance to Research
* Practical reference implementation of an eBPF agent for Kubernetes runtime protection, demonstrating how to restrict host access in shared kernels.