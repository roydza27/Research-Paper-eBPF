# Master's Research Reading Roadmap

This roadmap orders the collected papers based on relevance to **eBPF-Based Multi-Tenant Cloud Security**.

## Must Read
1. **Hive: A Hardware-assisted Isolated Execution Environment for eBPF on AArch64 (2024)**
   * *Rationale:* Establishes state-of-the-art in hardware-assisted eBPF isolation utilizing ARM AArch64 PAC/MTE. Reduces verifier TCB dependencies.
2. **SafeBPF: Hardware-assisted Defense-in-depth for eBPF Kernel Extensions (2024)**
   * *Rationale:* Provides a direct comparative perspective between software SFI and hardware MTE security bounds.
3. **Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing (SandBPF - 2023)**
   * *Rationale:* Foundational paper on runtime post-JIT binary rewriting and address masking for BPF isolation.
4. **eBPF Security Threat Model (2024 - Linux Foundation)**
   * *Rationale:* Key taxonomy reference to identify threats (confidentiality, integrity, evasion) and standard system controls.

## Highly Recommended
5. **Validating the eBPF Verifier via State Embedding (2024)**
   * *Rationale:* Essential for understanding the vulnerabilities of static verification. Highlights why runtime isolation is technically required.
6. **bpfbox: Simple Precise Process Confinement with eBPF (2020)**
   * *Rationale:* Demonstrates host-level security policy enforcement using eBPF hooks.

## Useful
7. **eBPF-PATROL: Protective Agent for Threat Recognition and Overreach Limitation (2025)**
   * *Rationale:* Practical container runtime protection agent reference layout.

## Background
* *Linux Kernel Documentation (BPF section)*
* *Aya Framework Docs (Rust eBPF compilation pipeline)*
* *LSM (Linux Security Module) documentation on BPFLSM hook registration*

## Historical
* *The original Berkeley Packet Filter paper (1993) by McCanne and Jacobson.*
