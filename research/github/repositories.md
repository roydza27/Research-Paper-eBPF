# GitHub Reference Repository Database

This file collections relevant open-source projects related to the research.

## Project 1: bpfbox
* **URL:** https://github.com/willfindlay/bpfbox
* **Description:** A policy enforcement engine written in eBPF to confine process access to security-sensitive resources. (Superseded by BPFContain).
* **Architecture:** Userspace control daemon + eBPF LSM programs linked via BPF maps.
* **Language:** C, Rust (BPFContain)
* **Stars:** ~250
* **License:** GPLv2
* **Relationship to Research:** Reference layout for process confinement.

## Project 2: eBPF-PATROL
* **URL:** https://github.com/CloudandComosLabs/eBPF-PATROL
* **Description:** Runtime security agent using eBPF to block container escapes.
* **Language:** C / Go
* **Relationship to Research:** Syscall argument monitoring blueprint.

## Project 3: Aya
* **URL:** https://github.com/aya-rs/aya
* **Description:** A library that makes it possible to write eBPF programs entirely in Rust.
* **Language:** Rust
* **Relationship to Research:** Prime technology stack selected for thesis prototyping.
