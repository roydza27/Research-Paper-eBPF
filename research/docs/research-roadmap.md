# Master's Research Roadmap

This document outlines the steps toward completing the Master's thesis.

## Phase 1: Literature Aggregation & Taxonomy (Months 1-3)
* [x] Restructure and clean up the research repository.
* [x] Seed reference library with 8 core software-only eBPF security/isolation papers.
* [ ] Complete reading roadmap of USENIX/OSDI papers.

## Phase 2: Gap Verification & Problem Statement (Months 4-5)
* [ ] Validate register-state-divergence vulnerabilities on local kernels.
* [ ] Focus on BPF map namespace segregation issues in containerized pods.

## Phase 3: Dynamic LSM Confinement Prototype (Months 6-9)
* [ ] Develop a Rust BPF agent using the Aya compiler to dynamically filter namespaces via BPFLSM hooks.
* [ ] Target a default-deny policy matching container credentials at thread launch.

## Phase 4: Benchmarking & Writing (Months 10-12)
* [ ] Benchmark CPU overhead of runtime syscall filters.
* [ ] Write and defend the Master's thesis on **eBPF-Based Multi-Tenant Container Confinement**.