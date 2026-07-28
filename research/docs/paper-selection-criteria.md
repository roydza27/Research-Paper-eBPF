# Paper Selection Criteria

To maintain a high signal-to-noise ratio in the repository, all potential additions must pass these verification gates.

## 1. Core Inclusion Gate
* **eBPF-Centric:** eBPF must be a primary contribution, technology stack, or target of the research (e.g. verifier analysis, LSM hook confinement, tracing agent).
* **Linux Systems Security:** Must be centered on Linux operating environments, networking (XDP/tc), container runtimes, or multi-tenant clouds.

## 2. Hard Exclusion Gate (Immediate Discard)
* **No Hardware Security:** Papers focusing on TEEs, AMD SEV, Intel SGX, ARM TrustZone, TPMs, or Secure Enclave designs are strictly out-of-scope.
* **No CPU Microarchitecture:** Exclude papers focusing on side-channels, branch predictions, Rowhammer, Spectre, Meltdown, or speculative execution.
* **No Generic Networking:** Exclude generic non-eBPF networking design papers.