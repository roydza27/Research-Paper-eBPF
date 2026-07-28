# Paper Summary: Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing

## Metadata
* **Title:** Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing
* **Authors:** Soo Yee Lim, Xueyuan Han, Thomas Pasquier
* **Year:** 2023
* **Venue:** SIGCOMM Workshop on eBPF and Kernel Extensions
* **URL:** https://arxiv.org/abs/2308.01983
* **Relevance Score:** 9.0/10
* **Tags:** eBPF, Isolation, Runtime Security, SFI, Multi-Tenant

## Summary

### Research Problem
The Linux kernel restricts loading eBPF programs to privileged users with capabilities (`CAP_SYS_ADMIN` or `CAP_BPF`) to prevent exploitation of verifier-bypass CVEs. This stops non-privileged user-space applications and containerized workloads from writing customized performance and logging plugins, limiting the flexibility of eBPF in multi-tenant systems.

### Motivation
The primary safety mechanism of eBPF (static verification) acts as a blocklist of illegal instructions. As eBPF programs grew in capability, the verifier complexity more than doubled in size (7.3k LoC in 2019 to 17.9k LoC in 2023), resulting in logic errors and implementation bypasses (represented by 56 BPF CVEs between 2010 and 2023). A secondary, runtime safety boundary is needed.

### Proposed Solution
The authors propose **SandBPF**, a software-based runtime sandbox that dynamically isolates unprivileged eBPF programs from general kernel memory. 

### Methodology
SandBPF processes raw JIT-compiled native assembly code at load time.
1. **Memory Isolation (SFI):** Implements Software Fault Isolation. Binary rewriting inserts pointer masking checks before every memory load/store instruction. It ANDs/ORs pointers with a predefined address space mask associated with a temporary per-CPU core sandbox page, restricting all memory accesses.
2. **Control Flow Integrity (CFI):** Diverts all JIT call operations to a specialized, read-only trampoline block. It dynamically queries a hash tree to check if the destination address is within the authorized eBPF helper capability allowlist.

### Experimental Setup
* Evaluated on a bare metal machine with 8-cores, 2.3GHz CPU, 32GB RAM executing Linux Kernel 5.18.7.
* Tested three native eBPF workloads: XDP packet logger, Socket Filter with ring buffer interactions, and the Katran L4 load balancer.
* Compared Vanilla kernel performance versus the SandBPF modified JIT executor.

### Results
* **Microbenchmarks:** Introduces a baseline overhead of ~2-2.5 microseconds primarily due to sandbox allocation and context swap boundaries (preemption disabling).
* **Macrobenchmarks:** Apache Web Server throughput tests showed in-context overhead between 0% and 10% on realistic server loads.
* Successfully blocked verifier bypass exploits representing CVE-2021-29154.

### Limitations
* Reserving a single page restricts BPF heap and stack footprints to 4KB combined.
* Lacks optimization for high-density setups running many concurrent unprivileged programs.
* The software fault isolation instruction injections introduce branch prediction delays under intensive network hooks.

### Future Work
* Extending SandBPF architecture to explore incoming hardware-assisted primitives (MTE/PAC) on Arm CPUs.
* Refining memory sharing models to permit larger context structures without copy overhead.