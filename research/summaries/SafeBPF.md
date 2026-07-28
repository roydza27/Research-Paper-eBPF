# Paper Summary: SafeBPF: Hardware-assisted Defense-in-depth for eBPF Kernel Extensions

## Metadata
* **Title:** SafeBPF: Hardware-assisted Defense-in-depth for eBPF Kernel Extensions
* **Authors:** Soo Yee Lim (UBC), Tanya Prasad (UBC), Xueyuan Han (WFU), Thomas Pasquier (UBC)
* **Year:** 2024
* **Venue:** ACM Cloud Computing Security Workshop (CCSW '24)
* **URL:** https://arxiv.org/abs/2409.07508
* **Relevance Score:** 9.5/10

## Abstract
The eBPF framework executes user-provided code in the Linux kernel. Discoveries of memory safety vulnerabilities have forced security teams to disable unprivileged eBPF. To improve run-time safety, we introduce SafeBPF, which isolates eBPF programs from the rest of the kernel. We evaluate a software-based Software Fault Isolation (SFI) approach as well as a hardware-assisted implementation leveraging ARM's Memory Tagging Extension (MTE). SafeBPF incurs up to 4% overhead on macrobenchmarks.

## Research Problem
The main problem is that static validation (eBPF verifier) is blind to dynamic out-of-bound array index overrides and type confusions caused by concurrency bugs. When these bugs occur, BPF programs gain raw pointer arithmetic access to general kernel data structures, endangering multi-tenant hosts.

## Motivation
We need a defense-in-depth framework that runs alongside the verifier or replaces its memory protection path. Rather than relying on simple software checks (which SandBPF showed can be slow), we can use ARM's hardware-assisted Memory Tagging Extension (MTE) to enforce spatial and temporal bounds checks.

## Methodology
SafeBPF provides two backends:
1. **SafeBPF-SFI (Software):** Improves on SandBPF by optimizing instructions and combining bounds-checks.
2. **SafeBPF-MTE (Hardware):** Utilizes ARM AArch64 MTE. Maps BPF stacks, maps, and temporary heaps with unique 4-bit tags. The pointer is modified to contain matching tags. If BPF attempts to write to a tag-mismatched kernel address, the CPU triggers a physical fault.

## Architecture
```
 [eBPF Core Invocation]
        │
        ├──> [SafeBPF-MTE Environment] ──> Tag memory regions (4-bit Key)
        │                                  Verify hardware access permissions
        └──> [SafeBPF-SFI Environment] ──> Perform software masking & jumps
```

## Threat Model
* **Threats:** Exploits targeting eBPF helper memory manipulation (e.g. CVE-2022-23222).
* **Scope:** Malicious eBPF code loaded by local unprivileged processes.
* **TCB:** Linux core, SafeBPF runtime setup.

## Experimental Setup
* **CPU:** ARMv8.5-A emulation / ARM hardware supporting MTE (e.g. Pixel 8, or emulation via QEMU).
* **Tests:** Netperf benchmarks, Apache benchmarking, syscall monitoring.

## Evaluation Metrics
* **Execution latency** (microseconds per request).
* **Throughput overhead** under extreme networking loads.

## Results
* SafeBPF-MTE achieves **<4% overhead** on macrobenchmarks.
* Outperforms SafeBPF-SFI by 2x in terms of raw instruction execution time, as SFI requires 2-3 extra instructions per load/store.

## Strengths
* Highlights a direct comparison between software SFI and hardware MTE for eBPF.
* Enforces fine-grained temporal and spatial memory safety.
* Strong security posture with minimal code modifications.

## Weaknesses
* Tag collision probability: A 4-bit MTE tag provides 16 options, meaning there is a 1/16 (6.25%) chance a random corrupted pointer matches a tag.
* MTE support is still evolving on server CPUs (mostly restricted to ARM Graviton or premium systems).

## Limitations
* Does not support old kernels (requires recent Linux versions with tagged address space support).

## Future Work
* Integrating SafeBPF with standard cloud runtimes (e.g., Cilium eBPF components).
* Porting to Intel's PML (Page Modification Logging) or MPK.

## Key Quotes
* *"SafeBPF isolates eBPF programs from the rest of the kernel to prevent exploitations of verifier breaches."*
* *"SafeBPF-MTE demonstrates that hardware-assisted tagging provides robust security with negligible performance impact."*

## Relation to Current Research
* SafeBPF offers a direct path to securing shared Kubernetes nodes handling multiple containers.