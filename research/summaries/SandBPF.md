# Paper Summary: Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing

## Metadata
* **Title:** Unleashing Unprivileged eBPF Potential with Dynamic Sandboxing
* **Authors:** Soo Yee Lim (UBC), Xueyuan Han (WFU), Thomas Pasquier (UBC)
* **Year:** 2023
* **Venue:** 1st SIGCOMM Workshop on eBPF and Kernel Extensions (eBPF '23)
* **URL:** https://arxiv.org/abs/2308.01983
* **Relevance Score:** 9.0/10

## Abstract
For safety reasons, unprivileged users today have only limited ways to customize the kernel through eBPF. We propose SandBPF, a software-based kernel isolation technique that dynamically sandboxes eBPF programs to allow unprivileged users to safely extend the kernel. Our early proof-of-concept shows that SandBPF can effectively prevent exploits missed by eBPF's native safety mechanism (static verification) while incurring 0%-10% overhead on web server benchmarks.

## Research Problem
Modern Linux kernels restrict the creation/loading of eBPF programs to privileged users (or require `CAP_SYS_ADMIN` / `CAP_BPF`) because bugs in the eBPF verifier allow malicious BPF code to bypass checks, corrupt kernel memory, and execute arbitrary code. This restriction severely limits non-privileged applications & containers from using eBPF for custom auditing, scheduling, or networking.

## Motivation
The eBPF verifier acts as a complex blocklist. Incessant CVEs from 2010 to 2023 (56 total, 62% in the verifier) show that static verification is highly prone to specification and implementation bugs. Verification of the verifier itself is extremely difficult due to code complexity (which more than doubled from 7.3k LoC in v5.0 to 17.9k LoC in v6.3). Thus, a dynamic enforcement mechanism is required.

## Methodology
SandBPF intercepts the JIT compilation output and performs post-JIT binary rewriting to instrument instructions.
1. **Memory isolation:** Inserts address masking checks on all read/write memory operations.
2. **Control flow integrity:** Redirects jump/call instructions to verified trampolines that check target capabilities.
3. **Execution safety:** Disables interrupts/preemption during program runs and uses a reserved per-core sandbox page.

## Architecture
```
[eBPF Bytecode] -> [JIT Compiler] -> [eBPF Native Code] -> [SandBPF Binary Rewriter] -> [Sandboxed Execute]
                                                                    |
                                                            [Address Masking]
                                                            [Trampoline Checks] -> [Sandbox Context & Memory]
```
The sandboxed execution space includes:
* **Per-core Sandbox:** 1 page (4KB) per CPU core, containing Heap, Stack, and Context info.
* **Metadata & Allowlist:** Read-only structures containing valid helper call addresses.

## Threat Model
* **Adversary capabilities:** Can load eBPF programs, and exploit logic bugs to corrupt memory or gain arbitary read/write/execution.
* **Trusted Computing Base (TCB):** System kernel (excluding BPF verifier and JIT compiler) plus SandBPF.
* **Untrusted components:** eBPF bytecode, JIT output, sandbox data.

## Experimental Setup
* **CPU:** Intel Core i7 (8 cores, 2.3 GHz), 32GB RAM. Disabled hyperthreading, turbo boost.
* **OS:** Linux Kernel 5.18.7 (Vanilla vs Sandboxed).
* **Test cases:** XDP packet logger, Socket Filter with ring buffer, Katran L4 load balancer.

## Evaluation Metrics
* **CPU execution time** (nanoseconds per eBPF invocation).
* **Relative application throughput/latency** (Apache web server performance).

## Results
* **Microbenchmarks:**
  * XDP: ~2100 ns overhead due to sandbox context switching.
  * Socket Filter: ~2500 ns overhead.
  * Katran: ~2200 ns overhead.
* **Macrobenchmarks:** Web server throughput impact ranges between 0% and 10%.

## Strengths
* Independent of Verifier and JIT correctness (operates on raw JIT output).
* Zero changes needed to user-space tools or BPF code.
* Effective dynamic enforcement against bugs like CVE-2021-29154.

## Weaknesses
* Reserving a single page restricts BPF memory footprint to 4KB (heap + stack).
* High overhead on small BPF programs due to sandbox management / context entry-exit.
* Relies on software-based masking which is CPU-cycle intensive.

## Limitations
* No support for running multiple concurrent unprivileged scripts per core (without preemption).
* Lacks complex helper validation (e.g. nested structures are difficult to copy).

## Future Work
* Port SandBPF to leverage hardware-assisted features like ARM PAC or MTE.
* Optimize context switches to reduce the 2-microsecond baseline setup overhead.

## Research Gaps
* Efficient dynamic runtime check mechanisms that do not restrict program size or context format.

## Key Quotes
* *"A verified eBPF program is not always safe... sandboxing is a key step towards unleashing the potential of unprivileged eBPF."*
* *"SandBPF dynamically sandboxes eBPF programs to allow unprivileged users to safely extend the kernel."*

## Personal Notes
* SFI shows reasonable overhead for macrobenchmarks but microbenchmarks reveal high absolute latency for simple hooks. This makes it challenging for packet-processing hotpaths.

## Relation to Current Research
* This establishes the need for runtime dynamic sandboxing in multi-tenant environments where the verifier cannot be trusted to isolate tenants.