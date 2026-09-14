# KRAKENGUARD Original Evaluation Claims

This file records published results separately from our reproduction. These numbers are **not** measurements from this repository's host.

## Published environment

The NSDI 2026 paper reports all experiments on an Azure `B16als_v2` VM with 16 vCPUs, 32 GiB RAM and a 64 GiB NVMe SSD, running Ubuntu 24.04 LTS with kernel `6.17.0-1008-azure`.

## Published single-program performance table

| Program | Time (s) | Memory (MiB) | Paths | LOC | Instructions | Features |
|---|---:|---:|---:|---:|---:|---|
| Katran | 0.98 | 91.547 | 109 | 4244 | 53,630 | H,M,P |
| Electrode FAST_REPLY | 0.46 | 93.113 | 21 | 589 | 8,696 | H,M,P |
| Electrode FAST_QUORUM_PRUNE | 28.30 | 218.184 | 77 | 480 | 12,666 | H,M,P |
| hXDP (firewall) | 0.34 | 81.266 | 10 | 686 | 11,165 | H,M,P |
| Fluvia | 0.95 | 84.281 | 23 | 156 | 148,975 | H,M,P |
| xdp_fwd_kernel | 0.28 | 79.688 | 5 | 157 | 5,545 | H,M,P |
| xdp_tx_iptunnel | 0.32 | 79.488 | 10 | 176 | 8,375 | H,M,P |
| CVE-2022-23222 | 0.22 | 75.465 | — | 85 | — | D |
| CVE-2020-8835 | 0.21 | 68.773 | — | 181 | — | D |
| CVE-2021-4204 | 0.21 | 73.398 | — | 123 | — | D |
| ekubelet-leak.c | 0.25 | 85.316 | 9 | 404 | 15,377 | H,D |
| rop.bpf.c | 0.32 | 95.540 | 14 | 380 | 17,202 | H,D |

H = helper-function policy, M = map-access policy, P = packet-access policy, D = malicious-program detection.

## Published cross-program results

| Program pair | Time (s) | Memory (MiB) | Paths | LOC | Instructions |
|---|---:|---:|---:|---:|---:|
| electrode-katran FAST_REPLY | 3.67 | 105.652 | 1,289 | 4,813 | 139,554 |
| electrode-katran FAST_QUORUM_PRUNE | 62.69 | 256.363 | 2,881 | 4,813 | 234,416 |

The paper also reports one XDP cross-program scenario taking 0.897 seconds total, with 0.306 seconds spent checking each program against its individual policy and the remainder spent on cross-program analysis.

## Published policy-complexity observation

The paper explicitly reports varying policy complexity by enabling/disabling constraints (H/M/P) while observing **no change in execution time, explored paths or memory**, because those quantities were driven by the eBPF program. This is important: it weakens the repository's earlier assumption that policy complexity itself will necessarily be the dominant scalability axis.

## Published bottleneck observation

The paper reports one problematic `bmc_cache` case where KRAKENGUARD did not terminate within a few minutes even though the Linux in-kernel verifier accepted the program. The authors attribute the long execution to symbolic execution of a program whose hash value is used in conditional branches, producing large SMT expressions.

The paper contrasts this with the kernel verifier's abstract-interpretation approach and explicitly identifies combining abstract interpretation with symbolic execution as a possible scalability direction. It also reports a conservative timeout policy for non-terminating analyses.

## Published caching observation

The paper's discussion also notes that analysis and loading could be decoupled and that combinations of popular eBPF programs and policies could be analyzed a priori and cached. This is a **published future-work observation**, not evidence that incremental policy verification is already required or that caching would improve our workload.

## Reproduction implication

The strongest artifact-backed Phase 3A questions are therefore:

1. Can the published performance numbers be approximately reproduced on our frozen host?
2. Does the `bmc_cache`-style path/SMT bottleneck reproduce?
3. Does program complexity, rather than policy complexity, dominate cost on our controlled corpus?
4. Does a policy delta actually trigger substantial repeated work in the implementation?
5. If policy changes are cheap already, should the Phase 4 question move away from incremental policy verification and toward sound program-side hybrid abstraction/symbolic analysis?

The answer to these questions must come from our own measurements before a contribution is implemented.
