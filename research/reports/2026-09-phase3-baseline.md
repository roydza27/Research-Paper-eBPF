# Phase 3 — Baseline Reproduction & Experimental Infrastructure

**Date:** 2026-09-14  
**Status:** Infrastructure prepared; baseline execution pending on a documented experimental host.

> This report deliberately does not claim successful reproduction or benchmark results that have not been executed. Phase 3 is a decision gate, not a proposal-defense exercise.

## 1. Executive Summary

Phase 2 established that the broad research claims are no longer sufficient: KRAKENGUARD provides fine-grained policy analysis, BCF provides proof-guided verifier refinement, BPF Token changes the delegation model, vBPF changes the tenant-virtualization model, and PeeR demonstrates resource-isolation concerns.

The repository roadmap therefore makes KRAKENGUARD reproduction the first Phase 3 milestone and explicitly defers the hybrid verifier prototype until a measurable baseline limitation is demonstrated.

The current Phase 3 work establishes:

- a reproducibility specification;
- a controlled eBPF benchmark corpus;
- a policy corpus using the documented KRAKENGUARD constraint vocabulary;
- a benchmark manifest with repetitions and timeout rules;
- a generic execution adapter that refuses to pretend an arbitrary command is native KRAKENGUARD;
- raw-result collection and machine-readable analysis;
- a ProcessScope evaluation boundary;
- a failure-analysis and decision-gate format.

**No performance, correctness, scalability, or security result is claimed yet.**

## 2. Phase 2 Conclusions Being Tested

The Phase 2 surviving hypothesis was narrowed to policy-level verification cost and reuse rather than generic eBPF isolation. The current testable form is:

> Can a restricted fine-grained eBPF policy be checked with lower repeated analysis cost when only policy constraints change, while preserving the same security decision as full analysis?

This remains a hypothesis until artifact-level reproduction.

## 3. Experimental Questions

| ID | Question | Evidence required |
|---|---|---|
| RQ1 | Can KRAKENGUARD be reproduced reliably? | Frozen artifact, environment, build log, native examples |
| RQ2 | How does cost change with program complexity? | Repeated timing/resource measurements |
| RQ3 | How does cost change with policy complexity? | Program × policy matrix |
| RQ4 | Where does symbolic/state complexity become a bottleneck? | Native state/path/solver telemetry where exposed |
| RQ5 | How accurately are compliant and violating programs distinguished? | Labeled corpus + decision matrix |
| RQ6 | How do multi-constraint policies behave? | Differential policy runs |
| RQ7 | What limitations remain after BPF Token/vBPF? | System comparison, not namespace assumptions |
| RQ8 | Is ProcessScope useful infrastructure? | Capability-to-requirement assessment |
| RQ9 | Is the Phase 4 direction justified? | Measured limitation + threat/validity analysis |

## 4. Experimental Environment

The repository must not record the assistant/container environment as the research host. The actual experiment host is still **pending**.

Run:

```bash
cd research/experiments/environment
chmod +x collect-environment.sh
./collect-environment.sh
```

The collector records kernel, architecture, CPU, memory, BTF availability, toolchain versions, container runtime and relevant kernel configuration. The resulting JSON must be committed or archived together with benchmark metadata after the host is frozen.

Required frozen fields include:

- CPU model and thread count;
- RAM and storage;
- architecture and virtualization state;
- distribution and kernel version;
- kernel configuration;
- BTF availability;
- clang/LLVM, libbpf/bpftool, GCC;
- Rust/Cargo/Python;
- solver versions;
- container runtime;
- baseline repository commit identifiers.

## 5. Baseline Selection

### Primary: KRAKENGUARD

KRAKENGUARD is the direct baseline because its public artifact describes a bytecode-level policy pipeline using lifting, LLVM transformation, verification-harness generation and KLEE symbolic execution. Its documented policy dimensions include helper, memory, map and return-value behavior, and its examples include cross-program analysis and CVE cases.

The public repository is available at https://github.com/krakenguard-ebpf/krakenguard. The Phase 3 manifest freezes commit `e7bd84005b304c5a10efcdb04914d1882b3cccf7` as the initial reproduction target.

**Reproduction classification:** partially reproducible / execution pending. The source, documentation and example corpus are public, but no independent build has been completed in this phase yet.

### Secondary: BCF

BCF is relevant for the verifier-assurance side of the Phase 2 question. Its public artifact includes kernel patches, proof tooling, eBPF programs and evaluation scripts and documents a VM-based environment.

**Classification:** partially reproducible / execution pending.

### Contextual: Veritas / SpecCheck

Veritas is important for verifier correctness and differential testing but is not a direct equivalent of a fine-grained policy manager. It should therefore be used as a verifier-assurance comparison, not as a substitute KRAKENGUARD baseline.

**Classification:** partially reproducible / execution pending; comparison-only in the first experiment pass.

### Not primary Phase 3 reproduction targets

- **AEE:** runtime enforcement against verifier approximation; relevant to assurance, not the same policy-analysis workload.
- **PeeR:** resource scheduling/isolation; orthogonal to policy verification.
- **vBPF:** tenant virtualization/state isolation; important contextual comparison, but not a policy-verifier baseline.
- **BPF Token:** native kernel delegation primitive; evaluated from Linux source/configuration rather than reproduced as a research artifact.
- **Linux verifier:** evaluated through the target kernel and native BPF tooling.

The point is to avoid reproducing papers merely because they are recent.

## 6. KRAKENGUARD Reproduction

The public KRAKENGUARD README specifies LLVM 13, Z3, Python/Jinja2, libbpf and standard build tools. It provides a setup script and Docker workflow and lists examples including firewall, Katran, CVE cases, eBPF-as-a-Service and cross-program analysis.

The first reproduction sequence is therefore:

1. freeze host environment;
2. clone the exact target commit with submodules;
3. preserve the original setup process;
4. build without source modifications;
5. run a native example such as `fw:test-object` or another documented example;
6. record build/runtime logs;
7. only after successful smoke reproduction, map the controlled corpus into the artifact's actual accepted input format;
8. reproduce representative published workloads before running new experiments.

The repository's example policy syntax was inspected directly. A representative policy uses `type: ACTION`, dependency fields and action dimensions such as `memory_access`, `map_access`, `helper_access` and `return_value`. The Phase 3 policy corpus follows this documented vocabulary rather than inventing a new policy language.

**Current result:** reproduction has not yet been executed on the user's experimental host, so no successful-reproduction claim is made.

## 7. Other Baseline Reproduction

BCF and Veritas both expose substantial artifacts, but they require different environments and answer different questions. They should be reproduced only to the extent needed for the differential research question.

The first comparison should therefore be:

1. KRAKENGUARD native examples;
2. BCF representative verifier-refinement examples;
3. Veritas/SpecCheck verifier-decision examples where the VM setup is practical.

A failed build must be recorded using the failure schema rather than silently replaced with another implementation.

## 8. Benchmark Corpus

The corpus currently contains five synthetic program classes:

| Program | Class | Purpose |
|---|---|---|
| `a_minimal_xdp.c` | A | Minimal control-flow baseline |
| `b_helper_map.c` | B | Helper + map interaction |
| `c_branching_maps.c` | C | Branching + state-dependent map access |
| `d_policy_sensitive.c` | D | Helper + map + memory + return policy dimensions |
| `e_adversarial_helper.c` | E | Synthetic helper-policy violation |

This is an initial corpus, not a claim of representativeness. It must grow only when an experimental question requires another controlled dimension.

No real exploit tooling is included.

## 9. Policy Corpus

The current policies are:

- `p1_allow_execution.json` — minimal documented memory/helper policy shape;
- `p2_helper_allowlist.json` — selected helper access;
- `p3_helper_map_policy.json` — helper plus named map access;
- `p4_policy_sensitive.json` — combined memory/map/helper/return constraints.

The policy corpus is intentionally tied to the baseline's supported vocabulary. Unsupported semantics must be classified as unsupported rather than used to make a baseline appear weaker.

## 10. Experimental Methodology

The experiment design is a factorial program × policy matrix.

### A — Program complexity

Increase branches, helpers, maps and control-flow complexity while holding the policy as constant as possible.

### B — Policy complexity

Increase the number of constrained dimensions while holding the program fixed.

### C — Program × policy interaction

Run each compatible program against each policy and classify outcomes as accepted, rejected, unsupported, timeout or unknown.

### D — Scaling

Increase program complexity, policy complexity and, where the baseline supports it, tenant/program count.

### E — Adversarial cases

Use synthetic policy violations and verifier-stress cases. Do not create real-world exploit payloads merely for benchmarking.

## 11. Metrics

The benchmark manifest freezes the initial measurement fields:

- wall-clock time;
- user/system CPU time;
- peak memory;
- timeout rate;
- accepted/rejected/unknown outcomes;
- instruction count;
- basic-block count;
- branch/loop count;
- helper/map count;
- policy-constraint count;
- symbolic states/path count when exposed;
- solver query count and solver time when exposed.

Seven measured repetitions plus two warmups are the initial default. This is a reproducibility configuration, not a statistical-significance claim.

## 12. Results

**Pending.** No baseline benchmark has been executed on the frozen experimental host yet.

This section must not be populated with estimated values.

## 13. Differential Testing

Differential testing is prepared but blocked on native artifact execution. Once multiple systems accept the same input representation, the same corpus must be run through each system and every disagreement investigated.

The comparison must preserve distinctions among:

- accepted;
- rejected;
- unsupported;
- timeout;
- unknown;
- infrastructure failure.

## 14. Scalability Analysis

The intended first analysis is empirical, not theoretical.

For each controlled dimension, plot or tabulate:

- median analysis time;
- p95 analysis time;
- peak memory;
- timeout frequency;
- state/path count where exposed.

Only after sufficient observations should the report discuss whether growth appears approximately linear, polynomial, exponential or irregular. Observed scaling must remain separate from asymptotic complexity claims.

## 15. Failure Analysis

Every reproduction failure must use:

```text
System:
Version/commit:
Environment:
Expected:
Observed:
Failure:
Root cause:
Workaround:
Impact on reproduction:
```

Failures must be classified as environment, dependency, undocumented requirement, source incompatibility, kernel incompatibility, experimental limitation or fundamental system limitation.

## 16. ProcessScope Evaluation

ProcessScope is currently best classified as **supporting experimental infrastructure / independent observability prototype**, not the thesis contribution.

Its public README describes an eBPF tracepoint collector feeding a BPF ring buffer and Rust userspace engine. The current eBPF collector attaches to `sched_process_exec` and records process execution information including PID, PPID, UID, GID, command name and filename.

The current project therefore provides useful capabilities for:

| Requirement | Current assessment |
|---|---|
| Process observation | Yes |
| eBPF event collection | Yes |
| Container identity | Not established |
| cgroup identity | Not established |
| namespace identity | Not established |
| tenant identification | Not established |
| event correlation | Partial/userspace-oriented |
| policy enforcement | No evidence of the Phase 3 policy-verification mechanism |
| benchmark execution | No dedicated harness identified |
| telemetry collection | Yes |

If used as research infrastructure, the minimum useful additions would be explicit cgroup/namespace identity capture, stable event schema/versioning, benchmark-mode output, machine-readable export and experiment metadata. It should not be redesigned into a verifier merely because it already exists.

## 17. Production-System Context

Production systems remain context rather than reproduction targets.

- **Tetragon:** kernel-resident filtering/enforcement and Kubernetes-aware identities make it relevant to runtime policy enforcement.
- **Cilium:** demonstrates production-scale eBPF networking/security policy and workload identity.
- **Falco:** demonstrates runtime detection rather than symbolic policy verification.
- **Tracee:** provides eBPF-based security telemetry and detection.
- **KubeArmor:** demonstrates container-aware runtime security policy enforcement.

These systems prevent the thesis from assuming that production lacks kernel-resident enforcement. The research baseline must therefore focus on the measurable verification-cost problem rather than generic runtime enforcement.

## 18. Threats to Validity

1. A small synthetic corpus may not represent real-world eBPF programs.
2. KRAKENGUARD's internal state/solver telemetry may not expose every metric requested by this plan.
3. Different baseline systems accept different input representations, limiting direct comparison.
4. VM/container environments may change timing and memory behavior.
5. Kernel/compiler changes can invalidate reproducibility.
6. Seven repetitions are sufficient for a first reproducibility pass but do not automatically establish statistical significance.
7. Unsupported or timeout results cannot be interpreted as security correctness.
8. A benchmark artifact may be available without guaranteeing artifact-evaluation parity with the published environment.

## 19. Reproducibility Assessment

Current state:

- repository baseline: inspected;
- Phase 2 conclusions: incorporated;
- KRAKENGUARD source: available;
- KRAKENGUARD native build: pending;
- BCF artifact: available;
- BCF reproduction: pending;
- benchmark corpus: prepared;
- policy corpus: prepared;
- experiment harness: prepared;
- frozen host environment: pending;
- raw measurements: pending;
- differential measurements: pending.

Therefore Phase 3 is **not complete**.

## 20. Research Hypothesis Verdict

**Inconclusive at this stage.**

Phase 2 justified testing the hypothesis; Phase 3 infrastructure now makes that test reproducible. It would be scientifically incorrect to mark the hypothesis as a strong opportunity before the baseline is actually measured.

## 21. Implications for Phase 4

Do not begin hybrid verification yet.

The first Phase 4 gate should require evidence that:

1. KRAKENGUARD can be reproduced;
2. its analysis cost scales unfavorably for a controlled workload;
3. policy changes cause avoidable repeated analysis;
4. a narrower incremental/delta analysis opportunity can be stated precisely;
5. the proposed method can preserve equivalent security decisions.

If those conditions fail, the thesis direction must be narrowed or abandoned.

## 22. Recommended Phase 4 Research Question

Only if the Phase 3 measurements support it:

> **Can tenant-scoped eBPF security policies be incrementally re-verified after policy deltas, reusing unaffected verification state to reduce analysis cost while preserving the security decisions of full policy analysis?**

This is intentionally narrower than the original "Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification" title.

## 23. References

- KRAKENGUARD: https://github.com/krakenguard-ebpf/krakenguard
- KRAKENGUARD paper: https://www.usenix.org/conference/nsdi26/presentation/patel
- BCF: https://github.com/SunHao-0/BCF
- Veritas/SpecCheck: https://github.com/rs3lab/veritas
- Linux BPF verifier documentation: https://docs.kernel.org/bpf/verifier.html
- ProcessScope: https://github.com/roydza27/ProcessScope
