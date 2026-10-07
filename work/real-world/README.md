# Real-World eBPF/XDP Evaluation

This directory adds a separate **real-world workload evaluation** to the hybrid-policy-verification study.

It complements the controlled synthetic experiments under `work/scaling/`:

- controlled experiments establish causal relationships between instruction/path dimensions and verification cost;
- this workload study asks whether the same hybrid mechanism behaves meaningfully on substantially more realistic eBPF/XDP applications.

## Research question

> On publicly available real-world eBPF/XDP programs, how often can the abstract policy analysis discharge the policy, and what end-to-end verification cost remains when unresolved programs fall back to KRAKENGUARD?

The study is deliberately descriptive. It does not assume that the hybrid architecture wins on every workload.

## Initial corpus

The first corpus contains:

| ID | Workload | Application role | Primary source |
|---|---|---|---|
| `katran` | Katran balancer | XDP L4 load balancing | dslab-epfl/ebpf-se example with upstream Facebook provenance |
| `hxdpfw` | hXDP firewall | XDP firewall | dslab-epfl/ebpf-se example with upstream hXDP provenance |
| `fluvia` | Fluvia | XDP/IPFIX telemetry | dslab-epfl/ebpf-se example with upstream Fluvia provenance |
| `crab` | CRAB load balancer | XDP load balancing | dslab-epfl/ebpf-se example with upstream CRAB provenance |
| `synproxy` | XDP SYNPROXY | SYN-flood/DDoS protection | xdp-project/bpf-examples |
| `xdp-filter` | xdp-filter | XDP packet filtering | xdp-project/xdp-tools |
| `xdp-forward` | xdp-forward | XDP forwarding plane | xdp-project/xdp-tools |

The dslab-epfl/ebpf-se XDP examples are **real application code used as symbolic-execution benchmarks**. They are not artificial instruction ladders. Their repositories retain provenance links to the original Katran, hXDP, Fluvia and CRAB projects.

The benchmark source revisions are pinned in `corpus.json`. Upstream projects are recorded separately so that source provenance remains auditable.

## Important provenance rule

The benchmark never rewrites a real workload into a miniature substitute.

A workload is either:

1. benchmarked from the pinned public source representation;
2. benchmarked through an explicitly documented build/harness adaptation required by the verification backend; or
3. recorded as incompatible / unsupported.

An unsupported workload is **not** converted to SAFE and is **not** silently modified until it works.

## Policy

The evaluation reuses the already frozen Phase 5 policy:

`270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`

This keeps the real-world study from changing the policy to obtain a desired result.

A real program containing policy operations outside the analyzer's current domain may legitimately produce `UNKNOWN` and therefore exercise the symbolic fallback. That is data about analyzer coverage, not a verifier failure.

## Measurement modes

The timing runner evaluates the same three conditions as the validated comparative workbench:

- `symbolic_only` — frozen KRAKENGUARD for every compatible program;
- `abstract_only` — abstract policy analysis only;
- `hybrid` — abstract analysis first, with KRAKENGUARD only on `UNKNOWN`.

Primary timing is complete verifier-section wall time:

- symbolic: `client.verify()` plus authoritative verdict extraction;
- abstract: in-process `AbstractPolicyAnalyzer.analyze()`;
- hybrid: abstract section plus the same symbolic section only when fallback is invoked.

Archive copying is outside the primary timing endpoint.

## Correctness model

The external workload corpus does not come with an independently audited policy oracle for this research policy.

Therefore the real-world benchmark reports:

- KRAKENGUARD symbolic-only verdict;
- abstract verdict;
- hybrid verdict;
- hybrid-vs-symbolic-reference agreement.

This is a **consistency check against the frozen symbolic baseline**, not an independent proof that KRAKENGUARD is universally correct.

## Workflow

From the repository root:

### 1. Prepare public sources

```bash
python3 work/real-world/prepare_corpus.py
```

This clones only the pinned public repositories into:

`work/real-world/runtime/sources/`

The source checkouts are ignored by git.

### 2. Build / discover benchmark objects

```bash
python3 work/real-world/prepare_corpus.py --build
```

For the dslab-epfl/ebpf-se examples, the script uses the documented `xdp-target` build path.

For xdp-project examples, it runs the project's own Makefile and discovers the generated eBPF ELF.

No source transformation is performed.

### 3. Inspect compatibility and static complexity

```bash
python3 work/real-world/inventory.py
```

The inventory records:

- source provenance;
- source LOC;
- selected eBPF source path;
- functions;
- map/helper references;
- object SHA-256;
- compiled instruction count when an object is available;
- branch/jump count when disassembly is available;
- compatibility status.

### 4. Run timing

Use the same frozen KRAKENGUARD artifact and Phase 5 policy as the validated workbench:

```bash
python3 work/real-world/run_real_world.py --mode all
```

Default timing controls are 2 warmups, 7 measured repetitions and a 300-second timeout. They can be overridden from the command line.

### 5. Analyze

```bash
python3 work/real-world/analyze_real_world.py
```

The analysis reports:

- per-program abstract verdict and route;
- symbolic-only, abstract-only and hybrid medians;
- absolute and percentage hybrid savings;
- fallback/discharge coverage;
- observed KLEE completed paths;
- hybrid-vs-symbolic verdict agreement;
- per-workload failures/timeouts;
- descriptive relationships between static complexity and timing.

## Separation from existing evidence

Nothing in this directory changes:

- `research/experiments/results/phase5-validation/`;
- `research/experiments/corpus/phase5/`;
- `work/scaling/runtime/`;
- the frozen KRAKENGUARD artifact.

Real-world results belong under:

`work/real-world/runtime/results/`

and remain a separate evidence set.

## Planned second stage

After the initial five core XDP workloads have been compatibility-checked, additional real-world programs can be added without changing the measurement protocol.

The first priority is **Katran**, because published symbolic-execution work has already demonstrated that its real workload can reach a very large path space. The other workloads provide security/firewall, telemetry and independent load-balancing diversity rather than repeated variants of one handwritten microbenchmark.
