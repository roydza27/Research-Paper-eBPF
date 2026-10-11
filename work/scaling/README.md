# Controlled Time/Space Scaling Workbench

This directory extends the validated comparative benchmark with a **parameterized scaling study**. It is deliberately isolated under `work/` and never writes to the authoritative Phase 5 result directories.

## Research question

> As program size and feasible symbolic-path complexity increase, does the hybrid architecture avoid the dominant symbolic cost when abstract analysis can discharge the policy, while preserving KRAKENGUARD fallback for unresolved cases?

The study separates two dimensions that the existing 24-program benchmark mixes:

1. **Program-size scaling**: approximately constant path count while compiled instruction count grows.
2. **Path scaling**: approximately constant helper/map/policy structure while feasible symbolic path count grows.

## Families

The generator creates four frozen semantic families:

| Family | Expected result | Purpose |
|---|---|---|
| A-size | COMPLIANT / abstract SAFE | isolate instruction-count effect on the fast path |
| C-size | POLICY VIOLATION / abstract VIOLATION | isolate instruction-count effect on the fast reject path |
| B-path | COMPLIANT / abstract UNKNOWN | measure fallback as symbolic paths grow |
| D-path | POLICY VIOLATION / abstract UNKNOWN | measure fallback as symbolic paths grow |

The path family reuses the validated E2 construction: one `bpf_ktime_get_ns()` value, independent bit predicates, and externally visible packet-memory mutations so LLVM optimisation does not erase the symbolic control flow. Fallback path scaling starts at one predicate (2 feasible paths); a zero-predicate case has no unresolved branch and is therefore excluded from the B/D scaling families.

## Timing conditions

The runner evaluates:

- `symbolic_only`
- `abstract_only`
- `hybrid`

For hybrid:

- SAFE/VIOLATION -> terminate after abstract analysis.
- UNKNOWN -> run the same KRAKENGUARD verifier.

Warmups and measured repetitions are configurable; the default is 2 warmups and 7 measured repetitions.

The primary endpoint is complete end-to-end wall time for each generated program. Archive/serialization work is outside the timed verifier sections, as in the validated comparative workbench.

## Independent variables

For size families:

- measured compiled instruction count is the primary coordinate;
- basic blocks and branches are recorded as secondary structural variables.

For path families:

- **observed KLEE explored paths** is the primary coordinate (2, 4, 8, 16, 32, 64 for B/D);
- target predicate count and target path count are structural variables.

No asymptotic class is assumed in advance.

## Correctness

For generated programs the semantic label is determined by construction and recorded in the manifest:

- size-A and path-B are compliant;
- size-C and path-D contain a forbidden `bpf_trace_printk` action.

The run reports KRAKENGUARD's observed verdict against the generated expected label and separately reports hybrid agreement. This is a construction-based validation for the scaling corpus, not an independent proof that KRAKENGUARD is universally correct.

## Resource/space study

Time and memory are separate campaigns.

The space runner uses Linux cgroup-v2 `memory.peak` for the KRAKENGUARD container where available, and the isolated abstract worker's process `ru_maxrss` for abstract analysis. The kernel documents `memory.peak` as the maximum cgroup memory usage since creation or reset and permits resetting it by writing a non-empty value.

Space results must never be combined with the primary timing results unless the execution scope and measurement boundary are explicitly identical.

## Frozen controls

The runner inherits the validated controls from `work/comparison-config.json`:

- KRAKENGUARD commit `e7bd84005b304c5a10efcdb04914d1882b3cccf7`
- frozen policy SHA-256 `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`
- immutable container digest `kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4`
- XDP
- x86_64
- deterministic seed

Kernel/compiler are recorded at run time and must remain stable during a campaign.

## Run order

1. Generate and compile the corpus.
2. Inspect and freeze object hashes.
3. Run a small smoke test.
4. Inspect correctness, path counts, and static metrics.
5. Run the full timing campaign.
6. Run the independent space campaign.
7. Analyze scaling relationships and uncertainty.

Nothing in this directory changes the validated Phase 5 evidence.
