# Master's Research Roadmap

This roadmap reflects the 2025–2026 state of eBPF security research while preserving the repository's software-only Linux focus.

## Phase 1: Literature Aggregation & Taxonomy

- [x] Restructure and clean up the research repository.
- [x] Seed the reference library with the original core literature.
- [x] Re-check the research landscape against 2025–2026 primary sources.
- [x] Add BCF, AEE, Veritas/SpecCheck, BPF Token, KRAKENGUARD, vBPF and PeeR to the current-state analysis.

## Phase 2: Gap Verification

- [x] Mark the original generic dynamic-verification gap as partially addressed.
- [x] Mark the original generic BPF-namespace gap as substantially reframed by BPF Token and vBPF.
- [x] Mark generic TOCTOU detection/enforcement as an established area rather than an untouched gap.
- [x] Identify scalable fine-grained policy verification as the primary current opportunity.
- [ ] Re-run the literature search immediately before thesis proposal submission.

## Phase 3: Baseline Reproduction

- [ ] Obtain and build the KRAKENGUARD artifact.
- [ ] Record exact kernel/compiler/solver versions.
- [ ] Reproduce a representative subset of the published policy-analysis experiments.
- [ ] Build a corpus of benign, complex and malicious eBPF programs.
- [ ] Measure symbolic path count, solver time, memory and timeout behavior.

## Phase 4: Primary Prototype — Hybrid Policy Verification

- [ ] Define a narrow policy language for helper/map/memory/packet effects.
- [ ] Implement inexpensive abstract policy summaries.
- [ ] Use summaries to prune or merge symbolic states where sound.
- [ ] Fall back to symbolic execution for policy-relevant uncertainty.
- [ ] Preserve conservative reject-on-timeout behavior.
- [ ] Differential-test against the KRAKENGUARD baseline.

## Phase 5: Security & Performance Evaluation

- [ ] Verify no unsafe policy decision is introduced by the hybrid analysis.
- [ ] Test documented vulnerable eBPF programs where reproducible.
- [ ] Measure analysis latency and peak memory.
- [ ] Measure timeout rate and accepted/rejected program counts.
- [ ] Evaluate policy precision and false accept/reject cases.
- [ ] Measure program load/attach latency.

## Phase 6: Thesis Contribution

- [ ] State the exact invariant being provided.
- [ ] Document the threat model and assumptions.
- [ ] Compare against KRAKENGUARD and relevant verifier work.
- [ ] Perform a final 2026/2027 novelty sweep.
- [ ] Publish reproducible code, benchmark corpus and experiment scripts where licensing permits.
- [ ] Write the Master's thesis on **Scalable Fine-Grained eBPF Isolation through Hybrid Policy Verification** if the baseline and prototype support the hypothesis.

## Fallback Direction

If KRAKENGUARD reproduction proves impractical, the fallback is **revocable tenant-scoped BPF delegation and object lifecycle isolation**, restricted to BPF Token + BPF-LSM + map/link/pin lifecycle semantics.
