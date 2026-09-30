# KRAKENGUARD Phase 3 Failure Analysis

Artifact commit: e7bd84005b304c5a10efcdb04914d1882b3cccf7
Benchmark run: runs-krakenguard-20260925T183849Z

## Deterministic observed behaviors

| Program | Policy | Runs | Result | Observed reason |
|---|---|---:|---|---|
| a_minimal_xdp | p1_allow_execution | 7 | NO_VIOLATIONS |  |
| a_minimal_xdp | p2_helper_allowlist | 7 | NO_VIOLATIONS |  |
| a_minimal_xdp | p4_policy_sensitive | 7 | NO_VIOLATIONS |  |
| c_branching_maps | p1_allow_execution | 7 | POLICY_VIOLATIONS | Violated: Policy 'base_packet_read_only' blocks ALL map access, but maps were accessed |
| c_branching_maps | p2_helper_allowlist | 7 | POLICY_VIOLATIONS | Violated: Unauthorized map access to 'state' |
| c_branching_maps | p4_policy_sensitive | 7 | POLICY_VIOLATIONS | Violated: Unauthorized map access to 'state' |
| d_policy_sensitive | p1_allow_execution | 7 | POLICY_VIOLATIONS | Violated: Policy 'base_packet_read_only' blocks ALL map access, but maps were accessed |
| d_policy_sensitive | p2_helper_allowlist | 7 | POLICY_VIOLATIONS | Violated: Unauthorized map access to 'policy_state' |
| d_policy_sensitive | p4_policy_sensitive | 7 | POLICY_VIOLATIONS | Violated: Write access to read-only map 'policy_state' |
| e_adversarial_helper | p1_allow_execution | 7 | NO_VIOLATIONS |  |
| e_adversarial_helper | p2_helper_allowlist | 7 | NO_VIOLATIONS |  |
| e_adversarial_helper | p4_policy_sensitive | 7 | NO_VIOLATIONS |  |

## Source-level interpretation

- C accesses the `state` map after computing a key from `ctx->ingress_ifindex` and then reads the map value for threshold-based branching.
- D accesses `policy_state`, calls `bpf_ktime_get_ns`, and writes the returned timestamp into the map value on the data-range branch.
- P1 permits wildcard helper access but does not grant map access.
- P2 permits `bpf_map_lookup_elem` but specifies an empty map-access set.
- P4 permits `policy_state` with Read access and permits `bpf_map_lookup_elem`; D additionally performs a write.
- E calls `bpf_ktime_get_ns` without accessing a map and repeatedly receives NO_VIOLATIONS under P2 and P4.

## Interpretation boundary

- These are observed KRAKENGUARD conditional-policy behaviors, not claims about the security of eBPF generally.
- Seven repetitions of the same reason are repeated observations of one deterministic behavior, not seven independent defects.
- The E helper-policy miss is reproducible across 7/7 P2 runs and 7/7 P4 runs.
- Top-level verifier `Passed=True` is not used as the policy-correctness verdict.

## Phase 3 status

- KRAKENGUARD execution and repeated measurement: complete.
- Failure classification for measured KRAKENGUARD corpus: complete.
- Broader Phase 3 baseline/differential work: pending.
- Phase 4 implementation: not started.
