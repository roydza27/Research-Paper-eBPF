# KRAKENGUARD Phase 3 Benchmark Analysis

Artifact commit: e7bd84005b304c5a10efcdb04914d1882b3cccf7
Benchmark run: runs-krakenguard-20260925T183849Z

## Dataset integrity

- Measured records: 84
- Combinations: 12
- Completed measured runs: 84
- No-violation records: 42
- Policy-violation records: 42

## Results

| Program | Policy | Runs | Outcome | Median wall ms | IQR ms | Range ms | CV % | Median client CPU ms | Median client RSS KB | Paths | Instructions |
|---|---|---:|---|---:|---:|---:|---:|---:|---:|---|---|
| a_minimal_xdp | p1_allow_execution | 7 | NO VIOLATIONS | 938.269 | 21.865 | 914.583-966.15 | 1.948 | 21.713 | 31548 | 1 | 12695 |
| a_minimal_xdp | p2_helper_allowlist | 7 | NO VIOLATIONS | 928.649 | 16.167 | 909.308-960.063 | 1.79 | 22.514 | 31708 | 1 | 12695 |
| a_minimal_xdp | p4_policy_sensitive | 7 | NO VIOLATIONS | 929.794 | 15.837 | 906.143-1099.646 | 6.875 | 22.867 | 31916 | 1 | 12695 |
| c_branching_maps | p1_allow_execution | 7 | POLICY VIOLATIONS | 936.198 | 36.815 | 917.087-974.39 | 2.447 | 22.928 | 31732 | 1 | 13127 |
| c_branching_maps | p2_helper_allowlist | 7 | POLICY VIOLATIONS | 945.26 | 15.223 | 927.792-961.339 | 1.246 | 22.325 | 31892 | 1 | 13127 |
| c_branching_maps | p4_policy_sensitive | 7 | POLICY VIOLATIONS | 942.996 | 20.621 | 928.337-967.127 | 1.552 | 22.583 | 31736 | 1 | 13127 |
| d_policy_sensitive | p1_allow_execution | 7 | POLICY VIOLATIONS | 949.905 | 14.366 | 943.729-964.886 | 0.93 | 21.514 | 31488 | 1 | 13277 |
| d_policy_sensitive | p2_helper_allowlist | 7 | POLICY VIOLATIONS | 984.492 | 25.917 | 930.462-1251.296 | 10.644 | 22.046 | 31356 | 1 | 13277 |
| d_policy_sensitive | p4_policy_sensitive | 7 | POLICY VIOLATIONS | 952.15 | 50.827 | 921.914-1039.535 | 4.333 | 22.422 | 31788 | 1 | 13277 |
| e_adversarial_helper | p1_allow_execution | 7 | NO VIOLATIONS | 931.488 | 19.065 | 911.811-957.94 | 1.789 | 22.34 | 31428 | 1 | 12712 |
| e_adversarial_helper | p2_helper_allowlist | 7 | NO VIOLATIONS | 940.185 | 13.891 | 914.877-986.586 | 2.381 | 21.962 | 30208 | 1 | 12712 |
| e_adversarial_helper | p4_policy_sensitive | 7 | NO VIOLATIONS | 937.706 | 8.077 | 930.48-954.194 | 0.859 | 22.01 | 32000 | 1 | 12712 |

## Observations

- All 84 measured executions completed.
- Each of the 12 program/policy combinations has 7 measured repetitions.
- Each combination explored exactly 1 path.
- Instruction counts were constant within each program across policies.
- Client CPU and RSS are host-side client-process measurements, not verifier CPU/RSS measurements.
- Conditional-policy results are used as the policy-correctness observation.
- Top-level Passed=True is not treated as the sole policy verdict.

## Policy outcome pattern

- a_minimal_xdp + p1_allow_execution: 7/7 no-violation; 0/7 policy-violation.
- a_minimal_xdp + p2_helper_allowlist: 7/7 no-violation; 0/7 policy-violation.
- a_minimal_xdp + p4_policy_sensitive: 7/7 no-violation; 0/7 policy-violation.
- c_branching_maps + p1_allow_execution: 0/7 no-violation; 7/7 policy-violation.
- c_branching_maps + p2_helper_allowlist: 0/7 no-violation; 7/7 policy-violation.
- c_branching_maps + p4_policy_sensitive: 0/7 no-violation; 7/7 policy-violation.
- d_policy_sensitive + p1_allow_execution: 0/7 no-violation; 7/7 policy-violation.
- d_policy_sensitive + p2_helper_allowlist: 0/7 no-violation; 7/7 policy-violation.
- d_policy_sensitive + p4_policy_sensitive: 0/7 no-violation; 7/7 policy-violation.
- e_adversarial_helper + p1_allow_execution: 7/7 no-violation; 0/7 policy-violation.
- e_adversarial_helper + p2_helper_allowlist: 7/7 no-violation; 0/7 policy-violation.
- e_adversarial_helper + p4_policy_sensitive: 7/7 no-violation; 0/7 policy-violation.

## Research interpretation

- The benchmark provides repeated baseline execution evidence for all 12 applicable combinations.
- C produces policy violations under P1, P2, and P4 because its corpus behavior accesses the state map without the required permission in those policies.
- D produces policy violations under P1, P2, and P4; P4 additionally constrains policy_state to read access while D writes it.
- E consistently produces NO VIOLATIONS under P2 and P4 despite invoking bpf_ktime_get_ns; this is the principal observed helper-policy enforcement anomaly.
- P3 remains outside the measured matrix because its intended corpus target is B, whose frozen KRAKENGUARD lifting path is unsupported.
- These results are baseline evidence and do not by themselves justify a Phase 4 implementation.
