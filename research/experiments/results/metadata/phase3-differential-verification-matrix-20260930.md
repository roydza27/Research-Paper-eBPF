# Phase 3 Differential Verification Matrix

Date: 2026-09-30

## Program-level comparison

| Program | Linux verifier | KRAKENGUARD policy observation |
|---|---|---|
| A — a_minimal_xdp | Accepted | P1/P2/P4: 7/7 NO VIOLATIONS |
| C — c_branching_maps | Accepted | P1/P2/P4: 7/7 POLICY VIOLATIONS |
| D — d_policy_sensitive | Accepted | P1/P2/P4: 7/7 POLICY VIOLATIONS |
| E — e_adversarial_helper | Accepted | P1/P2/P4: 7/7 NO VIOLATIONS; symbolic-return helper-policy miss confirmed under P2/P4 |

## Linux verifier evidence

A: 53 usec; 2 instructions processed; total_states 0; peak_states 0.
C: 570 usec; 36 instructions processed; total_states 2; peak_states 2.
D: 449 usec; 24 instructions processed; total_states 1; peak_states 1.
E: 227 usec; 9 instructions processed; total_states 1; peak_states 1.

## Interpretation boundary

Linux verifier acceptance establishes kernel-level program validity, not compliance with the KRAKENGUARD policy language.
KRAKENGUARD policy results are therefore treated as a separate higher-level policy-analysis observation.
The E anomaly is tied to symbolic return-value handling in the reproduced KRAKENGUARD conditional-policy path.

## Phase 3 status

Kernel-verifier controls: complete for A, C, D, E; B remains excluded from the KRAKENGUARD frozen matrix because its lifting path was unsupported.
Kernel-verifier controls: complete for A, C, D, E.
KRAKENGUARD repeated benchmark: complete for A, C, D, E across P1/P2/P4.
KRAKENGUARD symbolic-return mechanism: experimentally reproduced and source-level mechanism confirmed.
Phase 4 implementation: not started.
