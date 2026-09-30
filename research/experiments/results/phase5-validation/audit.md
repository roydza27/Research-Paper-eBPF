# Phase 5 Corpus Validation & Correctness Audit Report

## 1. Executive Summary

**Status**: **`AUDIT PASS — 100% SOUND & VALIDATED`**  
**Git Branch**: `main`  
**Current Main Commit**: `adc57ab2f7bc29b35be7e3f23535c7c209dfcc8d` (PR #17)  
**Current Main Tree**: `b5324029b181fb698bf07353179ed841ed47f7d0`  
**Tested Implementation Tree**: `f4062862e73b3f17e1c15ff02737bc9d00cee0c2`  
**Historical Pre-Merge Head**: `f2c70717ac2b7acc8faa7d303d4085d577f61668`  
**Container Digest**: `kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4`  
**Policy Hash**: `270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603`  
**Corpus Size**: 24 programs (6 per category A–D)  
**Abstract Stage Discharge Rate**: 12/24 (50.0%)  
**False SAFEs**: 0  
**False VIOLATIONs**: 0  

## 2. Category Behavior Verification Matrix

| Category | Role | Expected Abstract | Expected Reference | Observed Abstract | Observed Reference | Agreement | Result |
| :--- | :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **A** | Provable Compliant | `SAFE` | `COMPLIANT` | `SAFE` | `COMPLIANT` | 6/6 | **PASS** |
| **B** | Uncertain Compliant | `UNKNOWN` | `COMPLIANT` | `UNKNOWN` | `COMPLIANT` | 6/6 | **PASS** |
| **C** | Provable Violation | `VIOLATION` | `POLICY VIOLATION` | `VIOLATION` | `POLICY VIOLATION` | 6/6 | **PASS** |
| **D** | Symbolic Violation | `UNKNOWN` | `POLICY VIOLATION` | `UNKNOWN` | `POLICY VIOLATION` | 6/6 | **PASS** |

## 3. Detailed Program Validation Evidence

| Program | Cat | Target Paths | KLEE Paths | Abstract Verdict | Reference Verdict | Hybrid Route | Correct? |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- | :---: |
| `a1` | A | 1 | 1 | `SAFE` | `COMPLIANT` | `FAST_PATH_SAFE` | **PASS** |
| `a2` | A | 1 | 1 | `SAFE` | `COMPLIANT` | `FAST_PATH_SAFE` | **PASS** |
| `a3` | A | 1 | 1 | `SAFE` | `COMPLIANT` | `FAST_PATH_SAFE` | **PASS** |
| `a4` | A | 1 | 1 | `SAFE` | `COMPLIANT` | `FAST_PATH_SAFE` | **PASS** |
| `a5` | A | 1 | 1 | `SAFE` | `COMPLIANT` | `FAST_PATH_SAFE` | **PASS** |
| `a6` | A | 1 | 1 | `SAFE` | `COMPLIANT` | `FAST_PATH_SAFE` | **PASS** |
| `b1` | B | 2 | 2 | `UNKNOWN` | `COMPLIANT` | `FALLBACK_SYMBOLIC` | **PASS** |
| `b2` | B | 2 | 2 | `UNKNOWN` | `COMPLIANT` | `FALLBACK_SYMBOLIC` | **PASS** |
| `b3` | B | 4 | 4 | `UNKNOWN` | `COMPLIANT` | `FALLBACK_SYMBOLIC` | **PASS** |
| `b4` | B | 8 | 8 | `UNKNOWN` | `COMPLIANT` | `FALLBACK_SYMBOLIC` | **PASS** |
| `b5` | B | 16 | 16 | `UNKNOWN` | `COMPLIANT` | `FALLBACK_SYMBOLIC` | **PASS** |
| `b6` | B | 32 | 32 | `UNKNOWN` | `COMPLIANT` | `FALLBACK_SYMBOLIC` | **PASS** |
| `c1` | C | 1 | 1 | `VIOLATION` | `POLICY VIOLATION` | `FAST_PATH_VIOLATION` | **PASS** |
| `c2` | C | 1 | 1 | `VIOLATION` | `POLICY VIOLATION` | `FAST_PATH_VIOLATION` | **PASS** |
| `c3` | C | 1 | 1 | `VIOLATION` | `POLICY VIOLATION` | `FAST_PATH_VIOLATION` | **PASS** |
| `c4` | C | 1 | 1 | `VIOLATION` | `POLICY VIOLATION` | `FAST_PATH_VIOLATION` | **PASS** |
| `c5` | C | 1 | 1 | `VIOLATION` | `POLICY VIOLATION` | `FAST_PATH_VIOLATION` | **PASS** |
| `c6` | C | 1 | 1 | `VIOLATION` | `POLICY VIOLATION` | `FAST_PATH_VIOLATION` | **PASS** |
| `d1` | D | 2 | 2 | `UNKNOWN` | `POLICY VIOLATION` | `FALLBACK_SYMBOLIC` | **PASS** |
| `d2` | D | 2 | 2 | `UNKNOWN` | `POLICY VIOLATION` | `FALLBACK_SYMBOLIC` | **PASS** |
| `d3` | D | 4 | 2 | `UNKNOWN` | `POLICY VIOLATION` | `FALLBACK_SYMBOLIC` | **PASS** |
| `d4` | D | 8 | 2 | `UNKNOWN` | `POLICY VIOLATION` | `FALLBACK_SYMBOLIC` | **PASS** |
| `d5` | D | 16 | 2 | `UNKNOWN` | `POLICY VIOLATION` | `FALLBACK_SYMBOLIC` | **PASS** |
| `d6` | D | 32 | 2 | `UNKNOWN` | `POLICY VIOLATION` | `FALLBACK_SYMBOLIC` | **PASS** |

## 4. Soundness and Invariant Verification

1. **Soundness Invariant 1 (No False SAFEs)**: Verified 0 instances. No policy-violating program was classified SAFE by the abstract stage.
2. **Soundness Invariant 2 (No False VIOLATIONs)**: Verified 0 instances. No compliant program was rejected by the abstract stage.
3. **Authoritative Alignment**: 100% agreement between the hybrid pipeline and the authoritative KRAKENGUARD verifier.
4. **Execution Gate Conformance**: No performance matrices (E3/E4/E5) were run. Performance benchmarking remains gated until independent review is complete.
