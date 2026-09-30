# Phase 4 E2 Dataset Integrity Audit Report

## 1. Audit Verdict

**Status**: **`AUDIT PASS — FULL DATASET VERIFIED`**

All 63 executions (14 warmups + 49 measured runs) across 7 program levels were executed under the approved protocol on `phase4-e2-full-matrix`.

## 2. Integrity Verification Matrix

| Integrity Check | Expected | Observed | Verdict |
| :--- | :--- | :--- | :--- |
| Total Executions | 63 | 63 | **PASS** |
| Warmup Executions | 14 (2 per level) | 14 | **PASS** |
| Measured Executions | 49 (7 per level) | 49 | **PASS** |
| Timeouts | 0 | 0 | **PASS** |
| Failures | 0 | 0 | **PASS** |
| Observed Path Monotonicity | [1, 2, 4, 8, 16, 32, 64] | [1, 2, 4, 8, 16, 32, 64] | **PASS** |
| Completed Paths Integrity | 100% matched explored paths | 100% match | **PASS** |
| Raw Log vs Dataset Agreement | 100% across all 63 runs | 100% match | **PASS** |
| Policy Hash Consistency | `27040327...` | Verified across all runs | **PASS** |
| Baseline Commit Consistency | `e7bd8400...` | Verified across all runs | **PASS** |

## 3. Measured Statistical Summary (49 Measured Runs)

| Program ID | Target Paths | Observed Feasible Paths | Z3 Queries | N | Median (ms) | Mean (ms) | StdDev (ms) | CV | Min (ms) | Max (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **E2-P0** | 1 | **1** | 1 | 7 | 746.14 | 757.28 | 34.55 | 0.0456 | 728.68 | 833.28 |
| **E2-P1** | 2 | **2** | 2 | 7 | 749.93 | 752.64 | 18.59 | 0.0247 | 721.32 | 783.98 |
| **E2-P2** | 4 | **4** | 4 | 7 | 762.77 | 770.22 | 28.96 | 0.0376 | 745.65 | 831.15 |
| **E2-P3** | 8 | **8** | 8 | 7 | 789.88 | 789.19 | 10.73 | 0.0136 | 772.99 | 802.17 |
| **E2-P4** | 16 | **16** | 16 | 7 | 853.02 | 854.79 | 11.25 | 0.0132 | 842.36 | 870.63 |
| **E2-P5** | 32 | **32** | 32 | 7 | 973.44 | 972.45 | 7.97 | 0.0082 | 961.65 | 981.92 |
| **E2-P6** | 64 | **64** | 64 | 7 | 1231.16 | 1266.86 | 56.61 | 0.0447 | 1213.62 | 1334.89 |

