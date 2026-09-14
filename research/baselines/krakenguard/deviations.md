# KRAKENGUARD Reproduction Deviations

This table is intentionally initialized without inventing host values.

| Dimension | Published environment | Our environment | Difference | Expected impact | Evidence |
|---|---|---|---|---|---|
| VM | Azure B16als_v2 | **pending** | pending | timing/resource comparability | host collector |
| CPU | 16 vCPUs | **pending** | pending | timing/path execution | host collector |
| RAM | 32 GiB | **pending** | pending | memory headroom | host collector |
| Storage | 64 GiB NVMe SSD | **pending** | pending | build/runtime I/O | host collector |
| OS | Ubuntu 24.04 LTS | **pending** | pending | dependency/kernel behavior | host collector |
| Kernel | 6.17.0-1008-azure | **pending** | pending | helper/model compatibility | host collector + artifact check |
| LLVM | 13 | **pending** | pending | lifting/IR compatibility | tool version |
| KLEE | v3.0 | frozen artifact | artifact-controlled | symbolic execution | artifact version |
| Z3 | 4.8.15 | frozen artifact | artifact-controlled | SMT behavior | artifact version |
| Dataset | published academic/Linux eBPF programs | **pending** | pending | direct benchmark comparability | artifact + run logs |
| Timeout | paper uses a time limit for non-terminating analyses; exact reproduction setting must be recorded | **pending** | pending | timeout classification | run configuration |
| Configuration | published paper/artifact | **pending** | pending | runtime/resource behavior | artifact status/logs |

## Rule

Every populated row must cite an observed command/output or an authoritative publication/artifact statement. No row should be filled from assumptions.
