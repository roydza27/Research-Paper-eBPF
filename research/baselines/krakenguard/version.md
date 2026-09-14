# KRAKENGUARD Version Freeze

| Item | Frozen value | Source |
|---|---|---|
| Repository | `krakenguard-ebpf/krakenguard` | official artifact |
| Commit | `e7bd84005b304c5a10efcdb04914d1882b3cccf7` | repository history / Phase 3 manifest |
| KLEE | `v3.0` | `setup.sh` |
| KLEE uclibc | `klee_uclibc_v1.3` | `setup.sh` |
| LLVM | `13` | `setup.sh` / Dockerfile |
| Z3 | `z3-4.8.15` | `setup.sh` |
| Docker base | `ubuntu:24.04` | Dockerfile |
| Python | `python3` in artifact environment | Dockerfile / setup |
| Jinja2 | installed by Dockerfile | Dockerfile |
| PyYAML | installed by Dockerfile | Dockerfile |
| pyelftools | installed by Dockerfile | Dockerfile |
| libbpf | `libbpf-dev` package in Dockerfile | Dockerfile |

## Reproduction rule

The exact commit above is the baseline identity. Do not substitute a newer `main` revision while calling results a KRAKENGUARD reproduction. Any later commit must be a separately identified baseline.

## Build paths

The artifact provides two documented paths:

- host/local setup through `setup.sh`;
- containerized setup through `Dockerfile` and `docker-compose.yaml`.

The reproduction runner prefers the containerized path because it freezes the artifact's build dependencies more tightly and avoids silently replacing LLVM/KLEE/Z3 versions on the research host.
