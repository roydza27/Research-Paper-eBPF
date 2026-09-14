# KRAKENGUARD Reproduction Requirements

## Required host capabilities

The experiment host must provide:

- Linux
- Git with submodule support
- Docker Engine and Compose support for the preferred artifact path
- enough disk/RAM to build KLEE, Z3, LLVM tooling and the lifter
- network access during the initial artifact/dependency acquisition phase
- Python 3 for the submission client and experiment harness
- standard timing tools (`/usr/bin/time`, `timeout`)

## Artifact-declared dependencies

The frozen KRAKENGUARD artifact declares or installs:

- LLVM/Clang 13
- KLEE v3.0
- klee-uclibc v1.3
- Z3 4.8.15
- libbpf
- CMake
- GCC/multilib
- Python 3
- Jinja2
- PyYAML
- pyelftools
- graphviz
- libelf
- libcap
- standard build utilities

The Dockerfile uses Ubuntu 24.04 as the image base and installs LLVM 13 from the upstream LLVM 13.0.0 binary archive. The local `setup.sh` instead performs package installation and builds the source dependencies.

## Kernel-side requirements

The initial experiment is verification-only. It does not require loading eBPF programs into the host kernel. Therefore `CAP_BPF`, XDP attachment and kernel loading privileges are not required for the first reproduction gate.

The host still needs a Linux environment suitable for collecting the Phase 3 environment metadata. Kernel configuration is recorded for reproducibility even when the first verification run does not attach a program.

## Exact version recording

The host-side collector must record exact versions rather than the word `latest`, including:

```text
uname -a
uname -r
bpftool version
clang --version
llvm-config --version
rustc --version
cargo --version
python --version
```

and the installed Docker/Compose versions when containerized reproduction is used.
