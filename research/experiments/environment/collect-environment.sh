#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OUT_DIR="${1:-$ROOT/research/experiments/results/metadata}"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_DIR/environment-$TS.json"

cmd_version() {
  local cmd="$1"
  if command -v "$cmd" >/dev/null 2>&1; then
    "$cmd" --version 2>&1 | head -n 1
  else
    printf '%s' "unavailable"
  fi
}

kernel="$(uname -srmo 2>/dev/null || true)"
arch="$(uname -m 2>/dev/null || true)"
cpu_model="$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null | sed 's/^ *//' || true)"
cpu_threads="$(nproc 2>/dev/null || true)"
ram_kib="$(awk '/MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || true)"

bpf_config='unavailable'
if [[ -r /proc/config.gz ]] && command -v zgrep >/dev/null 2>&1; then
  bpf_config="$(zgrep -E 'CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|BPF_LSM|CGROUP_BPF|SECURITY|USER_NS|NET_NS|PID_NS|CGROUPS)=' /proc/config.gz 2>/dev/null || true)"
elif [[ -r "/boot/config-$(uname -r)" ]]; then
  bpf_config="$(grep -E 'CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|BPF_LSM|CGROUP_BPF|SECURITY|USER_NS|NET_NS|PID_NS|CGROUPS)=' "/boot/config-$(uname -r)" 2>/dev/null || true)"
fi

btf='false'
[[ -r /sys/kernel/btf/vmlinux ]] && btf='true'

container_runtime='none'
if command -v docker >/dev/null 2>&1; then container_runtime="docker $(docker --version 2>/dev/null || true)"; fi
if command -v podman >/dev/null 2>&1; then container_runtime="podman $(podman --version 2>/dev/null || true)"; fi

python3 - <<PY > "$OUT"
import json

def text(value):
    return value if isinstance(value, str) else str(value)

manifest = {
  "schema": "phase3-environment/v1",
  "timestamp_utc": "$TS",
  "host": {
    "kernel": text("$kernel"),
    "architecture": text("$arch"),
    "cpu_model": text("$cpu_model"),
    "cpu_threads": text("$cpu_threads"),
    "ram_kib": text("$ram_kib"),
    "btf_vmlinux": "$btf" == "true",
  },
  "toolchain": {
    "clang": text("$(cmd_version clang)"),
    "llvm": text("$(cmd_version llvm-config)"),
    "gcc": text("$(cmd_version gcc)"),
    "bpftool": text("$(cmd_version bpftool)"),
    "rustc": text("$(cmd_version rustc)"),
    "cargo": text("$(cmd_version cargo)"),
    "python3": text("$(cmd_version python3)"),
    "container_runtime": text("$container_runtime"),
  },
  "kernel_configuration": text("""$bpf_config"""),
}
print(json.dumps(manifest, indent=2, sort_keys=True))
PY

printf 'Wrote %s\n' "$OUT"
cat "$OUT"