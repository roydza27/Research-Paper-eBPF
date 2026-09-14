#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CORPUS="$ROOT/research/experiments/corpus"
OUT="$ROOT/research/experiments/results/raw/objects"
mkdir -p "$OUT"

: "${CLANG:=clang}"
: "${BPF_ARCH:=x86}"
: "${BPF_INCLUDE_DIR:=/usr/include}"

if ! command -v "$CLANG" >/dev/null 2>&1; then
  echo "clang not found: $CLANG" >&2
  exit 2
fi

for src in "$CORPUS"/programs/*.c; do
  name="$(basename "$src" .c)"
  obj="$OUT/$name.o"
  echo "[build] $src -> $obj"
  "$CLANG" -target bpf -D__TARGET_ARCH_${BPF_ARCH} -O2 -g \
    -I"$BPF_INCLUDE_DIR" -c "$src" -o "$obj"
done

printf 'Built %s objects under %s\n' "$(find "$OUT" -maxdepth 1 -name '*.o' | wc -l)" "$OUT"