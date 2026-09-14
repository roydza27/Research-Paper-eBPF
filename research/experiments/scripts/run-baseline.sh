#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
OBJ_DIR="$ROOT/research/experiments/results/raw/objects"
POLICY_DIR="$ROOT/research/experiments/corpus/policies"
OUT_DIR="$ROOT/research/experiments/results/raw/runs"
mkdir -p "$OUT_DIR"

: "${BASELINE_NAME:=unknown}"
: "${BASELINE_CMD:=}"
: "${TIMEOUT_SECONDS:=300}"
: "${RUNS:=7}"

if [[ -z "$BASELINE_CMD" ]]; then
  cat >&2 <<'EOF'
BASELINE_CMD is required.

The command must accept these placeholders:
  {program} = compiled eBPF object
  {policy}  = policy JSON

Example adapter pattern:
  BASELINE_CMD='python3 <baseline>/... --object {program} --constraints {policy}' ./run-baseline.sh

Do not use a substituted command and report it as native KRAKENGUARD reproduction unless it is the actual artifact workflow.
EOF
  exit 2
fi

run_one() {
  local program="$1" policy="$2" iteration="$3"
  local name
  name="$(basename "$program" .o)__$(basename "$policy" .json)__run${iteration}"
  local logfile="$OUT_DIR/$name.log"
  local statusfile="$OUT_DIR/$name.status"
  local cmd="${BASELINE_CMD//\{program\}/$program}"
  cmd="${cmd//\{policy\}/$policy}"

  echo "[run] $name"
  if /usr/bin/time -v timeout "$TIMEOUT_SECONDS" bash -lc "$cmd" >"$logfile" 2>&1; then
    printf 'completed\n' > "$statusfile"
  else
    rc=$?
    if [[ "$rc" -eq 124 ]]; then
      printf 'timeout\n' > "$statusfile"
    else
      printf 'failed:%s\n' "$rc" > "$statusfile"
    fi
  fi
}

for program in "$OBJ_DIR"/*.o; do
  [[ -e "$program" ]] || { echo "No compiled objects found; run build-corpus.sh first." >&2; exit 3; }
  for policy in "$POLICY_DIR"/*.json; do
    for ((i=1; i<=RUNS; i++)); do
      run_one "$program" "$policy" "$i"
    done
  done
done
