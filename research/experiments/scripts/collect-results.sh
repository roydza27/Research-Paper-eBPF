#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
RUN_DIR="$ROOT/research/experiments/results/raw/runs"
OUT="$ROOT/research/experiments/results/processed/baseline-results.jsonl"
mkdir -p "$(dirname "$OUT")"

python3 - "$RUN_DIR" "$OUT" <<'PY'
import json
import pathlib
import re
import sys

run_dir = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
rows = []

for status_path in sorted(run_dir.glob('*.status')):
    stem = status_path.stem
    status = status_path.read_text().strip()
    log = status_path.with_suffix('.log')
    text = log.read_text(errors='replace') if log.exists() else ''

    elapsed = re.search(r'Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([^\n]+)', text)
    memory = re.search(r'Maximum resident set size \(kbytes\): (\d+)', text)
    user = re.search(r'User time \(seconds\): ([0-9.]+)', text)
    system = re.search(r'System time \(seconds\): ([0-9.]+)', text)

    rows.append({
        'run_id': stem,
        'status': status,
        'wall_time_raw': elapsed.group(1) if elapsed else None,
        'peak_memory_kb': int(memory.group(1)) if memory else None,
        'user_time_s': float(user.group(1)) if user else None,
        'system_time_s': float(system.group(1)) if system else None,
        'accepted': None,
        'rejected': None,
        'unknown': None,
        'timeout': status == 'timeout',
        'note': 'Decision fields are intentionally unset until a baseline-specific adapter parses native output.'
    })

with out.open('w') as f:
    for row in rows:
        f.write(json.dumps(row, sort_keys=True) + '\n')

print(f'Wrote {len(rows)} rows to {out}')
PY