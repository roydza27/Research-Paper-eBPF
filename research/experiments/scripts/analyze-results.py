#!/usr/bin/env python3
"""Summarize Phase 3 JSONL results without inventing missing security decisions."""
import json
import pathlib
import statistics
import sys

if len(sys.argv) != 2:
    raise SystemExit('usage: analyze-results.py <baseline-results.jsonl>')

path = pathlib.Path(sys.argv[1])
rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

completed = [r for r in rows if r.get('status') == 'completed']
mem = [r['peak_memory_kb'] for r in completed if r.get('peak_memory_kb') is not None]
user = [r['user_time_s'] for r in completed if r.get('user_time_s') is not None]

summary = {
    'total_runs': len(rows),
    'completed_runs': len(completed),
    'timeouts': sum(r.get('timeout', False) for r in rows),
    'failures': sum(r.get('status', '').startswith('failed:') for r in rows),
    'median_peak_memory_kb': statistics.median(mem) if mem else None,
    'median_user_time_s': statistics.median(user) if user else None,
    'security_decisions_available': all(
        r.get('accepted') is not None or r.get('rejected') is not None or r.get('unknown') is not None
        for r in rows
    ) if rows else False,
}

print(json.dumps(summary, indent=2, sort_keys=True))
