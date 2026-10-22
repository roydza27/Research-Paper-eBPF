#!/usr/bin/env python3
"""Summarize normalized raw run records without inventing missing outcomes.

Accepted raw JSON: one object per file or a list of objects. Required fields are
program_id and pipeline. See design/README for the full normalized record schema.
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]

def load_records(paths: list[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        payload = json.loads(path.read_text())
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                raise ValueError(f"{path}: each run must be a JSON object")
            row = dict(item)
            row.setdefault("raw_path", str(path))
            rows.append(row)
    return rows

def _num(row: dict[str, Any], key: str) -> float | None:
    value = row.get(key)
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None

def summarize(records: list[dict[str, Any]], bootstrap_samples: int = 5000,
              seed: int = 20261022) -> dict[str, Any]:
    for index, row in enumerate(records):
        if not row.get("program_id") or not row.get("pipeline"):
            raise ValueError(f"run row {index} lacks program_id or pipeline")
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        groups[(str(row["program_id"]), str(row["pipeline"]))].append(row)
    per_program = []
    for (program_id, pipeline), rows in sorted(groups.items()):
        latencies = [x for row in rows if (x := _num(row, "end_to_end_duration_ms")) is not None]
        abstract_latencies = [x for row in rows if (x := _num(row, "abstract_duration_ms")) is not None]
        symbolic_latencies = [x for row in rows if (x := _num(row, "symbolic_duration_ms")) is not None]
        symbolic_calls = sum(bool(r.get("symbolic_invoked")) for r in rows)
        dispositions = [str(r.get("final_verdict", r.get("overall_verdict", r.get("disposition", "unresolved")))).upper()
                        for r in rows]
        oracle = [str(r.get("reference_verdict", "")).upper() for r in rows]
        compared = [(o, v) for o, v in zip(oracle, dispositions) if o in {"SAFE", "VIOLATION", "COMPLIANT", "POLICY VIOLATION"}]
        normalized = lambda v: "SAFE" if v in {"SAFE", "COMPLIANT"} else ("VIOLATION" if v in {"VIOLATION", "POLICY VIOLATION", "REJECT"} else "UNKNOWN")
        agreements = sum(normalized(o) == normalized(v) for o, v in compared)
        per_program.append({
            "program_id": program_id, "pipeline": pipeline, "run_count": len(rows),
            "end_to_end_ms_median": statistics.median(latencies) if latencies else None,
            "end_to_end_ms_mean": statistics.mean(latencies) if latencies else None,
            "abstract_ms_median": statistics.median(abstract_latencies) if abstract_latencies else None,
            "symbolic_ms_median": statistics.median(symbolic_latencies) if symbolic_latencies else None,
            "symbolic_invocation_rate": symbolic_calls / len(rows),
            "unknown_or_unresolved_count": sum(v in {"UNKNOWN", "UNRESOLVED", "TIMEOUT", "ERROR"} for v in dispositions),
            "oracle_comparisons": len(compared),
            "oracle_agreement_rate": agreements / len(compared) if compared else None,
            "false_safe_count": sum(normalized(o) == "VIOLATION" and normalized(v) == "SAFE" for o, v in compared),
            "false_reject_count": sum(normalized(o) == "SAFE" and normalized(v) == "VIOLATION" for o, v in compared),
            "note": "Counts are over recorded runs; oracle agreement is null when no oracle labels are supplied."
        })
    # Paired comparison is only valid when the caller supplies a stable pair_id.
    pair_map: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in records:
        pair_id = row.get("pair_id")
        if pair_id:
            pair_map[str(pair_id)][str(row["pipeline"])] = row
    pipeline_names = sorted({str(r["pipeline"]) for r in records})
    paired = []
    rng = random.Random(seed)
    for i, left in enumerate(pipeline_names):
        for right in pipeline_names[i + 1:]:
            differences = []
            for pair_id, pair in pair_map.items():
                if left in pair and right in pair:
                    a = _num(pair[left], "end_to_end_duration_ms")
                    b = _num(pair[right], "end_to_end_duration_ms")
                    if a is not None and b is not None:
                        differences.append(b - a)  # right minus left; positive means right slower
            ci = None
            if differences:
                boots = []
                for _ in range(bootstrap_samples):
                    sample = [rng.choice(differences) for _ in differences]
                    boots.append(statistics.mean(sample))
                boots.sort()
                ci = {"mean_difference_ms": statistics.mean(differences),
                      "bootstrap_95pct_mean_ci_ms": [boots[int(.025 * (len(boots)-1))],
                                                       boots[int(.975 * (len(boots)-1))]],
                      "paired_n": len(differences),
                      "interpretation": f"{right} minus {left}; positive means {right} is slower"}
            paired.append({"left_pipeline": left, "right_pipeline": right, **(ci or {
                "paired_n": 0, "mean_difference_ms": None, "bootstrap_95pct_mean_ci_ms": None,
                "interpretation": "no complete pair_id-matched measurements; no paired claim"})})
    return {
        "schema": "split-bypass-summary/v1", "run_count": len(records),
        "seed": seed, "bootstrap_samples": bootstrap_samples,
        "per_program_pipeline": per_program, "paired_latency_comparisons": paired,
        "limitations": [
            "No reference agreement can be inferred when reference_verdict is missing.",
            "Only rows sharing explicit pair_id are paired; unpaired timings are not treated as paired.",
            "Bootstrap intervals quantify observed sampling variation only and do not establish verifier soundness.",
            "Region-discharge counts are not calculated unless genuine region-level results are explicitly supplied."
        ]
    }

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=ROOT / "research/experiments/split_bypass/results/raw")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bootstrap-samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=20261022)
    args = parser.parse_args()
    if args.output.exists():
        parser.error(f"refusing to overwrite summary: {args.output}")
    files = sorted(args.raw_dir.glob("*.json"))
    if not files:
        parser.error(f"no raw JSON records found under {args.raw_dir}")
    summary = summarize(load_records(files), args.bootstrap_samples, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "run_count": summary["run_count"],
                      "program_pipeline_rows": len(summary["per_program_pipeline"])}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
