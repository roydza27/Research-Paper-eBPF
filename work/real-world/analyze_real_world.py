#!/usr/bin/env python3
"""Analyze real-world verification runs without altering raw evidence."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "work" / "real-world"
RUNTIME = WORK / "runtime"
INPUT = RUNTIME / "results" / "runs.csv"
OUTPUT = RUNTIME / "results" / "analysis.json"


def median(values: list[float]) -> float:
    if not values:
        raise ValueError("median of empty list")
    return statistics.median(values)


def number(value: str | None) -> float | None:
    if value in (None, "", "None"):
        return None
    return float(value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=INPUT)
    args = parser.parse_args()

    with args.input.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    measured = [r for r in rows if r["repetition_type"] == "measured"]
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in measured:
        by_key[(row["program_id"], row["mode"])].append(row)

    program_rows: list[dict[str, Any]] = []
    for pid in sorted({r["program_id"] for r in measured}):
        sym = by_key.get((pid, "symbolic_only"), [])
        abs_rows = by_key.get((pid, "abstract_only"), [])
        hyb = by_key.get((pid, "hybrid"), [])

        sym_times = [number(r["wall_time_ms"]) for r in sym if r["status"] == "ok"]
        abs_times = [number(r["wall_time_ms"]) for r in abs_rows if r["status"] == "ok"]
        hyb_times = [number(r["wall_time_ms"]) for r in hyb if r["status"] == "ok"]
        sym_times = [x for x in sym_times if x is not None]
        abs_times = [x for x in abs_times if x is not None]
        hyb_times = [x for x in hyb_times if x is not None]

        symbolic_verdicts = sorted({r["final_verdict"] for r in sym if r["status"] == "ok"})
        hybrid_verdicts = sorted({r["final_verdict"] for r in hyb if r["status"] == "ok"})
        reference = symbolic_verdicts[0] if len(symbolic_verdicts) == 1 else None
        agreement = (
            reference is not None
            and bool(hybrid_verdicts)
            and all(v == reference for v in hybrid_verdicts)
        )

        fallback = [r for r in hyb if r["status"] == "ok" and r["fallback_invoked"] == "True"]
        discharged = [r for r in hyb if r["status"] == "ok" and r["discharged"] == "True"]
        paths = [
            int(r["klee_completed_paths"])
            for r in sym
            if r["status"] == "ok" and r["klee_completed_paths"] not in ("", None)
        ]

        row = {
            "program_id": pid,
            "application": (hyb or sym)[0]["application"],
            "role": (hyb or sym)[0]["role"],
            "symbolic_median_ms": median(sym_times) if sym_times else None,
            "abstract_median_ms": median(abs_times) if abs_times else None,
            "hybrid_median_ms": median(hyb_times) if hyb_times else None,
            "median_saving_ms": (
                median(sym_times) - median(hyb_times)
                if sym_times and hyb_times else None
            ),
            "median_saving_pct": (
                100.0 * (median(sym_times) - median(hyb_times)) / median(sym_times)
                if sym_times and hyb_times and median(sym_times) > 0 else None
            ),
            "fallback_fraction": (
                len(fallback) / (len(fallback) + len(discharged))
                if fallback or discharged else None
            ),
            "discharge_fraction": (
                len(discharged) / (len(fallback) + len(discharged))
                if fallback or discharged else None
            ),
            "symbolic_verdicts": symbolic_verdicts,
            "hybrid_verdicts": hybrid_verdicts,
            "hybrid_agrees_with_symbolic_reference": agreement,
            "observed_klee_completed_paths_median": median(paths) if paths else None,
            "measured_rows": {
                "symbolic_only": len(sym),
                "abstract_only": len(abs_rows),
                "hybrid": len(hyb)
            },
        }
        program_rows.append(row)

    hybrid_ok = [r for r in measured if r["mode"] == "hybrid" and r["status"] == "ok"]
    routed = [
        r for r in hybrid_ok
        if r["fallback_invoked"] == "True" or r["discharged"] == "True"
    ]
    fallback_count = sum(r["fallback_invoked"] == "True" for r in routed)
    discharge_count = sum(r["discharged"] == "True" for r in routed)
    savings = [
        r["median_saving_ms"] for r in program_rows
        if r["median_saving_ms"] is not None
    ]
    savings_pct = [
        r["median_saving_pct"] for r in program_rows
        if r["median_saving_pct"] is not None
    ]

    output = {
        "schema": "real-world-analysis/v1",
        "raw_runs": len(rows),
        "measured_runs": len(measured),
        "successful_measured_runs": sum(r["status"] == "ok" for r in measured),
        "program_count": len(program_rows),
        "coverage": {
            "hybrid_rows_with_terminal_route": len(routed),
            "fallback_fraction": fallback_count / len(routed) if routed else None,
            "fast_path_fraction": discharge_count / len(routed) if routed else None,
        },
        "correctness_consistency": {
            "programs_with_symbolic_reference": sum(
                bool(r["symbolic_verdicts"]) for r in program_rows
            ),
            "all_hybrid_programs_agree_with_symbolic_reference": all(
                r["hybrid_agrees_with_symbolic_reference"]
                for r in program_rows if r["symbolic_verdicts"]
            ),
        },
        "aggregate": {
            "median_program_level_saving_ms": median(savings) if savings else None,
            "median_program_level_saving_pct": median(savings_pct) if savings_pct else None,
        },
        "programs": program_rows,
        "note": "Real-world correctness is reported as hybrid-vs-symbolic-baseline agreement; this is not an independent correctness oracle."
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": "analyzed",
        "programs": len(program_rows),
        "output": str(OUTPUT.relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
