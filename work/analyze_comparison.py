#!/usr/bin/env python3
"""Analyze comparative workbench evidence without changing raw observations."""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "work" / "results"


def read_runs(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            row["target_paths"] = int(row["target_paths"]) if row["target_paths"] else None
            row["wall_time_ms"] = float(row["wall_time_ms"])
            row["verdict_correct"] = None if row["verdict_correct"] in ("", "None") else row["verdict_correct"] == "True"
            row["fallback_invoked"] = row["fallback_invoked"] == "True"
            rows.append(row)
    return rows


def median_by_program(rows: List[Dict[str, Any]], mode: str) -> Dict[str, Dict[str, Any]]:
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["mode"] == mode and row["repetition_type"] == "measured" and row["status"] == "ok":
            grouped[row["program_id"]].append(row)
    result = {}
    for pid, observations in grouped.items():
        times = [r["wall_time_ms"] for r in observations]
        mem_a = [int(r["peak_abstract_rss_bytes"]) for r in observations if r.get("peak_abstract_rss_bytes")]
        mem_k = [int(r["peak_krakenguard_container_memory_bytes"]) for r in observations if r.get("peak_krakenguard_container_memory_bytes")]
        result[pid] = {
            "program_id": pid,
            "category": observations[0]["category"],
            "target_paths": observations[0]["target_paths"],
            "median_ms": statistics.median(times),
            "mean_ms": statistics.fmean(times),
            "min_ms": min(times),
            "max_ms": max(times),
            "fallback_fraction": sum(r["fallback_invoked"] for r in observations) / len(observations),
            "median_abstract_rss_bytes": statistics.median(mem_a) if mem_a else None,
            "median_kg_memory_bytes": statistics.median(mem_k) if mem_k else None,
        }
    return result


def exact_two_sided_sign_test(differences: List[float]) -> Dict[str, Any]:
    nonzero = [d for d in differences if d != 0]
    n = len(nonzero)
    if n == 0:
        return {"n": 0, "positive": 0, "negative": 0, "p_two_sided": 1.0}
    positive = sum(d > 0 for d in nonzero)
    negative = n - positive
    k = min(positive, negative)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return {"n": n, "positive": positive, "negative": negative, "p_two_sided": min(1.0, 2.0 * tail)}


def bootstrap_median_ci(values: List[float], seed: int = 42, samples: int = 20000) -> Tuple[float, float]:
    if not values:
        return (float("nan"), float("nan"))
    if len(values) == 1:
        return (values[0], values[0])
    rng = random.Random(seed)
    medians = []
    for _ in range(samples):
        sample = [values[rng.randrange(len(values))] for _ in values]
        medians.append(statistics.median(sample))
    medians.sort()
    return medians[int(0.025 * (samples - 1))], medians[int(0.975 * (samples - 1))]


def linear_fit(xs: List[float], ys: List[float]) -> Dict[str, Any]:
    if len(xs) < 2:
        return {"n": len(xs), "slope": None, "intercept": None, "r2": None}
    xbar, ybar = statistics.fmean(xs), statistics.fmean(ys)
    denom = sum((x - xbar) ** 2 for x in xs)
    if denom == 0:
        return {"n": len(xs), "slope": None, "intercept": ybar, "r2": None}
    slope = sum((x - xbar) * (y - ybar) for x, y in zip(xs, ys)) / denom
    intercept = ybar - slope * xbar
    ss_tot = sum((y - ybar) ** 2 for y in ys)
    ss_res = sum((y - (intercept + slope * x)) ** 2 for x, y in zip(xs, ys))
    return {"n": len(xs), "slope": slope, "intercept": intercept, "r2": 1.0 - ss_res / ss_tot if ss_tot else 1.0}


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    sym = median_by_program(rows, "symbolic_only")
    abstract = median_by_program(rows, "abstract_only")
    hybrid = median_by_program(rows, "hybrid")
    common = sorted(set(sym) & set(hybrid))
    paired = []
    for pid in common:
        s, h = sym[pid]["median_ms"], hybrid[pid]["median_ms"]
        diff = s - h
        paired.append({
            "program_id": pid,
            "category": sym[pid]["category"],
            "target_paths": sym[pid]["target_paths"],
            "symbolic_median_ms": s,
            "hybrid_median_ms": h,
            "absolute_saving_ms": diff,
            "saving_pct": (diff / s * 100.0) if s else 0.0,
            "hybrid_fallback_fraction": hybrid[pid]["fallback_fraction"],
            "symbolic_median_kg_memory_bytes": sym[pid]["median_kg_memory_bytes"],
            "hybrid_median_abstract_rss_bytes": hybrid[pid]["median_abstract_rss_bytes"],
            "hybrid_median_kg_memory_bytes": hybrid[pid]["median_kg_memory_bytes"],
        })
    diffs = [x["absolute_saving_ms"] for x in paired]
    ci = bootstrap_median_ci(diffs)
    sign = exact_two_sided_sign_test(diffs)

    categories = defaultdict(list)
    for row in paired:
        categories[row["category"]].append(row)
    category_summary = {}
    for cat, items in sorted(categories.items()):
        category_summary[cat] = {
            "program_count": len(items),
            "symbolic_median_ms": statistics.median([x["symbolic_median_ms"] for x in items]),
            "hybrid_median_ms": statistics.median([x["hybrid_median_ms"] for x in items]),
            "median_saving_pct": statistics.median([x["saving_pct"] for x in items]),
            "median_fallback_fraction": statistics.median([x["hybrid_fallback_fraction"] for x in items]),
        }

    checked = [
        r for r in rows
        if r["repetition_type"] == "measured"
        and r["status"] == "ok"
        and r["verdict_correct"] is not None
    ]
    false_safe = sum(
        r["abstract_verdict"] == "SAFE" and r["reference_verdict"] == "POLICY VIOLATION"
        for r in checked
    )
    false_violation = sum(
        r["abstract_verdict"] == "VIOLATION" and r["reference_verdict"] == "COMPLIANT"
        for r in checked
    )

    hybrid_rows = [
        r for r in rows
        if r["mode"] == "hybrid"
        and r["repetition_type"] == "measured"
        and r["status"] == "ok"
    ]

    complexity = {}
    for mode, table in (
        ("symbolic_only", sym),
        ("abstract_only", abstract),
        ("hybrid", hybrid),
    ):
        pts = [
            (float(v["target_paths"]), float(v["median_ms"]))
            for v in table.values()
            if v["target_paths"] is not None
        ]
        fit = linear_fit([x for x, _ in pts], [y for _, y in pts])
        complexity[mode] = {
            "tested_relationship": "median_time_ms = intercept + slope * target_paths",
            "note": "Descriptive corpus fit only; not an asymptotic complexity proof.",
            **fit,
        }

    return {
        "schema": "comparative-verification-analysis/v1",
        "raw_run_count": len(rows),
        "successful_measured_run_count": sum(
            r["repetition_type"] == "measured" and r["status"] == "ok"
            for r in rows
        ),
        "program_count": len(common),
        "paired_symbolic_vs_hybrid": paired,
        "primary_endpoint": {
            "metric": "paired program-level median end-to-end wall time",
            "median_absolute_saving_ms": statistics.median(diffs) if diffs else None,
            "median_saving_pct": statistics.median([x["saving_pct"] for x in paired]) if paired else None,
            "bootstrap_95ci_median_absolute_saving_ms": ci,
            "exact_two_sided_sign_test": sign,
        },
        "correctness": {
            "checked_measured_rows": len(checked),
            "all_checked_agree": all(r["verdict_correct"] for r in checked) if checked else None,
            "false_safe": false_safe,
            "false_violation": false_violation,
        },
        "fallback": {
            "measured_hybrid_rows": len(hybrid_rows),
            "fraction": (
                sum(r["fallback_invoked"] for r in hybrid_rows) / len(hybrid_rows)
                if hybrid_rows else None
            ),
        },
        "category_summary": category_summary,
        "empirical_complexity": complexity,
    }


def write_outputs(summary: Dict[str, Any]) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "analysis.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    paired = summary["paired_symbolic_vs_hybrid"]
    fields = [
        "program_id", "category", "target_paths", "symbolic_median_ms",
        "hybrid_median_ms", "absolute_saving_ms", "saving_pct",
        "hybrid_fallback_fraction", "symbolic_median_kg_memory_bytes",
        "hybrid_median_abstract_rss_bytes", "hybrid_median_kg_memory_bytes"
    ]
    with (RESULTS / "paired-comparison.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(paired)

    p, c, f = summary["primary_endpoint"], summary["correctness"], summary["fallback"]
    lines = [
        "# Comparative Verification Analysis",
        "",
        "Generated only from work/results/runs.csv. Raw observations are not modified.",
        "",
        "## Primary endpoint",
        f"- Median paired absolute saving: {p['median_absolute_saving_ms']} ms",
        f"- Median paired percentage saving: {p['median_saving_pct']}%",
        f"- Bootstrap 95% CI for median absolute saving: {p['bootstrap_95ci_median_absolute_saving_ms']}",
        f"- Exact two-sided paired sign test: {p['exact_two_sided_sign_test']}",
        "",
        "## Correctness",
        f"- Checked measured rows: {c['checked_measured_rows']}",
        f"- All checked rows agree: {c['all_checked_agree']}",
        f"- False SAFE: {c['false_safe']}",
        f"- False VIOLATION: {c['false_violation']}",
        "",
        "## Fallback",
        f"- Measured hybrid rows: {f['measured_hybrid_rows']}",
        f"- Fallback fraction: {f['fraction']}",
        "",
        "## Interpretation",
        "Positive saving means hybrid required less wall time than symbolic-only.",
        "The empirical path/time fits are descriptive for this corpus and are not asymptotic complexity proofs.",
    ]
    (RESULTS / "analysis.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=RESULTS / "runs.csv")
    args = parser.parse_args()
    if not args.input.exists():
        raise SystemExit(f"missing raw run file: {args.input}")
    summary = summarize(read_runs(args.input))
    write_outputs(summary)
    print(json.dumps({
        "status": "analysis_complete",
        "analysis_json": str((RESULTS / "analysis.json").relative_to(ROOT)),
        "paired_csv": str((RESULTS / "paired-comparison.csv").relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
