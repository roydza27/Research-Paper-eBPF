#!/usr/bin/env python3
"""Single-run worker used to measure the abstract analyzer in isolation."""

from __future__ import annotations

import argparse
import json
import os
import resource
import time
from pathlib import Path

import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "research"))

from analyzer.abstract_policy_analyzer import AbstractPolicyAnalyzer


def peak_rss_bytes() -> int:
    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports KiB; keep the worker portable enough for macOS-style bytes.
    return int(value * 1024 if os.name == "posix" else value)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--object", required=True)
    parser.add_argument("--policy", required=True)
    args = parser.parse_args()

    start_wall = time.perf_counter_ns()
    start_cpu = time.process_time_ns()
    try:
        result = AbstractPolicyAnalyzer(args.object, args.policy).analyze()
        status = "ok"
        error = None
    except Exception as exc:  # defensive boundary for benchmark evidence
        result = {"verdict": "UNKNOWN", "discharged": False, "metrics": {}}
        status = "error"
        error = f"{type(exc).__name__}: {exc}"
    end_cpu = time.process_time_ns()
    end_wall = time.perf_counter_ns()

    payload = {
        "status": status,
        "error": error,
        "verdict": result.get("verdict"),
        "discharged": bool(result.get("discharged", False)),
        "proof": result.get("proof", ""),
        "metrics": result.get("metrics", {}),
        "wall_time_us": (end_wall - start_wall) // 1000,
        "cpu_time_us": (end_cpu - start_cpu) // 1000,
        "peak_rss_bytes": peak_rss_bytes(),
    }
    print(json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    main()
