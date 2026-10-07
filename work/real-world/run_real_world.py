#!/usr/bin/env python3
"""Run symbolic-only, abstract-only and hybrid verification on real workloads."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / "work" / "real-world"
RUNTIME = WORK / "runtime"
RESULTS = RUNTIME / "results"
RAW = RESULTS / "raw"
PREPARED = RUNTIME / "prepared-corpus.json"

BASELINE_DIR = ROOT / "research" / "baselines" / "krakenguard" / "artifact"
POLICY = ROOT / "research" / "experiments" / "corpus" / "phase5" / "policies" / "phase5_policy.json"
SOCKET = ROOT / "research" / "baselines" / "krakenguard" / "artifact" / "socket" / "krakenguard.sock"

sys.path.insert(0, str(ROOT / "research"))
sys.path.insert(0, str(BASELINE_DIR))

from daemon.krakenguard_client import KrakenGuardClient
from analyzer.abstract_policy_analyzer import AbstractPolicyAnalyzer

FROZEN_POLICY_SHA = "270403272d736ae7aee2ceda3bf8d088b6ac0cb476bb99ce0218dd8f33c3c603"
FROZEN_KG_COMMIT = "e7bd84005b304c5a10efcdb04914d1882b3cccf7"
FROZEN_CONTAINER_DIGEST = "kg-artifact-krakenguard@sha256:9633a6922518589803a4c9b8123d0549e54b5f57c1d04f9e383e822fd9ae3bd4"
MODES = ("symbolic_only", "abstract_only", "hybrid")


def run(cmd: list[str]) -> str:
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(cmd)}: {p.stderr.strip()}")
    return p.stdout.strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_prepared() -> list[dict[str, Any]]:
    payload = json.loads(PREPARED.read_text(encoding="utf-8"))
    rows = []
    for item in payload["programs"]:
        object_file = item.get("object_file")
        if item.get("prepare_status") != "ready" or not object_file:
            continue
        path = Path(object_file)
        if not path.exists():
            continue
        rows.append({
            "program_id": item["id"],
            "application": item["application"],
            "role": item["role"],
            "object_file": path,
            "object_sha256": sha256_file(path),
            "source_revision": item.get("upstream", {}).get("revision"),
            "source_status": item.get("source_status"),
        })
    if not rows:
        raise RuntimeError("no compatible prepared real-world objects; run prepare_corpus.py --build first")
    return rows


def cpu_model() -> str:
    try:
        text = run(["lscpu"])
        m = re.search(r"^Model name:\s*(.*)$", text, re.MULTILINE)
        return m.group(1).strip() if m else "unknown"
    except Exception:
        return "unknown"


def preflight(programs: list[dict[str, Any]], warmups: int, repetitions: int, timeout: int, seed: int) -> dict[str, Any]:
    observed = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "repo_branch": run(["git", "-C", str(ROOT), "branch", "--show-current"]),
        "repo_head": run(["git", "-C", str(ROOT), "rev-parse", "HEAD"]),
        "repo_tree": run(["git", "-C", str(ROOT), "rev-parse", "HEAD^{tree}"]),
        "krakenguard_commit": run(["git", "-C", str(BASELINE_DIR), "rev-parse", "HEAD"]),
        "policy_sha256": sha256_file(POLICY),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "compiler_version": run(["clang", "--version"]).splitlines()[0],
        "cpu_model": cpu_model(),
        "program_count": len(programs),
        "controls": {
            "hook": "XDP",
            "warmups": warmups,
            "repetitions": repetitions,
            "timeout_seconds": timeout,
            "seed": seed,
            "memory_sampling": "disabled_in_primary_timing"
        },
    }
    if observed["krakenguard_commit"] != FROZEN_KG_COMMIT:
        raise RuntimeError("KRAKENGUARD commit mismatch")
    if observed["policy_sha256"] != FROZEN_POLICY_SHA:
        raise RuntimeError("policy SHA mismatch")
    if observed["architecture"] != "x86_64":
        raise RuntimeError("architecture mismatch")
    if not SOCKET.exists():
        raise RuntimeError(f"KRAKENGUARD socket not found: {SOCKET}")
    raw = run(["docker", "image", "inspect", "kg-artifact-krakenguard:latest", "--format", "{{json .RepoDigests}}"])
    if FROZEN_CONTAINER_DIGEST not in json.loads(raw):
        raise RuntimeError("frozen container digest not present")
    return observed


def parse_result(resp: Any) -> tuple[str, dict[str, Any], str, Path]:
    if getattr(resp.execution, "return_code", 0) != 0:
        raise RuntimeError(f"KRAKENGUARD returned {resp.execution.return_code}")

    out_dir = Path((getattr(resp.output, "directory", "") or "").replace("/data", str(BASELINE_DIR / "data")))
    verdict_file = out_dir / "conditional_policy.results.txt"
    if not verdict_file.exists():
        raise RuntimeError(f"missing verdict artifact: {verdict_file}")

    text = verdict_file.read_text(encoding="utf-8", errors="replace").strip()
    if "Status: POLICY VIOLATIONS DETECTED" in text:
        verdict = "POLICY VIOLATION"
    elif "Status: NO VIOLATIONS" in text:
        verdict = "COMPLIANT"
    else:
        raise RuntimeError(f"unrecognized KRAKENGUARD verdict: {text[:300]}")

    stats: dict[str, Any] = {
        "completed_paths": None,
        "total_queries": None,
        "explored_paths": getattr(resp.execution, "paths_explored", None),
        "total_instructions": getattr(resp.execution, "total_instructions", None),
    }
    info = out_dir / "info"
    if info.exists():
        patterns = {
            "completed_paths": re.compile(r"^\s*KLEE:\s*done:\s*completed paths = (\d+)\s*$"),
            "total_queries": re.compile(r"^\s*KLEE:\s*done:\s*total queries = (\d+)\s*$"),
            "explored_paths": re.compile(r"^\s*KLEE:\s*done:\s*explored paths = (\d+)\s*$"),
            "total_instructions": re.compile(r"^\s*KLEE:\s*done:\s*total instructions = (\d+)\s*$"),
        }
        for line in info.read_text(encoding="utf-8", errors="replace").splitlines():
            for key, pattern in patterns.items():
                if match := pattern.match(line):
                    stats[key] = int(match.group(1))
    return verdict, stats, text, out_dir


def symbolic_once(client: KrakenGuardClient, program: dict[str, Any], timeout: int, run_id: str) -> dict[str, Any]:
    raw = RAW / run_id
    raw.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter_ns()
    response = None
    try:
        response = client.verify(
            object_file=str(program["object_file"].resolve()),
            constraints_file=str(POLICY.resolve()),
            timeout=timeout,
        )
        verdict, stats, conditional, out_dir = parse_result(response)
        status, error = "ok", None
    except Exception as exc:
        verdict, stats, conditional, out_dir = "TIMEOUT_OR_ERROR", {}, "", None
        status, error = "error", f"{type(exc).__name__}: {exc}"
    elapsed_us = (time.perf_counter_ns() - start) // 1000

    if response is not None and status == "ok":
        (raw / "response.json").write_text(json.dumps(response.to_dict(), indent=2), encoding="utf-8")
        (raw / "conditional_policy.results.txt").write_text(conditional, encoding="utf-8")
        for name in ("info", "messages.txt", "warnings.txt"):
            src = out_dir / name
            if src.exists():
                (raw / name).write_bytes(src.read_bytes())

    return {
        "status": status,
        "verdict": verdict,
        "wall_time_us": elapsed_us,
        "wall_time_ms": round(elapsed_us / 1000.0, 6),
        "klee": stats,
        "error": error,
    }


def abstract_once(program: dict[str, Any], run_id: str) -> dict[str, Any]:
    raw = RAW / run_id
    raw.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter_ns()
    try:
        result = AbstractPolicyAnalyzer(str(program["object_file"]), str(POLICY)).analyze()
        status, error = "ok", None
    except Exception as exc:
        result = {"verdict": "UNKNOWN", "discharged": False, "metrics": {}, "proof": ""}
        status, error = "error", f"{type(exc).__name__}: {exc}"
    elapsed_us = (time.perf_counter_ns() - start) // 1000

    (raw / "analysis.json").write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    return {
        "status": status,
        "verdict": result.get("verdict", "UNKNOWN"),
        "discharged": bool(result.get("discharged", False)),
        "wall_time_us": elapsed_us,
        "wall_time_ms": round(elapsed_us / 1000.0, 6),
        "metrics": result.get("metrics", {}),
        "proof": result.get("proof", ""),
        "error": error,
    }


def run_one(client: KrakenGuardClient, mode: str, program: dict[str, Any], timeout: int, run_id: str) -> dict[str, Any]:
    abstract = None
    symbolic = None

    if mode == "symbolic_only":
        symbolic = symbolic_once(client, program, timeout, run_id)
        final, route, discharged = symbolic["verdict"], "SYMBOLIC_ONLY", False
    elif mode == "abstract_only":
        abstract = abstract_once(program, run_id)
        final, route, discharged = normalize(abstract["verdict"]), "ABSTRACT_ONLY", abstract["discharged"]
    else:
        abstract = abstract_once(program, run_id + "-abstract")
        if abstract["verdict"] == "SAFE":
            final, route, discharged = "COMPLIANT", "FAST_PATH_SAFE", True
        elif abstract["verdict"] == "VIOLATION":
            final, route, discharged = "POLICY VIOLATION", "FAST_PATH_VIOLATION", True
        else:
            symbolic = symbolic_once(client, program, timeout, run_id + "-symbolic")
            final, route, discharged = symbolic["verdict"], "FALLBACK_SYMBOLIC", False

    if mode == "symbolic_only":
        total_us = symbolic["wall_time_us"]
    elif mode == "abstract_only":
        total_us = abstract["wall_time_us"]
    else:
        total_us = abstract["wall_time_us"] + (symbolic["wall_time_us"] if symbolic else 0)

    return {
        "run_id": run_id,
        "mode": mode,
        "program_id": program["program_id"],
        "application": program["application"],
        "role": program["role"],
        "route": route,
        "discharged": discharged,
        "abstract_verdict": abstract["verdict"] if abstract else None,
        "final_verdict": final,
        "fallback_invoked": route == "FALLBACK_SYMBOLIC",
        "status": "ok" if final in ("COMPLIANT", "POLICY VIOLATION", "UNKNOWN") else "error",
        "wall_time_us": total_us,
        "wall_time_ms": round(total_us / 1000.0, 6),
        "abstract_wall_time_us": abstract["wall_time_us"] if abstract else None,
        "symbolic_wall_time_us": symbolic["wall_time_us"] if symbolic else None,
        "klee_completed_paths": symbolic.get("klee", {}).get("completed_paths") if symbolic else None,
        "klee_total_queries": symbolic.get("klee", {}).get("total_queries") if symbolic else None,
        "klee_explored_paths": symbolic.get("klee", {}).get("explored_paths") if symbolic else None,
        "klee_total_instructions": symbolic.get("klee", {}).get("total_instructions") if symbolic else None,
        "object_sha256": program["object_sha256"],
        "policy_sha256": FROZEN_POLICY_SHA,
        "krakenguard_commit": FROZEN_KG_COMMIT,
        "source_revision": program["source_revision"],
        "source_status": program["source_status"],
        "error": (symbolic or abstract or {}).get("error"),
    }


def normalize(verdict: str) -> str:
    return {"SAFE": "COMPLIANT", "VIOLATION": "POLICY VIOLATION", "UNKNOWN": "UNKNOWN"}.get(verdict, "UNKNOWN")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=[*MODES, "all"], default="all")
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    programs = load_prepared()
    modes = list(MODES) if args.mode == "all" else [args.mode]
    provenance = preflight(programs, args.warmups, args.repetitions, args.timeout, args.seed)
    client = KrakenGuardClient(os.path.relpath(SOCKET, Path.cwd()))
    health = client.health()
    if getattr(health, "status", None) != "success":
        raise RuntimeError(f"KRAKENGUARD health check failed: {health.to_dict()}")

    RESULTS.mkdir(parents=True, exist_ok=True)
    RAW.mkdir(parents=True, exist_ok=True)
    (RESULTS / "provenance.json").write_text(json.dumps(provenance, indent=2), encoding="utf-8")

    rng = random.Random(args.seed)
    records: list[dict[str, Any]] = []
    for rep_type, count in (("warmup", args.warmups), ("measured", args.repetitions)):
        for rep in range(1, count + 1):
            jobs = [(mode, program) for mode in modes for program in programs]
            rng.shuffle(jobs)
            for mode, program in jobs:
                run_id = f"{mode}-{program['program_id']}-{rep_type[0]}{rep:02d}"
                row = run_one(client, mode, program, args.timeout, run_id)
                row.update({"repetition_type": rep_type, "repetition": rep})
                records.append(row)

    fields = [
        "run_id", "mode", "program_id", "application", "role", "repetition_type", "repetition",
        "route", "discharged", "abstract_verdict", "final_verdict", "fallback_invoked", "status",
        "wall_time_us", "wall_time_ms", "abstract_wall_time_us", "symbolic_wall_time_us",
        "klee_completed_paths", "klee_total_queries", "klee_explored_paths",
        "klee_total_instructions", "object_sha256", "policy_sha256", "krakenguard_commit",
        "source_revision", "source_status", "error"
    ]
    with (RESULTS / "runs.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)

    measured = [r for r in records if r["repetition_type"] == "measured"]
    successful = [r for r in measured if r["status"] == "ok"]
    print(json.dumps({
        "status": "completed",
        "programs": len(programs),
        "modes": modes,
        "measured_runs": len(measured),
        "successful_measured_runs": len(successful),
        "output": str((RESULTS / "runs.csv").relative_to(ROOT)),
    }, indent=2))


if __name__ == "__main__":
    main()
